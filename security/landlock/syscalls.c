// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - System call implementations and user space interfaces
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 * Copyright © 2021-2025 Microsoft Corporation
 */

#include <asm/current.h>
#include <linux/anon_inodes.h>
#include <linux/bitops.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/cleanup.h>
#include <linux/compiler_types.h>
#include <linux/completion.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/linux/landlock.h>

#include "cred.h"
#include "domain.h"
#include "fs.h"
#include "limits.h"
#include "net.h"
#include "ruleset.h"
#include "setup.h"

static bool is_initialized(void)
{
	if (likely(landlock_initialized))
		return true;

	pr_warn_once(
		"Disabled but requested by user space. "
		"You should enable Landlock at boot time: "
		"https://docs.kernel.org/userspace-api/landlock.html#boot-time-configuration\n");
	return false;
}

/**
 * copy_min_struct_from_user - Safe future-proof argument copying
 *
 * Extend copy_struct_from_user() to check for consistent user buffer.
 *
 * @dst: Kernel space pointer or NULL.
 * @ksize: Actual size of the data pointed to by @dst.
 * @ksize_min: Minimal required size to be copied.
 * @src: User space pointer or NULL.
 * @usize: (Alleged) size of the data pointed to by @src.
 */
static __always_inline int
copy_min_struct_from_user(void *const dst, const size_t ksize,
			  const size_t ksize_min, const void __user *const src,
			  const size_t usize)
{
	/* Checks buffer inconsistencies. */
	BUILD_BUG_ON(!dst);
	if (!src)
		return -EFAULT;

	/* Checks size ranges. */
	BUILD_BUG_ON(ksize <= 0);
	BUILD_BUG_ON(ksize < ksize_min);
	if (usize < ksize_min)
		return -EINVAL;
	if (usize > PAGE_SIZE)
		return -E2BIG;

	/* Copies user buffer and fills with zeros. */
	return copy_struct_from_user(dst, ksize, src, usize);
}

/*
 * This function only contains arithmetic operations with constants, leading to
 * BUILD_BUG_ON().  The related code is evaluated and checked at build time,
 * but it is then ignored thanks to compiler optimizations.
 */
static void build_check_abi(void)
{
	struct landlock_ruleset_attr ruleset_attr;
	struct landlock_path_beneath_attr path_beneath_attr;
	struct landlock_net_port_attr net_port_attr;
	size_t ruleset_size, path_beneath_size, net_port_size;

	/*
	 * For each user space ABI structures, first checks that there is no
	 * hole in them, then checks that all architectures have the same
	 * struct size.
	 */
	ruleset_size = sizeof(ruleset_attr.handled_access_fs);
	ruleset_size += sizeof(ruleset_attr.handled_access_net);
	ruleset_size += sizeof(ruleset_attr.scoped);
	BUILD_BUG_ON(sizeof(ruleset_attr) != ruleset_size);
	BUILD_BUG_ON(sizeof(ruleset_attr) != 24);

	path_beneath_size = sizeof(path_beneath_attr.allowed_access);
	path_beneath_size += sizeof(path_beneath_attr.parent_fd);
	BUILD_BUG_ON(sizeof(path_beneath_attr) != path_beneath_size);
	BUILD_BUG_ON(sizeof(path_beneath_attr) != 12);

	net_port_size = sizeof(net_port_attr.allowed_access);
	net_port_size += sizeof(net_port_attr.port);
	BUILD_BUG_ON(sizeof(net_port_attr) != net_port_size);
	BUILD_BUG_ON(sizeof(net_port_attr) != 16);
}

/* Ruleset handling */

static int fop_ruleset_release(struct inode *const inode,
			       struct file *const filp)
{
	struct landlock_ruleset *ruleset = filp->private_data;

	landlock_put_ruleset(ruleset);
	return 0;
}

static ssize_t fop_dummy_read(struct file *const filp, char __user *const buf,
			      const size_t size, loff_t *const ppos)
{
	/* Dummy handler to enable FMODE_CAN_READ. */
	return -EINVAL;
}

static ssize_t fop_dummy_write(struct file *const filp,
			       const char __user *const buf, const size_t size,
			       loff_t *const ppos)
{
	/* Dummy handler to enable FMODE_CAN_WRITE. */
	return -EINVAL;
}

/*
 * A ruleset file descriptor enables to build a ruleset by adding (i.e.
 * writing) rule after rule, without relying on the task's context.  This
 * reentrant design is also used in a read way to enforce the ruleset on the
 * current task.
 */
static const struct file_operations ruleset_fops = {
	.release = fop_ruleset_release,
	.read = fop_dummy_read,
	.write = fop_dummy_write,
};

/*
 * The Landlock ABI version should be incremented for each new Landlock-related
 * user space visible change (e.g. Landlock syscalls).  This version should
 * only be incremented once per Linux release, and the date in
 * Documentation/userspace-api/landlock.rst should be updated to reflect the
 * UAPI change.
 */
const int landlock_abi_version = 7;

/**
 * sys_landlock_create_ruleset - Create a new ruleset
 *
 * @attr: Pointer to a &struct landlock_ruleset_attr identifying the scope of
 *        the new ruleset.
 * @size: Size of the pointed &struct landlock_ruleset_attr (needed for
 *        backward and forward compatibility).
 * @flags: Supported values:
 *
 *         - %LANDLOCK_CREATE_RULESET_VERSION
 *         - %LANDLOCK_CREATE_RULESET_ERRATA
 *
 * This system call enables to create a new Landlock ruleset, and returns the
 * related file descriptor on success.
 *
 * If %LANDLOCK_CREATE_RULESET_VERSION or %LANDLOCK_CREATE_RULESET_ERRATA is
 * set, then @attr must be NULL and @size must be 0.
 *
 * Possible returned errors are:
 *
 * - %EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - %EINVAL: unknown @flags, or unknown access, or unknown scope, or too small @size;
 * - %E2BIG: @attr or @size inconsistencies;
 * - %EFAULT: @attr or @size inconsistencies;
 * - %ENOMSG: empty &landlock_ruleset_attr.handled_access_fs.
 *
 * .. kernel-doc:: include/uapi/linux/landlock.h
 *     :identifiers: landlock_create_ruleset_flags
 */
SYSCALL_DEFINE3(landlock_create_ruleset,
		const struct landlock_ruleset_attr __user *const, attr,
		const size_t, size, const __u32, flags)
{
	struct landlock_ruleset_attr ruleset_attr;
	struct landlock_ruleset *ruleset;
	int err, ruleset_fd;

	/* Build-time checks. */
	build_check_abi();

	if (!is_initialized())
		return -EOPNOTSUPP;

	if (flags) {
		if (attr || size)
			return -EINVAL;

		if (flags == LANDLOCK_CREATE_RULESET_VERSION)
			return landlock_abi_version;

		if (flags == LANDLOCK_CREATE_RULESET_ERRATA)
			return landlock_errata;

		return -EINVAL;
	}

	/* Copies raw user space buffer. */
	err = copy_min_struct_from_user(&ruleset_attr, sizeof(ruleset_attr),
					offsetofend(typeof(ruleset_attr),
						    handled_access_fs),
					attr, size);
	if (err)
		return err;

	/* Checks content (and 32-bits cast). */
	if ((ruleset_attr.handled_access_fs | LANDLOCK_MASK_ACCESS_FS) !=
	    LANDLOCK_MASK_ACCESS_FS)
		return -EINVAL;

	/* Checks network content (and 32-bits cast). */
	if ((ruleset_attr.handled_access_net | LANDLOCK_MASK_ACCESS_NET) !=
	    LANDLOCK_MASK_ACCESS_NET)
		return -EINVAL;

	/* Checks IPC scoping content (and 32-bits cast). */
	if ((ruleset_attr.scoped | LANDLOCK_MASK_SCOPE) != LANDLOCK_MASK_SCOPE)
		return -EINVAL;

	/* Checks arguments and transforms to kernel struct. */
	ruleset = landlock_create_ruleset(ruleset_attr.handled_access_fs,
					  ruleset_attr.handled_access_net,
					  ruleset_attr.scoped);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	/* Creates anonymous FD referring to the ruleset. */
	ruleset_fd = anon_inode_getfd("[landlock-ruleset]", &ruleset_fops,
				      ruleset, O_RDWR | O_CLOEXEC);
	if (ruleset_fd < 0)
		landlock_put_ruleset(ruleset);
	return ruleset_fd;
}

/*
 * Returns an owned ruleset from a FD. It is thus needed to call
 * landlock_put_ruleset() on the return value.
 */
static struct landlock_ruleset *get_ruleset_from_fd(const int fd,
						    const fmode_t mode)
{
	CLASS(fd, ruleset_f)(fd);
	struct landlock_ruleset *ruleset;

	if (fd_empty(ruleset_f))
		return ERR_PTR(-EBADF);

	/* Checks FD type and access right. */
	if (fd_file(ruleset_f)->f_op != &ruleset_fops)
		return ERR_PTR(-EBADFD);
	if (!(fd_file(ruleset_f)->f_mode & mode))
		return ERR_PTR(-EPERM);
	ruleset = fd_file(ruleset_f)->private_data;
	if (WARN_ON_ONCE(ruleset->num_layers != 1))
		return ERR_PTR(-EINVAL);
	landlock_get_ruleset(ruleset);
	return ruleset;
}

/* Path handling */

/*
 * @path: Must call put_path(@path) after the call if it succeeded.
 */
static int get_path_from_fd(const s32 fd, struct path *const path)
{
	CLASS(fd_raw, f)(fd);

	BUILD_BUG_ON(!__same_type(
		fd, ((struct landlock_path_beneath_attr *)NULL)->parent_fd));

	if (fd_empty(f))
		return -EBADF;
	/*
	 * Forbids ruleset FDs, internal filesystems (e.g. nsfs), including
	 * pseudo filesystems that will never be mountable (e.g. sockfs,
	 * pipefs).
	 */
	if ((fd_file(f)->f_op == &ruleset_fops) ||
	    (fd_file(f)->f_path.mnt->mnt_flags & MNT_INTERNAL) ||
	    (fd_file(f)->f_path.dentry->d_sb->s_flags & SB_NOUSER) ||
	    IS_PRIVATE(d_backing_inode(fd_file(f)->f_path.dentry)))
		return -EBADFD;

	*path = fd_file(f)->f_path;
	path_get(path);
	return 0;
}

static int add_rule_path_beneath(struct landlock_ruleset *const ruleset,
				 const void __user *const rule_attr)
{
	struct landlock_path_beneath_attr path_beneath_attr;
	struct path path;
	int res, err;
	access_mask_t mask;

	/* Copies raw user space buffer. */
	res = copy_from_user(&path_beneath_attr, rule_attr,
			     sizeof(path_beneath_attr));
	if (res)
		return -EFAULT;

	/*
	 * Informs about useless rule: empty allowed_access (i.e. deny rules)
	 * are ignored in path walks.
	 */
	if (!path_beneath_attr.allowed_access)
		return -ENOMSG;

	/* Checks that allowed_access matches the @ruleset constraints. */
	mask = ruleset->access_masks[0].fs;
	if ((path_beneath_attr.allowed_access | mask) != mask)
		return -EINVAL;

	/* Gets and checks the new rule. */
	err = get_path_from_fd(path_beneath_attr.parent_fd, &path);
	if (err)
		return err;

	/* Imports the new rule. */
	err = landlock_append_fs_rule(ruleset, &path,
				      path_beneath_attr.allowed_access);
	path_put(&path);
	return err;
}

static int add_rule_net_port(struct landlock_ruleset *ruleset,
			     const void __user *const rule_attr)
{
	struct landlock_net_port_attr net_port_attr;
	int res;
	access_mask_t mask;

	/* Copies raw user space buffer. */
	res = copy_from_user(&net_port_attr, rule_attr, sizeof(net_port_attr));
	if (res)
		return -EFAULT;

	/*
	 * Informs about useless rule: empty allowed_access (i.e. deny rules)
	 * are ignored by network actions.
	 */
	if (!net_port_attr.allowed_access)
		return -ENOMSG;

	/* Checks that allowed_access matches the @ruleset constraints. */
	mask = landlock_get_net_access_mask(ruleset, 0);
	if ((net_port_attr.allowed_access | mask) != mask)
		return -EINVAL;

	/* Denies inserting a rule with port greater than 65535. */
	if (net_port_attr.port > U16_MAX)
		return -EINVAL;

	/* Imports the new rule. */
	return landlock_append_net_rule(ruleset, net_port_attr.port,
					net_port_attr.allowed_access);
}

/**
 * sys_landlock_add_rule - Add a new rule to a ruleset
 *
 * @ruleset_fd: File descriptor tied to the ruleset that should be extended
 *		with the new rule.
 * @rule_type: Identify the structure type pointed to by @rule_attr:
 *             %LANDLOCK_RULE_PATH_BENEATH or %LANDLOCK_RULE_NET_PORT.
 * @rule_attr: Pointer to a rule (matching the @rule_type).
 * @flags: Must be 0.
 *
 * This system call enables to define a new rule and add it to an existing
 * ruleset.
 *
 * Possible returned errors are:
 *
 * - %EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - %EAFNOSUPPORT: @rule_type is %LANDLOCK_RULE_NET_PORT but TCP/IP is not
 *   supported by the running kernel;
 * - %EINVAL: @flags is not 0;
 * - %EINVAL: The rule accesses are inconsistent (i.e.
 *   &landlock_path_beneath_attr.allowed_access or
 *   &landlock_net_port_attr.allowed_access is not a subset of the ruleset
 *   handled accesses)
 * - %EINVAL: &landlock_net_port_attr.port is greater than 65535;
 * - %ENOMSG: Empty accesses (e.g. &landlock_path_beneath_attr.allowed_access is
 *   0);
 * - %EBADF: @ruleset_fd is not a file descriptor for the current thread, or a
 *   member of @rule_attr is not a file descriptor as expected;
 * - %EBADFD: @ruleset_fd is not a ruleset file descriptor, or a member of
 *   @rule_attr is not the expected file descriptor type;
 * - %EPERM: @ruleset_fd has no write access to the underlying ruleset;
 * - %EFAULT: @rule_attr was not a valid address.
 */
SYSCALL_DEFINE4(landlock_add_rule, const int, ruleset_fd,
		const enum landlock_rule_type, rule_type,
		const void __user *const, rule_attr, const __u32, flags)
{
	struct landlock_ruleset *ruleset __free(landlock_put_ruleset) = NULL;

	if (!is_initialized())
		return -EOPNOTSUPP;

	/* No flag for now. */
	if (flags)
		return -EINVAL;

	/* Gets and checks the ruleset. */
	ruleset = get_ruleset_from_fd(ruleset_fd, FMODE_CAN_WRITE);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	switch (rule_type) {
	case LANDLOCK_RULE_PATH_BENEATH:
		return add_rule_path_beneath(ruleset, rule_attr);
	case LANDLOCK_RULE_NET_PORT:
		return add_rule_net_port(ruleset, rule_attr);
	default:
		return -EINVAL;
	}
}

/* Enforcement */

/*
 * Shared state between multiple threads which are enforcing Landlock rulesets
 * in lockstep with each other.
 */
struct tsync_shared_context {
	/* The old and tentative new creds of the calling thread. */
	const struct cred *old_cred;
	const struct cred *new_cred;

	/* An error encountered in preparation step, or 0. */
	atomic_t preparation_error;

	/*
	 * Barrier after preparation step in the inner loop.
	 * The calling thread waits for completion.
	 *
	 * Re-initialized on every round of looking for newly spawned threads.
	 */
	atomic_t num_preparing;
	struct completion all_prepared;

	/* Sibling threads wait for completion. */
	struct completion ready_to_commit;

	/*
	 * Barrier after commit step (used by syscall impl to wait for
	 * completion).
	 */
	atomic_t num_unfinished;
	struct completion all_finished;
};

struct tsync_work {
	struct callback_head work;
	struct task_struct *task;
	struct tsync_shared_context *shared_ctx;
};

/*
 * restrict_one_thread - update a thread's Landlock domain in lockstep with the
 * other threads in the same process
 *
 * When this is run, the same function gets run in all other threads in the same
 * process (except for the calling thread which called landlock_restrict_self).
 * The concurrently running invocations of restrict_one_thread coordinate
 * through the shared ctx object to do their work in lockstep to implement
 * all-or-nothing semantics for enforcing the new Landlock domain.
 *
 * Afterwards, depending on the presence of an error, all threads either commit
 * or abort the prepared credentials.  The commit operation can not fail any more.
 */
static void restrict_one_thread(struct tsync_shared_context *ctx)
{
	int res;
	struct cred *cred = NULL;
	const struct cred *current_cred = current_cred();

	if (current_cred == ctx->old_cred) {
		/*
		 * As a shortcut, switch out old_cred with new_cred, if
		 * possible.
		 *
		 * Note: We are intentionally dropping the const qualifier here,
		 * because it is required by commit_creds() and abort_creds().
		 */
		cred = (struct cred *)get_cred(ctx->new_cred);
	} else {
		/* Else, prepare new creds and populate them. */
		cred = prepare_creds();

		if (!cred) {
			atomic_set(&ctx->preparation_error, -ENOMEM);

			/*
			 * Even on error, we need to adhere to the protocol and
			 * coordinate with concurrently running invocations.
			 */
			if (atomic_dec_return(&ctx->num_preparing) == 0)
				complete_all(&ctx->all_prepared);

			goto out;
		}

		landlock_cred_copy(landlock_cred(cred),
				   landlock_cred(ctx->new_cred));
	}

	/*
	 * Barrier: Wait until all threads are done preparing.
	 * After this point, we can have no more failures.
	 */
	if (atomic_dec_return(&ctx->num_preparing) == 0)
		complete_all(&ctx->all_prepared);

	/*
	 * Wait for signal from calling thread that it's safe to read the
	 * preparation error now and we are ready to commit (or abort).
	 */
	wait_for_completion(&ctx->ready_to_commit);

	/* Abort the commit if any of the other threads had an error. */
	res = atomic_read(&ctx->preparation_error);
	if (res) {
		abort_creds(cred);
		goto out;
	}

	/* If needed, establish enforcement prerequisites. */
	if (!ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))
		task_set_no_new_privs(current);

	commit_creds(cred);

out:
	/* Notify the calling thread once all threads are done */
	if (atomic_dec_return(&ctx->num_unfinished) == 0)
		complete_all(&ctx->all_finished);
}

/*
 * restrict_one_thread_callback - task_work callback for restricting a thread
 *
 * Calls restrict_one_thread with the struct landlock_shared_tsync_context.
 */
static void restrict_one_thread_callback(struct callback_head *work)
{
	struct tsync_work *ctx = container_of(work, struct tsync_work, work);

	restrict_one_thread(ctx->shared_ctx);
}

/*
 * struct tsync_works - a growable array of per-task contexts
 *
 * The zero-initialized struct represents the empty array.
 */
struct tsync_works {
	struct tsync_work **works;
	size_t size;
	size_t capacity;
};

/*
 * tsync_works_provide - provides a preallocated tsync_work for the given task
 *
 * This also stores a task pointer in the context and increments the reference
 * count of the task.
 *
 * Returns:
 *   A pointer to the preallocated context struct, with task filled in.
 *
 *   NULL, if we ran out of preallocated context structs.
 */
static struct tsync_work *tsync_works_provide(struct tsync_works *s,
					      struct task_struct *task)
{
	struct tsync_work *ctx;

	if (s->size >= s->capacity)
		return NULL;

	ctx = s->works[s->size];
	s->size++;

	ctx->task = get_task_struct(task);
	return ctx;
}

/*
 * tsync_works_grow_by - preallocates space for n more contexts in s
 *
 * Returns:
 *   -ENOMEM if the (re)allocation fails
 *   0       if the allocation succeeds, partially succeeds, or no reallocation was needed
 */
static int tsync_works_grow_by(struct tsync_works *s, size_t n, gfp_t flags)
{
	int i;
	size_t new_capacity = s->capacity + n;
	struct tsync_work **works;

	if (new_capacity <= s->capacity)
		return 0;

	works = krealloc_array(s->works, new_capacity, sizeof(s->works[0]),
			       flags);
	if (IS_ERR(works))
		return PTR_ERR(works);

	s->works = works;

	for (i = s->capacity; i < new_capacity; i++) {
		s->works[i] = kzalloc(sizeof(*s->works[i]), flags);
		if (IS_ERR(s->works[i])) {
			/*
			 * Leave the object in a consistent state,
			 * but return an error.
			 */
			s->capacity = i;
			return PTR_ERR(s->works[i]);
		}
	}
	s->capacity = new_capacity;
	return 0;
}

/*
 * tsync_works_contains - checks for presence of task in s
 */
static bool tsync_works_contains_task(struct tsync_works *s,
				      struct task_struct *task)
{
	size_t i;

	for (i = 0; i < s->size; i++)
		if (s->works[i]->task == task)
			return true;
	return false;
}

/*
 * tsync_works_free - free memory held by s and drop all task references
 */
static void tsync_works_free(struct tsync_works *s)
{
	int i;

	for (i = 0; i < s->size; i++)
		put_task_struct(s->works[i]->task);
	for (i = 0; i < s->capacity; i++)
		kfree(s->works[i]);
	kfree(s->works);
	s->works = NULL;
	s->size = 0;
	s->capacity = 0;
}

/*
 * restrict_sibling_threads - enables a Landlock policy for all sibling threads
 */
static int restrict_sibling_threads(const struct cred *old_cred,
				    const struct cred *new_cred)
{
	int res;
	struct task_struct *thread, *caller;
	struct tsync_shared_context shared_ctx;
	struct tsync_works works = {};
	size_t newly_discovered_threads;
	bool found_more_threads;
	struct tsync_work *ctx;

	atomic_set(&shared_ctx.preparation_error, 0);
	init_completion(&shared_ctx.all_prepared);
	init_completion(&shared_ctx.ready_to_commit);
	atomic_set(&shared_ctx.num_unfinished, 0);
	init_completion(&shared_ctx.all_finished);
	shared_ctx.old_cred = old_cred;
	shared_ctx.new_cred = new_cred;

	caller = current;

	/*
	 * We schedule a pseudo-signal task_work for each of the calling task's
	 * sibling threads.  In the task work, each thread:
	 *
	 * 1) runs prepare_creds() and writes back the error to
	 *    shared_ctx.preparation_error, if needed.
	 *
	 * 2) signals that it's done with prepare_creds() to the calling task.
	 *    (completion "all_prepared").
	 *
	 * 3) waits for the completion "ready_to_commit".  This is sent by the
	 *    calling task after ensuring that all sibling threads have done
	 *    with the "preparation" stage.
	 *
	 *    After this barrier is reached, it's safe to read
	 *    shared_ctx.preparation_error.
	 *
	 * 4) reads shared_ctx.preparation_error and then either does
	 *    commit_creds() or abort_creds().
	 *
	 * 5) signals that it's done altogether (barrier synchronization
	 *    "all_finished")
	 */
	do {
		found_more_threads = false;

		/*
		 * The "all_prepared" barrier is used locally to the inner loop,
		 * this use of for_each_thread().  We can reset it on each loop
		 * iteration because all previous loop iterations are done with
		 * it already.
		 *
		 * num_preparing is initialized to 1 so that the counter can not
		 * go to 0 and mark the completion as done before all task works
		 * are registered.  (We decrement it at the end of this loop.)
		 */
		atomic_set(&shared_ctx.num_preparing, 1);
		reinit_completion(&shared_ctx.all_prepared);

		/* In RCU read-lock, count the threads we need. */
		newly_discovered_threads = 0;
		rcu_read_lock();
		for_each_thread(caller, thread) {
			/* Skip current, since it is initiating the sync. */
			if (thread == caller)
				continue;

			/* Skip exited threads. */
			if (thread->flags & PF_EXITING)
				continue;

			/* Skip threads that we have already seen. */
			if (tsync_works_contains_task(&works, thread))
				continue;

			newly_discovered_threads++;
		}
		rcu_read_unlock();

		if (newly_discovered_threads == 0)
			break; /* done */

		res = tsync_works_grow_by(&works, newly_discovered_threads,
					  GFP_KERNEL_ACCOUNT);
		if (res) {
			atomic_set(&shared_ctx.preparation_error, res);
			break;
		}

		rcu_read_lock();
		for_each_thread(caller, thread) {
			/* Skip current, since it is initiating the sync. */
			if (thread == caller)
				continue;

			/* Skip exited threads. */
			if (thread->flags & PF_EXITING)
				continue;

			/* Skip threads that we already looked at. */
			if (tsync_works_contains_task(&works, thread))
				continue;

			/*
			 * We found a sibling thread that is not doing its
			 * task_work yet, and which might spawn new threads
			 * before our task work runs, so we need at least one
			 * more round in the outer loop.
			 */
			found_more_threads = true;

			ctx = tsync_works_provide(&works, thread);
			if (!ctx) {
				/*
				 * We ran out of preallocated contexts -- we
				 * need to try again with this thread at a later
				 * time!  found_more_threads is already true
				 * at this point.
				 */
				break;
			}

			ctx->shared_ctx = &shared_ctx;

			atomic_inc(&shared_ctx.num_preparing);
			atomic_inc(&shared_ctx.num_unfinished);

			init_task_work(&ctx->work,
				       restrict_one_thread_callback);
			res = task_work_add(thread, &ctx->work, TWA_SIGNAL);
			if (res) {
				/*
				 * Remove the task from ctx so that we will
				 * revisit the task at a later stage, if it
				 * still exists.
				 */
				put_task_struct_rcu_user(ctx->task);
				ctx->task = NULL;

				atomic_set(&shared_ctx.preparation_error, res);
				atomic_dec(&shared_ctx.num_preparing);
				atomic_dec(&shared_ctx.num_unfinished);
			}
		}
		rcu_read_unlock();

		/*
		 * Decrement num_preparing for current, to undo that we
		 * initialized it to 1 at the beginning of the inner loop.
		 */
		if (atomic_dec_return(&shared_ctx.num_preparing) > 0)
			wait_for_completion(&shared_ctx.all_prepared);
	} while (found_more_threads &&
		 !atomic_read(&shared_ctx.preparation_error));

	/*
	 * We now have all sibling threads blocking and in "prepared" state in
	 * the task work. Ask all threads to commit.
	 */
	complete_all(&shared_ctx.ready_to_commit);

	if (works.size)
		wait_for_completion(&shared_ctx.all_finished);

	tsync_works_free(&works);

	return atomic_read(&shared_ctx.preparation_error);
}

/**
 * sys_landlock_restrict_self - Enforce a ruleset on the calling thread
 *
 * @ruleset_fd: File descriptor tied to the ruleset to merge with the target.
 * @flags: Supported values:
 *
 *         - %LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF
 *         - %LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
 *         - %LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
 *         - %LANDLOCK_RESTRICT_SELF_TSYNC
 *
 * This system call enforces a Landlock ruleset on the current thread.
 * Enforcing a ruleset requires that the task has %CAP_SYS_ADMIN in its
 * namespace or is running with no_new_privs.  This avoids scenarios where
 * unprivileged tasks can affect the behavior of privileged children.
 *
 * If %LANDLOCK_RESTRICT_SELF_TSYNC is specified in @flags, all other threads of
 * the process will be brought into the exact same Landlock configuration as the
 * calling thread.  This includes both the enforced ruleset and logging
 * configuration, and happens irrespective of previously established rulesets
 * and logging configurations on these threads.  If required, this operation
 * also enables the no_new_privs flag for these threads.
 *
 * Possible returned errors are:
 *
 * - %EOPNOTSUPP: Landlock is supported by the kernel but disabled at boot time;
 * - %EINVAL: @flags contains an unknown bit.
 * - %EBADF: @ruleset_fd is not a file descriptor for the current thread;
 * - %EBADFD: @ruleset_fd is not a ruleset file descriptor;
 * - %EPERM: @ruleset_fd has no read access to the underlying ruleset, or the
 *   current thread is not running with no_new_privs, or it doesn't have
 *   %CAP_SYS_ADMIN in its namespace.
 * - %E2BIG: The maximum number of stacked rulesets is reached for the current
 *   thread.
 *
 * .. kernel-doc:: include/uapi/linux/landlock.h
 *     :identifiers: landlock_restrict_self_flags
 */
SYSCALL_DEFINE2(landlock_restrict_self, const int, ruleset_fd, const __u32,
		flags)
{
	struct landlock_ruleset *new_dom,
		*ruleset __free(landlock_put_ruleset) = NULL;
	struct cred *new_cred;
	struct landlock_cred_security *new_llcred;
	bool __maybe_unused log_same_exec, log_new_exec, log_subdomains,
		prev_log_subdomains;
	int res;

	if (!is_initialized())
		return -EOPNOTSUPP;

	/*
	 * Similar checks as for seccomp(2), except that an -EPERM may be
	 * returned.
	 */
	if (!task_no_new_privs(current) &&
	    !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	if ((flags | LANDLOCK_MASK_RESTRICT_SELF) !=
	    LANDLOCK_MASK_RESTRICT_SELF)
		return -EINVAL;

	/* Translates "off" flag to boolean. */
	log_same_exec = !(flags & LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF);
	/* Translates "on" flag to boolean. */
	log_new_exec = !!(flags & LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON);
	/* Translates "off" flag to boolean. */
	log_subdomains = !(flags & LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF);

	/*
	 * It is allowed to set LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF with
	 * -1 as ruleset_fd, but no other flag must be set.
	 */
	if (!(ruleset_fd == -1 &&
	      flags == LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF)) {
		/* Gets and checks the ruleset. */
		ruleset = get_ruleset_from_fd(ruleset_fd, FMODE_CAN_READ);
		if (IS_ERR(ruleset))
			return PTR_ERR(ruleset);
	}

	/* Prepares new credentials. */
	new_cred = prepare_creds();
	if (!new_cred)
		return -ENOMEM;

	new_llcred = landlock_cred(new_cred);

#ifdef CONFIG_AUDIT
	prev_log_subdomains = !new_llcred->log_subdomains_off;
	new_llcred->log_subdomains_off = !prev_log_subdomains ||
					 !log_subdomains;
#endif /* CONFIG_AUDIT */

	/*
	 * The only case when a ruleset may not be set is if
	 * LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF is set and ruleset_fd is -1.
	 * We could optimize this case by not calling commit_creds() if this flag
	 * was already set, but it is not worth the complexity.
	 */
	if (!ruleset)
		return commit_creds(new_cred);

	/*
	 * There is no possible race condition while copying and manipulating
	 * the current credentials because they are dedicated per thread.
	 */
	new_dom = landlock_merge_ruleset(new_llcred->domain, ruleset);
	if (IS_ERR(new_dom)) {
		abort_creds(new_cred);
		return PTR_ERR(new_dom);
	}

#ifdef CONFIG_AUDIT
	new_dom->hierarchy->log_same_exec = log_same_exec;
	new_dom->hierarchy->log_new_exec = log_new_exec;
	if ((!log_same_exec && !log_new_exec) || !prev_log_subdomains)
		new_dom->hierarchy->log_status = LANDLOCK_LOG_DISABLED;
#endif /* CONFIG_AUDIT */

	/* Replaces the old (prepared) domain. */
	landlock_put_ruleset(new_llcred->domain);
	new_llcred->domain = new_dom;

#ifdef CONFIG_AUDIT
	new_llcred->domain_exec |= BIT(new_dom->num_layers - 1);
#endif /* CONFIG_AUDIT */

	if (flags & LANDLOCK_RESTRICT_SELF_TSYNC) {
		res = restrict_sibling_threads(current_cred(), new_cred);
		if (res != 0) {
			abort_creds(new_cred);
			return res;
		}
	}

	return commit_creds(new_cred);
}
