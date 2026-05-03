// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Filesystem management and hooks
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 * Copyright © 2021-2025 Microsoft Corporation
 * Copyright © 2022 Günther Noack <gnoack3000@gmail.com>
 * Copyright © 2023-2024 Google LLC
 */

#include <asm/ioctls.h>
#include <kunit/test.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/compiler_types.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/lsm_audit.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/wait_bit.h>
#include <linux/workqueue.h>
#include <net/af_unix.h>
#include <uapi/linux/fiemap.h>
#include <uapi/linux/landlock.h>

#include "access.h"
#include "audit.h"
#include "common.h"
#include "cred.h"
#include "domain.h"
#include "fs.h"
#include "limits.h"
#include "object.h"
#include "ruleset.h"
#include "setup.h"

/* Underlying object management */

static void release_inode(struct landlock_object *const object)
	__releases(object->lock)
{
	struct inode *const inode = object->underobj;
	struct super_block *sb;

	if (!inode) {
		spin_unlock(&object->lock);
		return;
	}

	/*
	 * Protects against concurrent use by hook_sb_delete() of the reference
	 * to the underlying inode.
	 */
	object->underobj = NULL;
	/*
	 * Makes sure that if the filesystem is concurrently unmounted,
	 * hook_sb_delete() will wait for us to finish iput().
	 */
	sb = inode->i_sb;
	atomic_long_inc(&landlock_superblock(sb)->inode_refs);
	spin_unlock(&object->lock);
	/*
	 * Because object->underobj was not NULL, hook_sb_delete() and
	 * get_inode_object() guarantee that it is safe to reset
	 * landlock_inode(inode)->object while it is not NULL.  It is therefore
	 * not necessary to lock inode->i_lock.
	 */
	rcu_assign_pointer(landlock_inode(inode)->object, NULL);
	/*
	 * Now, new rules can safely be tied to @inode with get_inode_object().
	 */

	iput(inode);
	if (atomic_long_dec_and_test(&landlock_superblock(sb)->inode_refs))
		wake_up_var(&landlock_superblock(sb)->inode_refs);
}

static const struct landlock_object_underops landlock_fs_underops = {
	.release = release_inode
};

/* IOCTL helpers */

/**
 * is_masked_device_ioctl - Determine whether an IOCTL command is always
 * permitted with Landlock for device files.  These commands can not be
 * restricted on device files by enforcing a Landlock policy.
 *
 * @cmd: The IOCTL command that is supposed to be run.
 *
 * By default, any IOCTL on a device file requires the
 * LANDLOCK_ACCESS_FS_IOCTL_DEV right.  However, we blanket-permit some
 * commands, if:
 *
 * 1. The command is implemented in fs/ioctl.c's do_vfs_ioctl(),
 *    not in f_ops->unlocked_ioctl() or f_ops->compat_ioctl().
 *
 * 2. The command is harmless when invoked on devices.
 *
 * We also permit commands that do not make sense for devices, but where the
 * do_vfs_ioctl() implementation returns a more conventional error code.
 *
 * Any new IOCTL commands that are implemented in fs/ioctl.c's do_vfs_ioctl()
 * should be considered for inclusion here.
 *
 * Return: True if the IOCTL @cmd can not be restricted with Landlock for
 * device files, false otherwise.
 */
static __attribute_const__ bool is_masked_device_ioctl(const unsigned int cmd)
{
	switch (cmd) {
	/*
	 * FIOCLEX, FIONCLEX, FIONBIO and FIOASYNC manipulate the FD's
	 * close-on-exec and the file's buffered-IO and async flags.  These
	 * operations are also available through fcntl(2), and are
	 * unconditionally permitted in Landlock.
	 */
	case FIOCLEX:
	case FIONCLEX:
	case FIONBIO:
	case FIOASYNC:
	/*
	 * FIOQSIZE queries the size of a regular file, directory, or link.
	 *
	 * We still permit it, because it always returns -ENOTTY for
	 * other file types.
	 */
	case FIOQSIZE:
	/*
	 * FIFREEZE and FITHAW freeze and thaw the file system which the
	 * given file belongs to.  Requires CAP_SYS_ADMIN.
	 *
	 * These commands operate on the file system's superblock rather
	 * than on the file itself.  The same operations can also be
	 * done through any other file or directory on the same file
	 * system, so it is safe to permit these.
	 */
	case FIFREEZE:
	case FITHAW:
	/*
	 * FS_IOC_FIEMAP queries information about the allocation of
	 * blocks within a file.
	 *
	 * This IOCTL command only makes sense for regular files and is
	 * not implemented by devices. It is harmless to permit.
	 */
	case FS_IOC_FIEMAP:
	/*
	 * FIGETBSZ queries the file system's block size for a file or
	 * directory.
	 *
	 * This command operates on the file system's superblock rather
	 * than on the file itself.  The same operation can also be done
	 * through any other file or directory on the same file system,
	 * so it is safe to permit it.
	 */
	case FIGETBSZ:
	/*
	 * FICLONE, FICLONERANGE and FIDEDUPERANGE make files share
	 * their underlying storage ("reflink") between source and
	 * destination FDs, on file systems which support that.
	 *
	 * These IOCTL commands only apply to regular files
	 * and are harmless to permit for device files.
	 */
	case FICLONE:
	case FICLONERANGE:
	case FIDEDUPERANGE:
	/*
	 * FS_IOC_GETFSUUID and FS_IOC_GETFSSYSFSPATH both operate on
	 * the file system superblock, not on the specific file, so
	 * these operations are available through any other file on the
	 * same file system as well.
	 */
	case FS_IOC_GETFSUUID:
	case FS_IOC_GETFSSYSFSPATH:
		return true;

	/*
	 * FIONREAD, FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_FSGETXATTR and
	 * FS_IOC_FSSETXATTR are forwarded to device implementations.
	 */

	/*
	 * file_ioctl() commands (FIBMAP, FS_IOC_RESVSP, FS_IOC_RESVSP64,
	 * FS_IOC_UNRESVSP, FS_IOC_UNRESVSP64 and FS_IOC_ZERO_RANGE) are
	 * forwarded to device implementations, so not permitted.
	 */

	/* Other commands are guarded by the access right. */
	default:
		return false;
	}
}

/*
 * is_masked_device_ioctl_compat - same as the helper above, but checking the
 * "compat" IOCTL commands.
 *
 * The IOCTL commands with special handling in compat-mode should behave the
 * same as their non-compat counterparts.
 */
static __attribute_const__ bool
is_masked_device_ioctl_compat(const unsigned int cmd)
{
	switch (cmd) {
	/* FICLONE is permitted, same as in the non-compat variant. */
	case FICLONE:
		return true;

#if defined(CONFIG_X86_64)
	/*
	 * FS_IOC_RESVSP_32, FS_IOC_RESVSP64_32, FS_IOC_UNRESVSP_32,
	 * FS_IOC_UNRESVSP64_32, FS_IOC_ZERO_RANGE_32: not blanket-permitted,
	 * for consistency with their non-compat variants.
	 */
	case FS_IOC_RESVSP_32:
	case FS_IOC_RESVSP64_32:
	case FS_IOC_UNRESVSP_32:
	case FS_IOC_UNRESVSP64_32:
	case FS_IOC_ZERO_RANGE_32:
#endif

	/*
	 * FS_IOC32_GETFLAGS, FS_IOC32_SETFLAGS are forwarded to their device
	 * implementations.
	 */
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
		return false;
	default:
		return is_masked_device_ioctl(cmd);
	}
}

/* Ruleset management */

static struct landlock_object *get_inode_object(struct inode *const inode)
{
	struct landlock_object *object, *new_object;
	struct landlock_inode_security *inode_sec = landlock_inode(inode);

	rcu_read_lock();
retry:
	object = rcu_dereference(inode_sec->object);
	if (object) {
		if (likely(refcount_inc_not_zero(&object->usage))) {
			rcu_read_unlock();
			return object;
		}
		/*
		 * We are racing with release_inode(), the object is going
		 * away.  Wait for release_inode(), then retry.
		 */
		spin_lock(&object->lock);
		spin_unlock(&object->lock);
		goto retry;
	}
	rcu_read_unlock();

	/*
	 * If there is no object tied to @inode, then create a new one (without
	 * holding any locks).
	 */
	new_object = landlock_create_object(&landlock_fs_underops, inode);
	if (IS_ERR(new_object))
		return new_object;

	/*
	 * Protects against concurrent calls to get_inode_object() or
	 * hook_sb_delete().
	 */
	spin_lock(&inode->i_lock);
	if (unlikely(rcu_access_pointer(inode_sec->object))) {
		/* Someone else just created the object, bail out and retry. */
		spin_unlock(&inode->i_lock);
		kfree(new_object);

		rcu_read_lock();
		goto retry;
	}

	/*
	 * @inode will be released by hook_sb_delete() on its superblock
	 * shutdown, or by release_inode() when no more ruleset references the
	 * related object.
	 */
	ihold(inode);
	rcu_assign_pointer(inode_sec->object, new_object);
	spin_unlock(&inode->i_lock);
	return new_object;
}

/* All access rights that can be tied to files. */
/* clang-format off */
#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV | \
	LANDLOCK_ACCESS_FS_RESOLVE_UNIX)
/* clang-format on */

/*
 * @path: Should have been checked by get_path_from_fd().
 */
int landlock_append_fs_rule(struct landlock_ruleset *const ruleset,
			    const struct path *const path,
			    access_mask_t access_rights)
{
	int err;
	struct landlock_id id = {
		.type = LANDLOCK_KEY_INODE,
	};

	/* Files only get access rights that make sense. */
	if (!d_is_dir(path->dentry) &&
	    !access_mask_subset(access_rights, ACCESS_FILE))
		return -EINVAL;
	if (WARN_ON_ONCE(ruleset->num_layers != 1))
		return -EINVAL;

	/* Transforms relative access rights to absolute ones. */
	access_rights |= LANDLOCK_MASK_ACCESS_FS &
			 ~landlock_get_fs_access_mask(ruleset, 0);
	id.key.object = get_inode_object(d_backing_inode(path->dentry));
	if (IS_ERR(id.key.object))
		return PTR_ERR(id.key.object);
	mutex_lock(&ruleset->lock);
	err = landlock_insert_rule(ruleset, id, access_rights);
	mutex_unlock(&ruleset->lock);
	/*
	 * No need to check for an error because landlock_insert_rule()
	 * increments the refcount for the new object if needed.
	 */
	landlock_put_object(id.key.object);
	return err;
}

/* Access-control management */

/*
 * The lifetime of the returned rule is tied to @domain.
 *
 * Returns NULL if no rule is found or if @dentry is negative.
 */
static const struct landlock_rule *
find_rule(const struct landlock_ruleset *const domain,
	  const struct dentry *const dentry)
{
	const struct landlock_rule *rule;
	const struct inode *inode;
	struct landlock_id id = {
		.type = LANDLOCK_KEY_INODE,
	};

	/* Ignores nonexistent leafs. */
	if (d_is_negative(dentry))
		return NULL;

	inode = d_backing_inode(dentry);
	rcu_read_lock();
	id.key.object = rcu_dereference(landlock_inode(inode)->object);
	rule = landlock_find_rule(domain, id);
	rcu_read_unlock();
	return rule;
}

/*
 * Allows access to pseudo filesystems that will never be mountable (e.g.
 * sockfs, pipefs), but can still be reachable through
 * /proc/<pid>/fd/<file-descriptor>
 */
static bool is_nouser_or_private(const struct dentry *dentry)
{
	return (dentry->d_sb->s_flags & SB_NOUSER) ||
	       (d_is_positive(dentry) &&
		unlikely(IS_PRIVATE(d_backing_inode(dentry))));
}

static const struct access_masks any_fs = {
	.fs = ~0,
};

/*
 * Collect the access bits granted to a single layer by @rule.  A rule
 * stores its layer entries in a sparse array, so iterate and merge the bits
 * of every entry that targets @layer_level (zero-based).
 */
static access_mask_t rule_layer_access(const struct landlock_rule *const rule,
				       const u16 layer_level)
{
	access_mask_t granted = 0;

	if (!rule)
		return 0;

	for (size_t i = 0; i < rule->num_layers; i++) {
		const struct landlock_layer *const layer = &rule->layers[i];

		if (layer->level - 1 == layer_level)
			granted |= layer->access;
	}
	return granted;
}

/**
 * walk_layer - Walk a file hierarchy upward for one Landlock layer
 *
 * @domain: Domain to check against.
 * @path: File hierarchy to walk through.  Walked upward to the real root
 *     (through mount points) or until @remaining reaches 0.
 * @layer_level: Zero-based index of the layer being walked.
 * @remaining: Unfulfilled access rights for this layer at the start of the
 *     walk.
 *
 * Return: The access rights that are still unfulfilled once the walk ends.
 * A return value of 0 means this layer grants every requested access along
 * the @path hierarchy.
 */
static access_mask_t walk_layer(const struct landlock_ruleset *const domain,
				const struct path *const path,
				const u16 layer_level, access_mask_t remaining)
{
	struct path walker;

	if (!remaining)
		return 0;

	walker = *path;
	path_get(&walker);

	while (true) {
		remaining &= ~rule_layer_access(
			find_rule(domain, walker.dentry), layer_level);
		if (!remaining)
			break;

		/* Hop across mount points until a non-root dentry is found. */
		while (walker.dentry == walker.mnt->mnt_root) {
			if (!follow_up(&walker))
				goto out; /* real root: stop */
		}

		if (unlikely(IS_ROOT(walker.dentry))) {
			if (likely(walker.mnt->mnt_flags & MNT_INTERNAL)) {
				/*
				 * Internal filesystem disconnected root (e.g.
				 * nsfs reached via /proc/<pid>/ns/<ns>):
				 * treat as fully allowed.
				 */
				remaining = 0;
				break;
			}

			/*
			 * Disconnected root from a bind mount: resume from
			 * the mount root.
			 */
			dput(walker.dentry);
			walker.dentry = walker.mnt->mnt_root;
			dget(walker.dentry);
		} else {
			struct dentry *const parent =
				dget_parent(walker.dentry);

			dput(walker.dentry);
			walker.dentry = parent;
		}
	}
out:
	path_put(&walker);
	return remaining;
}

/*
 * may_refer_layer - Per-layer privilege-escalation check for refer actions
 *
 * At a single layer, return true iff moving a child with @src_child_remaining
 * unfulfilled bits under @src_parent_remaining would not gain new access bits
 * under @new_parent_remaining.  All inputs are post-walk per-layer remaining
 * masks (bits the path/dentry did *not* grant at this layer).
 *
 * For a non-directory child, only file-applicable bits matter.
 */
static bool may_refer_layer(const access_mask_t src_parent_remaining,
			    const access_mask_t src_child_remaining,
			    const access_mask_t new_parent_remaining,
			    const bool child_is_dir)
{
	access_mask_t child_access =
		src_parent_remaining & src_child_remaining;
	access_mask_t parent_access = new_parent_remaining;

	if (!child_is_dir) {
		child_access &= ACCESS_FILE;
		parent_access &= ACCESS_FILE;
	}
	return access_mask_subset(child_access, parent_access);
}

/*
 * walk_for_refer_layer - Single-layer walk for the refer path
 *
 * Walk from @start upward to @mnt_dir->dentry (a mount root), then continue
 * upward through mountpoints.  Decrement @remaining by every rule's
 * @layer_level bits along the way.
 *
 * Returns the unfulfilled bits at the end of the walk; 0 means the layer
 * grants every initially-requested bit somewhere on the way up.
 */
static access_mask_t
walk_for_refer_layer(const struct landlock_ruleset *const domain,
		     struct dentry *const start,
		     const struct path *const mnt_dir, const u16 layer_level,
		     access_mask_t remaining)
{
	struct dentry *walker;

	if (!remaining)
		return 0;

	walker = dget(start);
	while (true) {
		struct dentry *parent;

		remaining &= ~rule_layer_access(find_rule(domain, walker),
						layer_level);
		if (!remaining || walker == mnt_dir->dentry ||
		    unlikely(IS_ROOT(walker)))
			break;
		parent = dget_parent(walker);
		dput(walker);
		walker = parent;
	}
	dput(walker);

	if (remaining)
		remaining = walk_layer(domain, mnt_dir, layer_level, remaining);
	return remaining;
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

#define MRL_TRUE(...) KUNIT_EXPECT_TRUE(test, may_refer_layer(__VA_ARGS__))
#define MRL_FALSE(...) KUNIT_EXPECT_FALSE(test, may_refer_layer(__VA_ARGS__))

static void test_may_refer_layer(struct kunit *const test)
{
	const access_mask_t X = LANDLOCK_ACCESS_FS_EXECUTE;
	const access_mask_t R = LANDLOCK_ACCESS_FS_READ_FILE;
	const access_mask_t M = LANDLOCK_ACCESS_FS_MAKE_REG;
	const access_mask_t XR = X | R;
	const access_mask_t XM = X | M;

	/* Unrestricted destination always accepts. */
	MRL_TRUE(X, 0, 0, false);
	MRL_TRUE(0, X, 0, false);
	MRL_FALSE(X, X, 0, false);

	/* Refer requires no inherited access at this layer. */
	MRL_TRUE(X, X, X, false);
	MRL_TRUE(XR, XR, XR, false);
	MRL_FALSE(XR, XR, X, false);

	/* File-only check ignores directory-only bits. */
	MRL_TRUE(XM, XM, X, false);
	MRL_FALSE(XM, XM, X, true);

	/* Disjoint child/parent: child_access is zero, allowed. */
	MRL_TRUE(X, R, X, false);
}

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#undef MRL_TRUE
#undef MRL_FALSE

/**
 * walk_path_per_layer - Per-layer path walk, storing one remaining mask per layer
 *
 * @domain: Domain to check against.
 * @path: File hierarchy to walk upward.
 * @access_request: Requested access bits.
 * @remaining_out: Per-layer unfulfilled bits on return; slots beyond
 *     @domain->num_layers are zeroed.
 *
 * Each entry of @remaining_out is the intersection of the requested
 * accesses with what that layer handled but did not grant anywhere along
 * @path.  A zero entry means the layer granted every requested access.
 */
static void walk_path_per_layer(const struct landlock_ruleset *const domain,
				const struct path *const path,
				const access_mask_t access_request,
				access_mask_t remaining_out[LANDLOCK_MAX_NUM_LAYERS])
{
	memset(remaining_out, 0, sizeof(access_mask_t) * LANDLOCK_MAX_NUM_LAYERS);

	if (is_nouser_or_private(path->dentry))
		return;

	for (u16 i = 0; i < domain->num_layers; i++) {
		const access_mask_t initial =
			landlock_get_fs_access_mask(domain, i) & access_request;

		remaining_out[i] = walk_layer(domain, path, i, initial);
	}
}

/*
 * Reduce a per-layer remaining array to the deepest denying layer.  Returns
 * true if every layer was fulfilled (no denial), false otherwise.  On false,
 * @narrowed_out gets that layer's remaining bits and @layer_out its index.
 */
static bool reduce_to_youngest_denier(
	const access_mask_t remaining[LANDLOCK_MAX_NUM_LAYERS],
	const u16 num_layers, access_mask_t *const narrowed_out,
	size_t *const layer_out)
{
	bool any_unfulfilled = false;

	*narrowed_out = 0;
	*layer_out = 0;

	for (u16 i = 0; i < num_layers; i++) {
		if (remaining[i]) {
			*narrowed_out = remaining[i];
			*layer_out = i;
			any_unfulfilled = true;
		}
	}

	return !any_unfulfilled;
}

static int current_check_access_path(const struct path *const path,
				     const access_mask_t access_request)
{
	const struct access_masks masks = {
		.fs = access_request,
	};
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), masks, NULL);
	access_mask_t remaining[LANDLOCK_MAX_NUM_LAYERS];
	access_mask_t unfulfilled;
	size_t denying_layer;

	if (!subject)
		return 0;

	walk_path_per_layer(subject->domain, path, access_request, remaining);
	if (reduce_to_youngest_denier(remaining, subject->domain->num_layers,
				      &unfulfilled, &denying_layer))
		return 0;

	landlock_log_denial(subject,
			    &(struct landlock_request){
				    .type = LANDLOCK_REQUEST_FS_ACCESS,
				    .audit.type = LSM_AUDIT_DATA_PATH,
				    .audit.u.path = *path,
				    .access = unfulfilled,
				    .layer_plus_one = denying_layer + 1,
			    });
	return -EACCES;
}

static __attribute_const__ access_mask_t get_mode_access(const umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFLNK:
		return LANDLOCK_ACCESS_FS_MAKE_SYM;
	case S_IFDIR:
		return LANDLOCK_ACCESS_FS_MAKE_DIR;
	case S_IFCHR:
		return LANDLOCK_ACCESS_FS_MAKE_CHAR;
	case S_IFBLK:
		return LANDLOCK_ACCESS_FS_MAKE_BLOCK;
	case S_IFIFO:
		return LANDLOCK_ACCESS_FS_MAKE_FIFO;
	case S_IFSOCK:
		return LANDLOCK_ACCESS_FS_MAKE_SOCK;
	case S_IFREG:
	case 0:
		/* A zero mode translates to S_IFREG. */
	default:
		/* Treats weird files as regular files. */
		return LANDLOCK_ACCESS_FS_MAKE_REG;
	}
}

static access_mask_t maybe_remove(const struct dentry *const dentry)
{
	if (d_is_negative(dentry))
		return 0;
	return d_is_dir(dentry) ? LANDLOCK_ACCESS_FS_REMOVE_DIR :
				  LANDLOCK_ACCESS_FS_REMOVE_FILE;
}

/**
 * current_check_refer_path - Check if a rename or link action is allowed
 *
 * @old_dentry: File or directory requested to be moved or linked.
 * @new_dir: Destination parent directory.
 * @new_dentry: Destination file or directory.
 * @removable: Sets to true if it is a rename operation.
 * @exchange: Sets to true if it is a rename operation with RENAME_EXCHANGE.
 *
 * Because of its unprivileged constraints, Landlock relies on file hierarchies
 * (and not only inodes) to tie access rights to files.  Being able to link or
 * rename a file hierarchy brings some challenges.  Indeed, moving or linking a
 * file (i.e. creating a new reference to an inode) can have an impact on the
 * actions allowed for a set of files if it would change its parent directory
 * (i.e. reparenting).
 *
 * To avoid trivial access right bypasses, Landlock first checks if the file or
 * directory requested to be moved would gain new access rights inherited from
 * its new hierarchy.  Before returning any error, Landlock then checks that
 * the parent source hierarchy and the destination hierarchy would allow the
 * link or rename action.  If it is not the case, an error with EACCES is
 * returned to inform user space that there is no way to remove or create the
 * requested source file type.  If it should be allowed but the new inherited
 * access rights would be greater than the source access rights, then the
 * kernel returns an error with EXDEV.  Prioritizing EACCES over EXDEV enables
 * user space to abort the whole operation if there is no way to do it, or to
 * manually copy the source to the destination if this remains allowed, e.g.
 * because file creation is allowed on the destination directory but not direct
 * linking.
 *
 * To achieve this goal, the kernel walks each parent hierarchy once per
 * layer (the same per-layer walk shape as the rest of Landlock's fs
 * checks), tracks the per-layer "still unfulfilled" bits as plain
 * access_mask_t arrays on the stack, and evaluates the privilege
 * escalation predicate as a per-layer subset check across the source and
 * destination remaining masks.  Stack usage scales with
 * LANDLOCK_MAX_NUM_LAYERS (currently 16).
 *
 * Return: 0 if access is allowed, -EXDEV if @old_dentry would inherit new
 * access rights from @new_dir, or -EACCES if file removal or creation is
 * denied.
 */
static int current_check_refer_path(struct dentry *const old_dentry,
				    const struct path *const new_dir,
				    struct dentry *const new_dentry,
				    const bool removable, const bool exchange)
{
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs, NULL);
	const struct landlock_ruleset *domain;
	access_mask_t access_request_parent1, access_request_parent2;
	struct path mnt_dir;
	struct dentry *old_parent;

	if (!subject)
		return 0;
	domain = subject->domain;

	if (unlikely(d_is_negative(old_dentry)))
		return -ENOENT;
	if (exchange) {
		if (unlikely(d_is_negative(new_dentry)))
			return -ENOENT;
		access_request_parent1 =
			get_mode_access(d_backing_inode(new_dentry)->i_mode);
	} else {
		access_request_parent1 = 0;
	}
	access_request_parent2 =
		get_mode_access(d_backing_inode(old_dentry)->i_mode);
	if (removable) {
		access_request_parent1 |= maybe_remove(old_dentry);
		access_request_parent2 |= maybe_remove(new_dentry);
	}

	/* The mount points are the same for old and new paths, cf. EXDEV. */
	if (old_dentry->d_parent == new_dir->dentry) {
		/*
		 * The LANDLOCK_ACCESS_FS_REFER access right is not required
		 * for same-directory referer (i.e. no reparenting): both ends
		 * sit under the same parent so there is no privilege
		 * escalation risk.  This collapses to the regular per-layer
		 * path walk against the union of both parents' requests.
		 */
		access_mask_t remaining[LANDLOCK_MAX_NUM_LAYERS];
		access_mask_t unfulfilled;
		size_t denying_layer;

		walk_path_per_layer(domain, new_dir,
				    access_request_parent1 |
					    access_request_parent2,
				    remaining);
		if (reduce_to_youngest_denier(remaining, domain->num_layers,
					      &unfulfilled, &denying_layer))
			return 0;

		landlock_log_denial(subject,
				    &(struct landlock_request){
					    .type = LANDLOCK_REQUEST_FS_ACCESS,
					    .audit.type = LSM_AUDIT_DATA_PATH,
					    .audit.u.path = *new_dir,
					    .access = unfulfilled,
					    .layer_plus_one = denying_layer + 1,
				    });
		return -EACCES;
	}

	access_request_parent1 |= LANDLOCK_ACCESS_FS_REFER;
	access_request_parent2 |= LANDLOCK_ACCESS_FS_REFER;

	/* Saves the common mount point. */
	mnt_dir.mnt = new_dir->mnt;
	mnt_dir.dentry = new_dir->mnt->mnt_root;

	/*
	 * old_dentry may be the root of the common mount point and
	 * !IS_ROOT(old_dentry) at the same time (e.g. with open_tree() and
	 * OPEN_TREE_CLONE).  We do not need to call dget(old_parent) because
	 * we keep a reference to old_dentry.
	 */
	old_parent = (old_dentry == mnt_dir.dentry) ? old_dentry :
						      old_dentry->d_parent;

	{
		const struct landlock_rule *const child1_rule =
			find_rule(domain, old_dentry);
		const struct landlock_rule *const child2_rule =
			exchange ? find_rule(domain, new_dentry) : NULL;
		const bool child1_is_dir = d_is_dir(old_dentry);
		const bool child2_is_dir =
			exchange ? d_is_dir(new_dentry) : true;
		const bool old_parent_private =
			is_nouser_or_private(old_parent);
		const bool new_parent_private =
			is_nouser_or_private(new_dir->dentry);
		access_mask_t p1[LANDLOCK_MAX_NUM_LAYERS] = {};
		access_mask_t p2[LANDLOCK_MAX_NUM_LAYERS] = {};
		access_mask_t scope1, scope2;
		access_mask_t youngest1 = 0, youngest2 = 0;
		size_t layer1 = 0, layer2 = 0;
		bool dom_ok = true;
		bool eacces1 = false, eacces2 = false;

		/*
		 * Outer per-layer loop: walk both parent hierarchies (source
		 * and destination), compute each layer's still-unfulfilled
		 * bits against the full domain-handled set, derive the
		 * children's per-layer remaining masks from their dentry rule,
		 * and evaluate the privilege escalation predicate locally.
		 */
		for (u16 i = 0; i < domain->num_layers; i++) {
			const access_mask_t handled =
				landlock_get_fs_access_mask(domain, i);
			access_mask_t r1 =
				old_parent_private ? 0 : handled;
			access_mask_t r2 =
				new_parent_private ? 0 : handled;
			const access_mask_t c1 =
				handled &
				~rule_layer_access(child1_rule, i);
			const access_mask_t c2 =
				exchange ?
					handled & ~rule_layer_access(
							  child2_rule, i) :
					0;

			if (r1)
				r1 = walk_for_refer_layer(domain, old_parent,
							  &mnt_dir, i, r1);
			if (r2)
				r2 = walk_for_refer_layer(domain,
							  new_dir->dentry,
							  &mnt_dir, i, r2);
			p1[i] = r1;
			p2[i] = r2;

			if (!may_refer_layer(r1, c1, r2, child1_is_dir))
				dom_ok = false;
			if (exchange &&
			    !may_refer_layer(r2, c2, r1, child2_is_dir))
				dom_ok = false;
		}

		/*
		 * If no privilege escalation is possible, narrow the denial
		 * check to the actually-requested bits.  Otherwise the layer's
		 * full handled set must have been fully granted somewhere on
		 * the path, or refer is denied.
		 */
		if (dom_ok) {
			scope1 = access_request_parent1;
			scope2 = access_request_parent2;
		} else {
			scope1 = scope2 =
				landlock_union_access_masks(domain).fs;
		}

		for (u16 i = 0; i < domain->num_layers; i++) {
			const access_mask_t s1 = p1[i] & scope1;
			const access_mask_t s2 = p2[i] & scope2;

			if (s1) {
				youngest1 = s1;
				layer1 = i;
			}
			if (s2) {
				youngest2 = s2;
				layer2 = i;
			}
			/*
			 * EACCES vs EXDEV: any non-REFER bit unmet against
			 * the original request is a hard deny; REFER alone
			 * yields EXDEV.
			 */
			if (p1[i] & access_request_parent1 &
			    ~LANDLOCK_ACCESS_FS_REFER)
				eacces1 = true;
			if (p2[i] & access_request_parent2 &
			    ~LANDLOCK_ACCESS_FS_REFER)
				eacces2 = true;
		}

		if (!youngest1 && !youngest2)
			return 0;

		if (youngest1)
			landlock_log_denial(
				subject,
				&(struct landlock_request){
					.type = LANDLOCK_REQUEST_FS_ACCESS,
					.audit.type = LSM_AUDIT_DATA_PATH,
					.audit.u.path.mnt = mnt_dir.mnt,
					.audit.u.path.dentry = old_parent,
					.access = youngest1,
					.layer_plus_one = layer1 + 1,
				});
		if (youngest2)
			landlock_log_denial(
				subject,
				&(struct landlock_request){
					.type = LANDLOCK_REQUEST_FS_ACCESS,
					.audit.type = LSM_AUDIT_DATA_PATH,
					.audit.u.path.mnt = mnt_dir.mnt,
					.audit.u.path.dentry = new_dir->dentry,
					.access = youngest2,
					.layer_plus_one = layer2 + 1,
				});

		if (likely(eacces1 || eacces2))
			return -EACCES;
		return -EXDEV;
	}
}

/* Inode hooks */

static void hook_inode_free_security_rcu(void *inode_security)
{
	struct landlock_inode_security *inode_sec;

	/*
	 * All inodes must already have been untied from their object by
	 * release_inode() or hook_sb_delete().
	 */
	inode_sec = inode_security + landlock_blob_sizes.lbs_inode;
	WARN_ON_ONCE(inode_sec->object);
}

/* Super-block hooks */

/*
 * Release the inodes used in a security policy.
 *
 * Cf. fsnotify_unmount_inodes() and evict_inodes()
 */
static void hook_sb_delete(struct super_block *const sb)
{
	struct inode *inode, *prev_inode = NULL;

	if (!landlock_initialized)
		return;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		struct landlock_object *object;

		/* Only handles referenced inodes. */
		if (!icount_read(inode))
			continue;

		/*
		 * Protects against concurrent modification of inode (e.g.
		 * from get_inode_object()).
		 */
		spin_lock(&inode->i_lock);
		/*
		 * Checks I_FREEING and I_WILL_FREE  to protect against a race
		 * condition when release_inode() just called iput(), which
		 * could lead to a NULL dereference of inode->security or a
		 * second call to iput() for the same Landlock object.  Also
		 * checks I_NEW because such inode cannot be tied to an object.
		 */
		if (inode_state_read(inode) &
		    (I_FREEING | I_WILL_FREE | I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		rcu_read_lock();
		object = rcu_dereference(landlock_inode(inode)->object);
		if (!object) {
			rcu_read_unlock();
			spin_unlock(&inode->i_lock);
			continue;
		}
		/* Keeps a reference to this inode until the next loop walk. */
		__iget(inode);
		spin_unlock(&inode->i_lock);

		/*
		 * If there is no concurrent release_inode() ongoing, then we
		 * are in charge of calling iput() on this inode, otherwise we
		 * will just wait for it to finish.
		 */
		spin_lock(&object->lock);
		if (object->underobj == inode) {
			object->underobj = NULL;
			spin_unlock(&object->lock);
			rcu_read_unlock();

			/*
			 * Because object->underobj was not NULL,
			 * release_inode() and get_inode_object() guarantee
			 * that it is safe to reset
			 * landlock_inode(inode)->object while it is not NULL.
			 * It is therefore not necessary to lock inode->i_lock.
			 */
			rcu_assign_pointer(landlock_inode(inode)->object, NULL);
			/*
			 * At this point, we own the ihold() reference that was
			 * originally set up by get_inode_object() and the
			 * __iget() reference that we just set in this loop
			 * walk.  Therefore there are at least two references
			 * on the inode.
			 */
			iput_not_last(inode);
		} else {
			spin_unlock(&object->lock);
			rcu_read_unlock();
		}

		if (prev_inode) {
			/*
			 * At this point, we still own the __iget() reference
			 * that we just set in this loop walk.  Therefore we
			 * can drop the list lock and know that the inode won't
			 * disappear from under us until the next loop walk.
			 */
			spin_unlock(&sb->s_inode_list_lock);
			/*
			 * We can now actually put the inode reference from the
			 * previous loop walk, which is not needed anymore.
			 */
			iput(prev_inode);
			cond_resched();
			spin_lock(&sb->s_inode_list_lock);
		}
		prev_inode = inode;
	}
	spin_unlock(&sb->s_inode_list_lock);

	/* Puts the inode reference from the last loop walk, if any. */
	if (prev_inode)
		iput(prev_inode);
	/* Waits for pending iput() in release_inode(). */
	wait_var_event(&landlock_superblock(sb)->inode_refs,
		       !atomic_long_read(&landlock_superblock(sb)->inode_refs));
}

static void
log_fs_change_topology_path(const struct landlock_cred_security *const subject,
			    size_t handle_layer, const struct path *const path)
{
	landlock_log_denial(subject, &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_CHANGE_TOPOLOGY,
		.audit = {
			.type = LSM_AUDIT_DATA_PATH,
			.u.path = *path,
		},
		.layer_plus_one = handle_layer + 1,
	});
}

static void log_fs_change_topology_dentry(
	const struct landlock_cred_security *const subject, size_t handle_layer,
	struct dentry *const dentry)
{
	landlock_log_denial(subject, &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_CHANGE_TOPOLOGY,
		.audit = {
			.type = LSM_AUDIT_DATA_DENTRY,
			.u.dentry = dentry,
		},
		.layer_plus_one = handle_layer + 1,
	});
}

/*
 * Because a Landlock security policy is defined according to the filesystem
 * topology (i.e. the mount namespace), changing it may grant access to files
 * not previously allowed.
 *
 * To make it simple, deny any filesystem topology modification by landlocked
 * processes.  Non-landlocked processes may still change the namespace of a
 * landlocked process, but this kind of threat must be handled by a system-wide
 * access-control security policy.
 *
 * This could be lifted in the future if Landlock can safely handle mount
 * namespace updates requested by a landlocked process.  Indeed, we could
 * update the current domain (which is currently read-only) by taking into
 * account the accesses of the source and the destination of a new mount point.
 * However, it would also require to make all the child domains dynamically
 * inherit these new constraints.  Anyway, for backward compatibility reasons,
 * a dedicated user space option would be required (e.g. as a ruleset flag).
 */
static int hook_sb_mount(const char *const dev_name,
			 const struct path *const path, const char *const type,
			 const unsigned long flags, void *const data)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_path(subject, handle_layer, path);
	return -EPERM;
}

static int hook_move_mount(const struct path *const from_path,
			   const struct path *const to_path)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_path(subject, handle_layer, to_path);
	return -EPERM;
}

/*
 * Removing a mount point may reveal a previously hidden file hierarchy, which
 * may then grant access to files, which may have previously been forbidden.
 */
static int hook_sb_umount(struct vfsmount *const mnt, const int flags)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_dentry(subject, handle_layer, mnt->mnt_root);
	return -EPERM;
}

static int hook_sb_remount(struct super_block *const sb, void *const mnt_opts)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_dentry(subject, handle_layer, sb->s_root);
	return -EPERM;
}

/*
 * pivot_root(2), like mount(2), changes the current mount namespace.  It must
 * then be forbidden for a landlocked process.
 *
 * However, chroot(2) may be allowed because it only changes the relative root
 * directory of the current process.  Moreover, it can be used to restrict the
 * view of the filesystem.
 */
static int hook_sb_pivotroot(const struct path *const old_path,
			     const struct path *const new_path)
{
	size_t handle_layer;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), any_fs,
						&handle_layer);

	if (!subject)
		return 0;

	log_fs_change_topology_path(subject, handle_layer, new_path);
	return -EPERM;
}

/* Path hooks */

static int hook_path_link(struct dentry *const old_dentry,
			  const struct path *const new_dir,
			  struct dentry *const new_dentry)
{
	return current_check_refer_path(old_dentry, new_dir, new_dentry, false,
					false);
}

static int hook_path_rename(const struct path *const old_dir,
			    struct dentry *const old_dentry,
			    const struct path *const new_dir,
			    struct dentry *const new_dentry,
			    const unsigned int flags)
{
	/* old_dir refers to old_dentry->d_parent and new_dir->mnt */
	return current_check_refer_path(old_dentry, new_dir, new_dentry, true,
					!!(flags & RENAME_EXCHANGE));
}

static int hook_path_mkdir(const struct path *const dir,
			   struct dentry *const dentry, const umode_t mode)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_DIR);
}

static int hook_path_mknod(const struct path *const dir,
			   struct dentry *const dentry, const umode_t mode,
			   const unsigned int dev)
{
	return current_check_access_path(dir, get_mode_access(mode));
}

static int hook_path_symlink(const struct path *const dir,
			     struct dentry *const dentry,
			     const char *const old_name)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_MAKE_SYM);
}

static int hook_path_unlink(const struct path *const dir,
			    struct dentry *const dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_REMOVE_FILE);
}

static int hook_path_rmdir(const struct path *const dir,
			   struct dentry *const dentry)
{
	return current_check_access_path(dir, LANDLOCK_ACCESS_FS_REMOVE_DIR);
}

static int hook_path_truncate(const struct path *const path)
{
	return current_check_access_path(path, LANDLOCK_ACCESS_FS_TRUNCATE);
}

/**
 * unmask_scoped_access - Remove access right bits in @masks in all layers
 *                        where @client and @server have the same domain
 *
 * This does the same as domain_is_scoped(), but unmasks bits in @masks.
 * It can not return early as domain_is_scoped() does.
 *
 * A scoped access for a given access right bit is allowed iff, for all layer
 * depths where the access bit is set, the client and server domain are the
 * same.  This function clears the access rights @access in @masks at all layer
 * depths where the client and server domain are the same, so that, when they
 * are all cleared, the access is allowed.
 *
 * @client: Client domain
 * @server: Server domain
 * @masks: Layer access masks to unmask
 * @access: Access bits that control scoping
 */
static void unmask_scoped_access(const struct landlock_ruleset *const client,
				 const struct landlock_ruleset *const server,
				 access_mask_t remaining[LANDLOCK_MAX_NUM_LAYERS],
				 const access_mask_t access)
{
	int client_layer, server_layer;
	const struct landlock_hierarchy *client_walker, *server_walker;

	/* This should not happen. */
	if (WARN_ON_ONCE(!client))
		return;

	/* Server has no Landlock domain; nothing to clear. */
	if (!server)
		return;

	/*
	 * client_layer must be able to represent all numbers from
	 * LANDLOCK_MAX_NUM_LAYERS - 1 to -1 for the loop below to terminate.
	 * (It must be large enough, and it must be signed.)
	 */
	BUILD_BUG_ON(!is_signed_type(typeof(client_layer)));
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_LAYERS - 1 >
		     type_max(typeof(client_layer)));

	client_layer = client->num_layers - 1;
	client_walker = client->hierarchy;
	server_layer = server->num_layers - 1;
	server_walker = server->hierarchy;

	/*
	 * Clears the access bits at all layers where the client domain is the
	 * same as the server domain.  We start the walk at min(client_layer,
	 * server_layer).  The layer bits until there can not be cleared because
	 * either the client or the server domain is missing.
	 */
	for (; client_layer > server_layer; client_layer--)
		client_walker = client_walker->parent;

	for (; server_layer > client_layer; server_layer--)
		server_walker = server_walker->parent;

	for (; client_layer >= 0; client_layer--) {
		if (remaining[client_layer] & access &&
		    client_walker == server_walker)
			remaining[client_layer] &= ~access;

		client_walker = client_walker->parent;
		server_walker = server_walker->parent;
	}
}

static int hook_unix_find(const struct path *const path, struct sock *other,
			  int flags)
{
	const struct landlock_ruleset *dom_other;
	const struct landlock_cred_security *subject;
	access_mask_t remaining[LANDLOCK_MAX_NUM_LAYERS] = {};
	access_mask_t unfulfilled;
	size_t denying_layer;
	u16 i;
	static const struct access_masks fs_resolve_unix = {
		.fs = LANDLOCK_ACCESS_FS_RESOLVE_UNIX,
	};

	/* Lookup for the purpose of saving coredumps is OK. */
	if (unlikely(flags & SOCK_COREDUMP))
		return 0;

	subject = landlock_get_applicable_subject(current_cred(),
						  fs_resolve_unix, NULL);

	if (!subject)
		return 0;

	/*
	 * Seed each layer's unfulfilled bits with the subset of the requested
	 * accesses that the layer handles (equivalent to the former
	 * landlock_init_layer_masks() call with LANDLOCK_KEY_INODE).
	 */
	for (i = 0; i < subject->domain->num_layers; i++)
		remaining[i] = landlock_get_fs_access_mask(subject->domain, i) &
			       fs_resolve_unix.fs;

	/* Checks the layers in which we are connecting within the same domain. */
	unix_state_lock(other);
	if (unlikely(sock_flag(other, SOCK_DEAD) || !other->sk_socket ||
		     !other->sk_socket->file)) {
		unix_state_unlock(other);
		/*
		 * We rely on the caller to catch the (non-reversible) SOCK_DEAD
		 * condition and retry the lookup.  If we returned an error
		 * here, the lookup would not get retried.
		 */
		return 0;
	}
	dom_other = landlock_cred(other->sk_socket->file->f_cred)->domain;

	/* Access to the same (or a lower) domain is always allowed. */
	unmask_scoped_access(subject->domain, dom_other, remaining,
			     fs_resolve_unix.fs);
	unix_state_unlock(other);

	/* Checks the connections to allow-listed paths. */
	if (is_nouser_or_private(path->dentry))
		return 0;
	for (i = 0; i < subject->domain->num_layers; i++)
		remaining[i] = walk_layer(subject->domain, path, i,
					  remaining[i]);

	if (reduce_to_youngest_denier(remaining, subject->domain->num_layers,
				      &unfulfilled, &denying_layer))
		return 0;

	landlock_log_denial(subject,
			    &(struct landlock_request){
				    .type = LANDLOCK_REQUEST_FS_ACCESS,
				    .audit.type = LSM_AUDIT_DATA_PATH,
				    .audit.u.path = *path,
				    .access = unfulfilled,
				    .layer_plus_one = denying_layer + 1,
			    });
	return -EACCES;
}

/* File hooks */

/**
 * get_required_file_open_access - Get access needed to open a file
 *
 * @file: File being opened.
 *
 * Return: The access rights that are required for opening the given file,
 * depending on the file type and open mode.
 */
static access_mask_t
get_required_file_open_access(const struct file *const file)
{
	access_mask_t access = 0;

	if (file->f_mode & FMODE_READ) {
		/* A directory can only be opened in read mode. */
		if (S_ISDIR(file_inode(file)->i_mode))
			return LANDLOCK_ACCESS_FS_READ_DIR;
		access = LANDLOCK_ACCESS_FS_READ_FILE;
	}
	if (file->f_mode & FMODE_WRITE)
		access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	/* __FMODE_EXEC is indeed part of f_flags, not f_mode. */
	if (file->f_flags & __FMODE_EXEC)
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	return access;
}

static int hook_file_alloc_security(struct file *const file)
{
	/*
	 * Grants all access rights, even if most of them are not checked later
	 * on. It is more consistent.
	 *
	 * Notably, file descriptors for regular files can also be acquired
	 * without going through the file_open hook, for example when using
	 * memfd_create(2).
	 */
	landlock_file(file)->allowed_access = LANDLOCK_MASK_ACCESS_FS;
	return 0;
}

static bool is_device(const struct file *const file)
{
	const struct inode *inode = file_inode(file);

	return S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode);
}

static int hook_file_open(struct file *const file)
{
	access_mask_t remaining[LANDLOCK_MAX_NUM_LAYERS];
	access_mask_t open_access_request, full_access_request, allowed_access,
		optional_access;
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(file->f_cred, any_fs, NULL);
	access_mask_t unfulfilled;
	size_t denying_layer;

	if (!subject)
		return 0;

	/*
	 * Because a file may be opened with O_PATH, get_required_file_open_access()
	 * may return 0.  This case will be handled with a future Landlock
	 * evolution.
	 */
	open_access_request = get_required_file_open_access(file);

	/*
	 * We look up more access than what we immediately need for open(), so
	 * that we can later authorize operations on opened files.
	 */
	optional_access = LANDLOCK_ACCESS_FS_TRUNCATE;
	if (is_device(file))
		optional_access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;

	full_access_request = open_access_request | optional_access;

	walk_path_per_layer(subject->domain, &file->f_path, full_access_request,
			    remaining);

	/*
	 * Remove bits still unfulfilled in any layer from the granted set.
	 * allowed_access is then recorded on the opened file for future
	 * operations (e.g. ftruncate()) that reuse it.
	 */
	allowed_access = full_access_request;
	for (u16 i = 0; i < subject->domain->num_layers; i++)
		allowed_access &= ~remaining[i];

	landlock_file(file)->allowed_access = allowed_access;
#ifdef CONFIG_AUDIT
	landlock_file(file)->deny_masks = landlock_get_deny_masks(
		_LANDLOCK_ACCESS_FS_OPTIONAL, optional_access, remaining);
#endif /* CONFIG_AUDIT */

	if (access_mask_subset(open_access_request, allowed_access))
		return 0;

	/*
	 * Reduce per-layer remaining bits to the deepest denying layer,
	 * narrowing to what the user actually asked for on open() so the
	 * audit record does not mention the opportunistic optional_access
	 * lookup bits (truncate, ioctl_dev).  The subset check above
	 * guarantees at least one open_access_request bit is still
	 * unfulfilled somewhere, so this always finds a denying layer.
	 */
	for (u16 i = 0; i < subject->domain->num_layers; i++)
		remaining[i] &= open_access_request;
	reduce_to_youngest_denier(remaining, subject->domain->num_layers,
				  &unfulfilled, &denying_layer);

	landlock_log_denial(subject,
			    &(struct landlock_request){
				    .type = LANDLOCK_REQUEST_FS_ACCESS,
				    .audit.type = LSM_AUDIT_DATA_PATH,
				    .audit.u.path = file->f_path,
				    .access = unfulfilled,
				    .layer_plus_one = denying_layer + 1,
			    });
	return -EACCES;
}

static int hook_file_truncate(struct file *const file)
{
	/*
	 * Allows truncation if the truncate right was available at the time of
	 * opening the file, to get a consistent access check as for read, write
	 * and execute operations.
	 *
	 * Note: For checks done based on the file's Landlock allowed access, we
	 * enforce them independently of whether the current thread is in a
	 * Landlock domain, so that open files passed between independent
	 * processes retain their behaviour.
	 */
	if (landlock_file(file)->allowed_access & LANDLOCK_ACCESS_FS_TRUNCATE)
		return 0;

	landlock_log_denial(landlock_cred(file->f_cred), &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit = {
			.type = LSM_AUDIT_DATA_FILE,
			.u.file = file,
		},
		.all_existing_optional_access = _LANDLOCK_ACCESS_FS_OPTIONAL,
		.access = LANDLOCK_ACCESS_FS_TRUNCATE,
#ifdef CONFIG_AUDIT
		.deny_masks = landlock_file(file)->deny_masks,
#endif /* CONFIG_AUDIT */
	});
	return -EACCES;
}

static int hook_file_ioctl_common(const struct file *const file,
				  const unsigned int cmd, const bool is_compat)
{
	access_mask_t allowed_access = landlock_file(file)->allowed_access;

	/*
	 * It is the access rights at the time of opening the file which
	 * determine whether IOCTL can be used on the opened file later.
	 *
	 * The access right is attached to the opened file in hook_file_open().
	 */
	if (allowed_access & LANDLOCK_ACCESS_FS_IOCTL_DEV)
		return 0;

	if (!is_device(file))
		return 0;

	if (unlikely(is_compat) ? is_masked_device_ioctl_compat(cmd) :
				  is_masked_device_ioctl(cmd))
		return 0;

	landlock_log_denial(landlock_cred(file->f_cred), &(struct landlock_request) {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit = {
			.type = LSM_AUDIT_DATA_IOCTL_OP,
			.u.op = &(struct lsm_ioctlop_audit) {
				.path = file->f_path,
				.cmd = cmd,
			},
		},
		.all_existing_optional_access = _LANDLOCK_ACCESS_FS_OPTIONAL,
		.access = LANDLOCK_ACCESS_FS_IOCTL_DEV,
#ifdef CONFIG_AUDIT
		.deny_masks = landlock_file(file)->deny_masks,
#endif /* CONFIG_AUDIT */
	});
	return -EACCES;
}

static int hook_file_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	return hook_file_ioctl_common(file, cmd, false);
}

static int hook_file_ioctl_compat(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	return hook_file_ioctl_common(file, cmd, true);
}

/*
 * Always allow sending signals between threads of the same process.  This
 * ensures consistency with hook_task_kill().
 */
static bool control_current_fowner(struct fown_struct *const fown)
{
	struct task_struct *p;

	/*
	 * Lock already held by __f_setown(), see commit 26f204380a3c ("fs: Fix
	 * file_set_fowner LSM hook inconsistencies").
	 */
	lockdep_assert_held(&fown->lock);

	/*
	 * Some callers (e.g. fcntl_dirnotify) may not be in an RCU read-side
	 * critical section.
	 */
	guard(rcu)();
	p = pid_task(fown->pid, fown->pid_type);
	if (!p)
		return true;

	return !same_thread_group(p, current);
}

static void hook_file_set_fowner(struct file *file)
{
	struct landlock_ruleset *prev_dom;
	struct landlock_cred_security fown_subject = {};
	size_t fown_layer = 0;

	if (control_current_fowner(file_f_owner(file))) {
		static const struct access_masks signal_scope = {
			.scope = LANDLOCK_SCOPE_SIGNAL,
		};
		const struct landlock_cred_security *new_subject =
			landlock_get_applicable_subject(
				current_cred(), signal_scope, &fown_layer);
		if (new_subject) {
			landlock_get_ruleset(new_subject->domain);
			fown_subject = *new_subject;
		}
	}

	prev_dom = landlock_file(file)->fown_subject.domain;
	landlock_file(file)->fown_subject = fown_subject;
#ifdef CONFIG_AUDIT
	landlock_file(file)->fown_layer = fown_layer;
#endif /* CONFIG_AUDIT*/

	/* May be called in an RCU read-side critical section. */
	landlock_put_ruleset_deferred(prev_dom);
}

static void hook_file_free_security(struct file *file)
{
	landlock_put_ruleset_deferred(landlock_file(file)->fown_subject.domain);
}

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_free_security_rcu, hook_inode_free_security_rcu),

	LSM_HOOK_INIT(sb_delete, hook_sb_delete),
	LSM_HOOK_INIT(sb_mount, hook_sb_mount),
	LSM_HOOK_INIT(move_mount, hook_move_mount),
	LSM_HOOK_INIT(sb_umount, hook_sb_umount),
	LSM_HOOK_INIT(sb_remount, hook_sb_remount),
	LSM_HOOK_INIT(sb_pivotroot, hook_sb_pivotroot),

	LSM_HOOK_INIT(path_link, hook_path_link),
	LSM_HOOK_INIT(path_rename, hook_path_rename),
	LSM_HOOK_INIT(path_mkdir, hook_path_mkdir),
	LSM_HOOK_INIT(path_mknod, hook_path_mknod),
	LSM_HOOK_INIT(path_symlink, hook_path_symlink),
	LSM_HOOK_INIT(path_unlink, hook_path_unlink),
	LSM_HOOK_INIT(path_rmdir, hook_path_rmdir),
	LSM_HOOK_INIT(path_truncate, hook_path_truncate),
	LSM_HOOK_INIT(unix_find, hook_unix_find),

	LSM_HOOK_INIT(file_alloc_security, hook_file_alloc_security),
	LSM_HOOK_INIT(file_open, hook_file_open),
	LSM_HOOK_INIT(file_truncate, hook_file_truncate),
	LSM_HOOK_INIT(file_ioctl, hook_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, hook_file_ioctl_compat),
	LSM_HOOK_INIT(file_set_fowner, hook_file_set_fowner),
	LSM_HOOK_INIT(file_free_security, hook_file_free_security),
};

__init void landlock_add_fs_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

/* clang-format off */
static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_may_refer_layer),
	{}
};
/* clang-format on */

static struct kunit_suite test_suite = {
	.name = "landlock_fs",
	.test_cases = test_cases,
};

kunit_test_suite(test_suite);

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */
