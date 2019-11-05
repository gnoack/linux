/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/lsm_hooks.h>
#include <linux/namei.h>
#include <linux/pathmask.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "include/types.h"

struct lsm_blob_sizes pm_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct pm_task_ctx),
};

static inline struct pm_task_ctx *task_ctx(struct task_struct *task)
{
	return task->security + pm_blob_sizes.lbs_task;
}

static int pm_task_ctx_copy(struct pm_task_ctx *dest, struct pm_task_ctx *src)
{
	struct pm_dentry_set *ctx_paths;

	if (!src->is_locked_down)
		return 0;

	dest->is_locked_down = src->is_locked_down;

	ctx_paths = pm_dup_dentry_set(src->ctx_paths);
	if (IS_ERR(ctx_paths))
		return PTR_ERR(ctx_paths);


	dest->ctx_paths = ctx_paths;
	return 0;
}

/* ------------ */

/* Confine a task to a given list of paths that it can subsequently access. */
static int pm_confine_path(struct task_struct *task, size_t count, struct dentry **dentries)
{
	struct pm_task_ctx *ctx;
	struct pm_dentry_set *whitelist;

	ctx = task_ctx(task);
	if (ctx->ctx_paths) {
		/* TODO: This should ideally just confine the paths *further*,
		 * but for now, giving an error is an OK option. */
		return -EACCES;
	}

	whitelist = pm_make_dentry_set(count, dentries);
	if (IS_ERR(whitelist))
		return PTR_ERR(whitelist);

	/* Swizzle out. */
	ctx->ctx_paths = whitelist;
	ctx->is_locked_down = true;
	return 0;
}

/* ------------ */

static int pm_file_open(struct file *file)
{
	if (!pm_is_whitelisted(task_ctx(current)->ctx_paths, file_dentry(file))) {
		return -EACCES;
	}
	return 0;
}

static int pm_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	pr_debug("LSM: task_ctx_copy when forking %d", current->pid);

	return pm_task_ctx_copy(task_ctx(task), task_ctx(current));
}

static void pm_task_free(struct task_struct *task)
{
	pm_free_dentry_set(task_ctx(task)->ctx_paths);
}

/* ------------ */

int pathmask_set_path_mask(const char __user* const __user *paths) {
	// TODO: Remove the pr_info calls before commit.
	const char __user *user_path;
	struct path path;
	int rc;
	size_t size, capacity;
	struct dentry **dentries;

	// TODO(gnoack): Maybe this should grow rather than returning -E2BIG.
	size = 0;
	capacity = 128;
	dentries = kmalloc_array(capacity, sizeof(struct dentry*), GFP_KERNEL);

	while (size < capacity) {
		if (get_user(user_path, paths++)) {
			pr_debug("get_user failed");
			rc = -EINVAL;
			goto out;
		}

		if (!user_path)
			break;  /* reached null pointer */

		// XXX: Use path_init and friends?
		rc = user_path_at_empty(AT_FDCWD, user_path, LOOKUP_FOLLOW, &path, NULL);
		if (rc) {
			pr_debug("user_path_at_empty failed");
			goto out;
		}

		pr_debug("LSM: path[%zu] = \"%pd\"", size, path.dentry);
		dentries[size++] = path.dentry;
	};

	if (size >= capacity) {
		pr_debug("over capacity");
		rc = -E2BIG;
		goto out;
	}

	pr_debug("LSM: confining %d", current->pid);
	rc = pm_confine_path(current, size, dentries);

out:
	kfree(dentries);
	return rc;
}

/* ------------ */

static struct security_hook_list pm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_open, pm_file_open),
	LSM_HOOK_INIT(task_alloc, pm_task_alloc),
	LSM_HOOK_INIT(task_free, pm_task_free),
};

static int __init pm_init(void)
{
	security_add_hooks(pm_hooks, ARRAY_SIZE(pm_hooks), "pathmask");
	pr_info("LSM: pathmasks enabled.");
	return 0;
}

DEFINE_LSM(pathmask) = {
	.name = "pathmask",
	.init = pm_init,
        .blobs = &pm_blob_sizes,
};
