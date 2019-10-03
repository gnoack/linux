/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/dcache.h>
#include <linux/lsm_hooks.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/namei.h>

#include "include/types.h"

struct lsm_blob_sizes pm_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct pm_task_ctx),
};

static inline struct pm_task_ctx *task_ctx(struct task_struct *task)
{
	return task->security + pm_blob_sizes.lbs_task;
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
	return 0;
}

/* ------------ */

static int pm_file_open(struct file *file)
{
	struct dentry *dentry;

	dentry = file_dentry(file);

	/*
	 * TODO: This is a hack; we enforce a sample set of paths
	 * when the user tries to access the file bogus2000.
	 */
	if (!strncmp(dentry->d_name.name, "bogus2000", 9)) {
		struct dentry* dentries[3];
		struct path path;
		int rc;

		rc = kern_path("/bin", LOOKUP_FOLLOW, &path);
		if (rc) {
			pr_info("LSM: Could not look up /bin, rc=%d", rc);
			return 0;
		}
		dentries[0] = path.dentry;

		rc = kern_path("/lib", LOOKUP_FOLLOW, &path);
		if (rc) return 0;
		dentries[1] = path.dentry;

		rc = kern_path("/root", LOOKUP_FOLLOW, &path);
		if (rc) return 0;
		dentries[2] = path.dentry;

		/* Actually lock down the process. */
		rc = pm_confine_path(current, 3, dentries);
		if (rc) {
			pr_info("LSM: Could not confine.");
			return rc;
		}
		pr_info("LSM: Process %d confined to /bin, /lib, /root.", current->pid);
	}

	if (!pm_is_whitelisted(task_ctx(current)->ctx_paths, dentry)) {
		return -EACCES;
	}
	return 0;
}

static void pm_task_free(struct task_struct *task)
{
	pm_free_dentry_set(task_ctx(task)->ctx_paths);
}

/* ------------ */

static struct security_hook_list pm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_open, pm_file_open),
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
