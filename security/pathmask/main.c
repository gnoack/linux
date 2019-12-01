/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/lsm_hooks.h>
#include <linux/namei.h>
#include <linux/pathmask.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "include/types.h"

struct lsm_blob_sizes pm_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct pathmask_policy),
};

static inline struct pathmask_policy *pm_policy(const struct cred *cred)
{
	return cred->security + pm_blob_sizes.lbs_cred;
}

static inline struct pathmask_policy *current_policy(void)
{
	return pm_policy(current_cred());
}

static int pathmask_policy_copy(struct pathmask_policy *dest, struct pathmask_policy *src)
{
	struct pm_dentry_set *paths;

	if (!src->is_locked_down)
		return 0;

	paths = pm_dup_dentry_set(src->paths);
	if (IS_ERR(paths))
		return PTR_ERR(paths);

	dest->paths = paths;
	dest->is_locked_down = src->is_locked_down;
	return 0;
}

/*
 * Cred hooks
 */
static int hook_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct pathmask_policy *old_policy = pm_policy(old);
	struct pathmask_policy *new_policy = pm_policy(new);

	return pathmask_policy_copy(new_policy, old_policy);
}

static void hook_cred_free(struct cred *cred) {
	pm_free_dentry_set(pm_policy(cred)->paths);
}

/* ------------ */

/* Confine the current task to a given list of paths that it can subsequently access. */
static int confine_path_policy(size_t count, struct dentry **dentries)
{
	struct pathmask_policy *policy, *new_policy;
	struct pm_dentry_set *whitelist;

	struct cred *new = prepare_creds();

	policy = current_policy();
	if (policy->is_locked_down) {
		/* TODO: This should ideally just confine the paths *further*,
		 * but for now, giving an error is an OK option. */
		abort_creds(new);
		return -EACCES;
	}

	whitelist = pm_make_dentry_set(count, dentries);
	if (IS_ERR(whitelist)) {
		abort_creds(new);
		return PTR_ERR(whitelist);
	}

	/* Swizzle out. */
	new_policy = pm_policy(new);
	new_policy->paths = whitelist;
	new_policy->is_locked_down = true;

	return commit_creds(new);
}

/*
 * Enforcement
 */

static int pm_file_open(struct file *file)
{
	struct pathmask_policy *policy = current_policy();

	if (!policy->is_locked_down)
		return 0;

	if (!pm_is_whitelisted(policy->paths, file_dentry(file)))
		return -EACCES;

	return 0;
}

/* ------------ */

int pathmask_set_path_mask(const char __user* const __user *paths) {
	// TODO: Remove the pr_info calls before commit.
	const char __user *user_path;
	struct path path;
	int rc;
	size_t size, capacity;
	struct dentry **dentries;

	// TODO(gnoack): Make this grow rather than returning -E2BIG.
	size = 0;
	capacity = 128;
	dentries = kmalloc_array(capacity, sizeof(struct dentry*), GFP_KERNEL);

	while (size < capacity) {
		if (get_user(user_path, paths++)) {
			rc = -EINVAL;
			goto out;
		}

		if (!user_path)
			break;  /* reached null pointer */

		// XXX: Use path_init and friends?
		rc = user_path_at_empty(AT_FDCWD, user_path, LOOKUP_FOLLOW, &path, NULL);
		if (rc) {
			goto out;
		}

		pr_debug("LSM: path[%zu] = \"%pd\"", size, path.dentry);
		dentries[size++] = path.dentry;
	};

	if (size >= capacity) {
		rc = -E2BIG;
		goto out;
	}

	pr_debug("LSM: confining %d", current->pid);
	rc = confine_path_policy(size, dentries);

out:
	kfree(dentries);
	return rc;
}

/* ------------ */

static struct security_hook_list pm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_open, pm_file_open),
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_free, hook_cred_free),
	/* TODO(gnoack): Does cred_transfer need an implementation too? */
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
