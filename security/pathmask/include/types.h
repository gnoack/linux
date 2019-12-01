/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PM_TYPES_H
#define __PM_TYPES_H

#include <linux/dcache.h>

// A set of dentries.
//
// TODO: This data structure should provide fast implementations of:
//
//  - Checking whether a dentry is itself in that set.
//  - Adding a dentry to a set.
//
// In the future this should maybe be a simple hash set.
struct pm_dentry_set {
	// Impleented as an array of dentry pointers of the given size.
	size_t size;
	struct dentry **dentries;
};

/* Create a set of dentries of the given size with the given dentries. */
extern struct pm_dentry_set *pm_make_dentry_set(size_t size, struct dentry **dentries);
extern bool pm_dentry_set_contains(struct pm_dentry_set *set, struct dentry *dentry);
extern void pm_free_dentry_set(struct pm_dentry_set *set);
extern struct pm_dentry_set *pm_dup_dentry_set(struct pm_dentry_set *set);

/* Checks whether the dentry or any of its parent dentries are in the whitelist set. */
extern bool pm_is_whitelisted(struct pm_dentry_set *whitelist, struct dentry *dentry);

struct pathmask_policy {
	bool is_locked_down;
	/* TODO(gnoack): Split into read and write whitelists. */
	struct pm_dentry_set *paths;
};

#endif /* __PM_TYPES_H */
