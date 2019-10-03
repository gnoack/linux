/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/dcache.h>
#include <linux/slab.h>

#include "include/types.h"

struct pm_dentry_set *pm_make_dentry_set(size_t size, struct dentry **dentries)
{
	struct pm_dentry_set *set;
	int i;

	set = kmalloc(sizeof(struct pm_dentry_set), GFP_KERNEL);
	if (!set)
		return ERR_PTR(-ENOMEM);

	set->size = size;
	set->dentries = kmalloc_array(size, sizeof(struct dentry*), GFP_KERNEL);
	if (!set->dentries) {
		kfree(set);
		return ERR_PTR(-ENOMEM);
	}

	for (i=0; i<size; i++) {
		set->dentries[i] = dget(dentries[i]);
	}
	return set;
}

bool pm_dentry_set_contains(struct pm_dentry_set *set, struct dentry *dentry)
{
	int i;

	/* The null pointer dentry set is the set of all dentries. */
	if (!set)
		return true;

	for (i=0; i<set->size; i++) {
		if (set->dentries[i] == dentry)
			return true;
	}
	return false;
}

bool pm_is_whitelisted(struct pm_dentry_set *whitelist, struct dentry *dentry)
{
	if (!whitelist)
		return true;

	/* Walk the dentry upwards until you find something from the set */
	while (!IS_ROOT(dentry)) {
		pr_info("LSM: Checking dentry %pd", dentry);
		if (pm_dentry_set_contains(whitelist, dentry)) {
			pr_info("LSM: OK");
			return true;
		}

		dentry = dentry->d_parent;
	}
	pr_info("LSM: fail");
	return false;
}

void pm_free_dentry_set(struct pm_dentry_set *set)
{
	int i;

	if (!set) return;

	for (i=0; i<set->size; i++) {
		dput(set->dentries[i]);
	}
	kfree(set);
}
