/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel API for restricting processes with the pathmask LSM.
 *
 * These APIs will return an error if the LSM is not available.
 */


#ifdef CONFIG_SECURITY_PATHMASK
extern int pathmask_set_path_mask(const char __user* const __user* paths);

#else // !CONFIG_SECURITY_PATHMASK
static inline int pathmask_set_path_mask(const char __user* const __user* paths) {
	return -EINVAL;
}
#endif // !CONFIG_SECURITY_PATHMASK
