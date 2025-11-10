/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Cross-thread ruleset enforcement
 *
 * Copyright 2025 Google LLC
 */

int landlock_restrict_sibling_threads(const struct cred *old_cred,
				      const struct cred *new_cred);
