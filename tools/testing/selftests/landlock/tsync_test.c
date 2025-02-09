// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Enforcing the same restrictions across multiple threads
 *
 * Copyright © 2025 Günther Noack <gnoack3000@gmail.com>
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/prctl.h>
#include <linux/landlock.h>

#include "common.h"

/* create_ruleset - Create a simple ruleset FD common to all tests */
static int create_ruleset(struct __test_metadata *const _metadata)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = (LANDLOCK_ACCESS_FS_WRITE_FILE |
				      LANDLOCK_ACCESS_FS_TRUNCATE),
	};
	const int ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

	ASSERT_LE(0, ruleset_fd);
	return ruleset_fd;
}

TEST(single_threaded_success)
{
	const int ruleset_fd = create_ruleset(_metadata);

	disable_caps(_metadata);

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_restrict_self(ruleset_fd,
					    LANDLOCK_RESTRICT_SELF_TSYNC));

	ASSERT_EQ(0, close(ruleset_fd));
}

void *idle(void *data)
{
	while (true)
		sleep(1);
}

TEST(multi_threaded_success)
{
	pthread_t t1, t2;
	const int ruleset_fd = create_ruleset(_metadata);

	disable_caps(_metadata);

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	ASSERT_EQ(0, pthread_create(&t1, NULL, idle, NULL));
	ASSERT_EQ(0, pthread_create(&t2, NULL, idle, NULL));

	EXPECT_EQ(0, landlock_restrict_self(ruleset_fd,
					    LANDLOCK_RESTRICT_SELF_TSYNC));

	ASSERT_EQ(0, pthread_cancel(t1));
	ASSERT_EQ(0, pthread_cancel(t2));
	ASSERT_EQ(0, pthread_join(t1, NULL));
	ASSERT_EQ(0, pthread_join(t2, NULL));
	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(multi_threaded_failure)
{
	pthread_t t1;
	const int ruleset_fd = create_ruleset(_metadata);

	disable_caps(_metadata);

	ASSERT_EQ(0, pthread_create(&t1, NULL, idle, NULL));

	/*
	 * landlock_restrict_self is expected to fail, because the other thread
	 * has neither the NO_NEW_PRIVS flag nor CAP_SYS_ADMIN, and thus, it may
	 * not enforce the Landlock ruleset.
	 */
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	EXPECT_EQ(-1, landlock_restrict_self(ruleset_fd,
					     LANDLOCK_RESTRICT_SELF_TSYNC));
	EXPECT_EQ(errno, EPERM);

	ASSERT_EQ(0, pthread_cancel(t1));
	ASSERT_EQ(0, pthread_join(t1, NULL));
	ASSERT_EQ(0, close(ruleset_fd));
}

TEST_HARNESS_MAIN
