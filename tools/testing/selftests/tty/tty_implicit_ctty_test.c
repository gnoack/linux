// SPDX-License-Identifier: GPL-2.0
/*
 * TTY Tests - implicit controlling terminal acquisition on open()
 *
 * A session leader without a controlling terminal acquires one when it opens
 * a terminal for reading without O_NOCTTY, unless the
 * dev.tty.legacy_implicit_ctty sysctl is 0.  TIOCSCTTY works in either case.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define SYSCTL_PATH "/proc/sys/dev/tty/legacy_implicit_ctty"

static int read_sysctl(void)
{
	FILE *fp;
	int value;

	fp = fopen(SYSCTL_PATH, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%d", &value) != 1)
		value = -1;
	fclose(fp);
	return value;
}

static bool write_sysctl(int value)
{
	FILE *fp;
	bool ok;

	fp = fopen(SYSCTL_PATH, "w");
	if (!fp)
		return false;
	ok = fprintf(fp, "%d\n", value) > 0;
	return fclose(fp) == 0 && ok;
}

FIXTURE(implicit_ctty)
{
	int original_setting;
	int pty_master_fd;
	char pty_slave_name[64];
};

FIXTURE_VARIANT(implicit_ctty)
{
	const int legacy_implicit_ctty;
	const int open_flags;
	const bool use_tiocsctty;
	const bool expect_ctty;
};

FIXTURE_VARIANT_ADD(implicit_ctty, legacy_open)
{
	.legacy_implicit_ctty = 1,
	.open_flags = O_RDWR,
	.expect_ctty = true,
};

FIXTURE_VARIANT_ADD(implicit_ctty, legacy_open_noctty)
{
	.legacy_implicit_ctty = 1,
	.open_flags = O_RDWR | O_NOCTTY,
	.expect_ctty = false,
};

/* Since Linux 4.3, read access is required to acquire a ctty on open(). */
FIXTURE_VARIANT_ADD(implicit_ctty, legacy_open_wronly)
{
	.legacy_implicit_ctty = 1,
	.open_flags = O_WRONLY,
	.expect_ctty = false,
};

FIXTURE_VARIANT_ADD(implicit_ctty, legacy_tiocsctty)
{
	.legacy_implicit_ctty = 1,
	.open_flags = O_RDWR | O_NOCTTY,
	.use_tiocsctty = true,
	.expect_ctty = true,
};

FIXTURE_VARIANT_ADD(implicit_ctty, strict_open)
{
	.legacy_implicit_ctty = 0,
	.open_flags = O_RDWR,
	.expect_ctty = false,
};

FIXTURE_VARIANT_ADD(implicit_ctty, strict_tiocsctty)
{
	.legacy_implicit_ctty = 0,
	.open_flags = O_RDWR,
	.use_tiocsctty = true,
	.expect_ctty = true,
};

FIXTURE_SETUP(implicit_ctty)
{
	self->pty_master_fd = -1;
	self->original_setting = read_sysctl();
	if (self->original_setting < 0)
		SKIP(return, "%s not available", SYSCTL_PATH);
	if (!write_sysctl(variant->legacy_implicit_ctty))
		SKIP(return, "cannot write %s (not root?)", SYSCTL_PATH);

	self->pty_master_fd = posix_openpt(O_RDWR | O_NOCTTY);
	ASSERT_LE(0, self->pty_master_fd);
	ASSERT_EQ(0, grantpt(self->pty_master_fd));
	ASSERT_EQ(0, unlockpt(self->pty_master_fd));
	ASSERT_EQ(0, ptsname_r(self->pty_master_fd, self->pty_slave_name,
			       sizeof(self->pty_slave_name)));
}

FIXTURE_TEARDOWN(implicit_ctty)
{
	if (self->pty_master_fd >= 0)
		close(self->pty_master_fd);
	if (self->original_setting >= 0)
		write_sysctl(self->original_setting);
}

/*
 * Child exit codes: 0 = has a ctty, 1 = has no ctty, 2 = unexpected error.
 */
static int child_open_slave(const char *name, int flags, bool use_tiocsctty)
{
	int fd, tty_fd;

	if (setsid() < 0)
		return 2;

	fd = open(name, flags);
	if (fd < 0)
		return 2;
	if (use_tiocsctty && ioctl(fd, TIOCSCTTY, 0) < 0)
		return 2;

	/* /dev/tty can only be opened with a controlling terminal. */
	tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY);
	if (tty_fd >= 0)
		return 0;
	return errno == ENXIO ? 1 : 2;
}

TEST_F(implicit_ctty, open_slave)
{
	int status;
	pid_t pid;

	pid = fork();
	ASSERT_LE(0, pid);
	if (pid == 0)
		_exit(child_open_slave(self->pty_slave_name,
				       variant->open_flags,
				       variant->use_tiocsctty));

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_NE(2, WEXITSTATUS(status));
	EXPECT_EQ(variant->expect_ctty ? 0 : 1, WEXITSTATUS(status));
}

TEST_HARNESS_MAIN
