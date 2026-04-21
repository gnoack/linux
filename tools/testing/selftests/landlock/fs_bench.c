// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock filesystem benchmark
 *
 * This program benchmarks the time required for file access checks.  We use a
 * large number (-d flag) of nested directories where each directory inode has
 * an associated Landlock rule, and we repeatedly (-n flag) exercise a file
 * access for which Landlock has to walk the path all the way up to the root.
 *
 * With an increasing number of nested subdirectories, Landlock's portion of the
 * overall system call time increases, which makes the effects of Landlock
 * refactorings more measurable.
 *
 * The -l flag controls the number of stacked Landlock domains, so that the
 * cost of nested domains can be measured.
 *
 * This benchmark does *not* measure the building of the Landlock ruleset.  The
 * time required to add all these rules is not large enough to be easily
 * measurable.  A separate benchmark tool would be better to test that, and that
 * tool could then also use a simpler file system layout.
 *
 * Copyright © 2026 Google LLC
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

#include "wrappers.h"

static const char *const PATH = "d"; /* nested directory name */

static void usage(const char *const argv0)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS]\n", argv0);
	printf("\n");
	printf("  Benchmark expensive Landlock checks for D nested dirs\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h	help\n");
	printf("  -L	disable Landlock (as a baseline)\n");
	printf("  -d D	set directory depth to D\n");
	printf("  -l L	set number of stacked Landlock domains to L\n");
	printf("  -n N	set number of benchmark iterations to N\n");
}

/* Create a chain of depth nested directories and return the FD to the deepest. */
static int make_directory_tree(size_t depth)
{
	int curr, prev;

	curr = open(".", O_PATH);
	if (curr < 0)
		err(1, "open(.)");

	while (depth--) {
		if (mkdirat(curr, PATH, 0700) < 0)
			err(1, "mkdirat(%s)", PATH);

		prev = curr;
		curr = openat(curr, PATH, O_PATH);
		if (curr < 0)
			err(1, "openat(%s)", PATH);

		close(prev);
	}
	return curr;
}

/* Reopen the deepest directory of the nested chain. */
static int open_deepest(size_t depth)
{
	int curr, prev;

	curr = open(".", O_PATH);
	if (curr < 0)
		err(1, "open(.)");

	while (depth--) {
		prev = curr;
		curr = openat(curr, PATH, O_PATH);
		if (curr < 0)
			err(1, "openat(%s)", PATH);
		close(prev);
	}
	return curr;
}

/*
 * Build and enforce one Landlock domain that covers every directory in the
 * chain of the given depth.
 */
static void enforce_one_domain(size_t depth)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_IOCTL_DEV |
				     LANDLOCK_ACCESS_FS_WRITE_FILE |
				     LANDLOCK_ACCESS_FS_MAKE_REG,
	};
	int ruleset_fd, dir, prev;

	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr), 0U);
	if (ruleset_fd < 0)
		err(1, "landlock_create_ruleset");

	dir = open(".", O_PATH);
	if (dir < 0)
		err(1, "open(.)");

	for (size_t i = 0; i < depth; i++) {
		struct landlock_path_beneath_attr path_attr = {
			.allowed_access = LANDLOCK_ACCESS_FS_IOCTL_DEV,
			.parent_fd = dir,
		};
		if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				      &path_attr, 0) < 0)
			err(1, "landlock_add_rule");

		prev = dir;
		dir = openat(dir, PATH, O_PATH);
		if (dir < 0)
			err(1, "openat(%s)", PATH);
		close(prev);
	}
	close(dir);

	if (landlock_restrict_self(ruleset_fd, 0) < 0)
		err(1, "landlock_restrict_self");
	close(ruleset_fd);
}

/*
 * Build a deep directory, enforce num_layers Landlock domains on top of it,
 * and return the FD to the deepest dir.  On any failure, exit the process
 * with an error.
 */
static int build_directory(size_t depth, size_t num_layers,
			   const bool use_landlock)
{
	int abi;

	if (use_landlock) {
		abi = landlock_create_ruleset(NULL, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 7)
			err(1, "Landlock ABI too low: got %d, wanted 7+", abi);
	}

	close(make_directory_tree(depth));

	if (use_landlock) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
			err(1, "prctl");

		for (size_t layer = 0; layer < num_layers; layer++)
			enforce_one_domain(depth);
	}

	return open_deepest(depth);
}

static void remove_recursively(const size_t depth)
{
	int fd = openat(AT_FDCWD, ".", O_PATH);

	if (fd < 0)
		err(1, "openat(.)");

	for (size_t i = 0; i < depth - 1; i++) {
		int oldfd = fd;

		fd = openat(fd, PATH, O_PATH);
		if (fd < 0)
			err(1, "openat(%s)", PATH);
		close(oldfd);
	}

	for (size_t i = 0; i < depth; i++) {
		if (unlinkat(fd, PATH, AT_REMOVEDIR) < 0)
			err(1, "unlinkat(%s)", PATH);
		int newfd = openat(fd, "..", O_PATH);

		close(fd);
		fd = newfd;
	}
	close(fd);
}

int main(int argc, char *argv[])
{
	bool use_landlock = true;
	size_t num_iterations = 100000;
	size_t num_subdirs = 10000;
	size_t num_layers = 1;
	int c, curr, fd;
	struct tms start_time, end_time;

	setbuf(stdout, NULL);
	while ((c = getopt(argc, argv, "hLd:l:n:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'L':
			use_landlock = false;
			break;
		case 'd':
			num_subdirs = atoi(optarg);
			break;
		case 'l':
			num_layers = atoi(optarg);
			break;
		case 'n':
			num_iterations = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (use_landlock && num_layers < 1)
		errx(1, "-l must be at least 1 when Landlock is enabled");

	printf("*** Benchmark ***\n");
	printf("%zu dirs, %zu iterations, ", num_subdirs, num_iterations);
	if (use_landlock)
		printf("%zu Landlock domain(s)\n", num_layers);
	else
		printf("without Landlock\n");

	if (times(&start_time) == -1)
		err(1, "times");

	curr = build_directory(num_subdirs, num_layers, use_landlock);

	for (int i = 0; i < num_iterations; i++) {
		fd = openat(curr, "file.txt", O_CREAT | O_TRUNC | O_WRONLY,
			    0600);
		if (use_landlock) {
			if (fd == 0)
				errx(1, "openat succeeded, expected EACCES");
			if (errno != EACCES)
				err(1, "openat expected EACCES, but got");
		}
		if (fd != -1)
			close(fd);
	}

	if (times(&end_time) == -1)
		err(1, "times");

	printf("*** Benchmark concluded ***\n");
	printf("System: %ld clocks\n",
	       end_time.tms_stime - start_time.tms_stime);
	printf("User  : %ld clocks\n",
	       end_time.tms_utime - start_time.tms_utime);
	printf("Clocks per second: %ld\n", CLOCKS_PER_SEC);

	close(curr);

	remove_recursively(num_subdirs);
}
