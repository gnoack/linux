// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock scope benchmark
 *
 * Measures the cost of Landlock's signal-scope check when the process is
 * restricted by one or more stacked LANDLOCK_SCOPE_SIGNAL domains.  The
 * benchmark repeatedly sends signal 0 to its parent.  Because the parent
 * lives outside the newly created scope(s), each call walks the full domain
 * stack and is denied with EPERM.
 *
 * Copyright © 2026 Google LLC
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "wrappers.h"

static void usage(const char *const argv0)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS]\n", argv0);
	printf("\n");
	printf("  Benchmark Landlock scoped-signal checks\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h	help\n");
	printf("  -L	run a no-Landlock baseline scenario\n");
	printf("  -l L	run one scenario per entry in comma-separated layer list L\n");
	printf("  -n N	set number of benchmark iterations to N\n");
	printf("\n");
	printf("  Without -L or -l, the default sweep runs a baseline plus 1, 2, 4, 8 layers.\n");
}

static void enforce_scoped_domain(void)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.scoped = LANDLOCK_SCOPE_SIGNAL,
	};
	int ruleset_fd;

	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr), 0U);
	if (ruleset_fd < 0)
		err(1, "landlock_create_ruleset");

	if (landlock_restrict_self(ruleset_fd, 0) < 0)
		err(1, "landlock_restrict_self");
	close(ruleset_fd);
}

static void run_scenario(size_t num_iterations, size_t num_layers,
			 const bool use_landlock)
{
	struct tms start_time, end_time;
	pid_t target, pid;
	int status, abi;

	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid > 0) {
		if (waitpid(pid, &status, 0) < 0)
			err(1, "waitpid");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			errx(1, "scenario failed");
		return;
	}

	target = getppid();
	if (target <= 1)
		errx(1, "parent PID is %d, cannot benchmark scope check", target);

	printf("*** Benchmark ***\n");
	printf("%zu iterations, ", num_iterations);
	if (use_landlock)
		printf("%zu Landlock domain(s)\n", num_layers);
	else
		printf("without Landlock\n");

	if (use_landlock) {
		abi = landlock_create_ruleset(NULL, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 6)
			err(1, "Landlock ABI too low: got %d, wanted 6+", abi);

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
			err(1, "prctl");

		for (size_t layer = 0; layer < num_layers; layer++)
			enforce_scoped_domain();
	}

	if (times(&start_time) == -1)
		err(1, "times");

	for (size_t i = 0; i < num_iterations; i++) {
		int ret = kill(target, 0);

		if (use_landlock) {
			if (ret == 0)
				errx(1, "kill succeeded, expected EPERM");
			if (errno != EPERM)
				err(1, "kill expected EPERM, but got");
		}
	}

	if (times(&end_time) == -1)
		err(1, "times");

	printf("*** Benchmark concluded ***\n");
	printf("System: %ld clocks\n",
	       end_time.tms_stime - start_time.tms_stime);
	printf("User  : %ld clocks\n",
	       end_time.tms_utime - start_time.tms_utime);
	printf("Clocks per second: %ld\n", CLOCKS_PER_SEC);

	_exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	size_t num_iterations = 100000;
	const char *layers_arg = NULL;
	bool baseline = false;
	int c;

	setbuf(stdout, NULL);
	while ((c = getopt(argc, argv, "hLl:n:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'L':
			baseline = true;
			break;
		case 'l':
			layers_arg = optarg;
			break;
		case 'n':
			num_iterations = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (!layers_arg && !baseline) {
		baseline = true;
		layers_arg = "1,2,4,8";
	}

	if (baseline)
		run_scenario(num_iterations, 0, false);

	if (layers_arg) {
		char *buf = strdup(layers_arg);
		char *save = NULL, *tok;

		if (!buf)
			err(1, "strdup");
		for (tok = strtok_r(buf, ",", &save); tok;
		     tok = strtok_r(NULL, ",", &save)) {
			size_t layers = atoi(tok);

			if (layers < 1)
				errx(1, "-l entries must be >= 1");
			run_scenario(num_iterations, layers, true);
		}
		free(buf);
	}

	return EXIT_SUCCESS;
}
