// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock network benchmark
 *
 * Measures the cost of Landlock's TCP connect() checks when the process is
 * restricted by one or more stacked Landlock domains.  Each layer handles
 * LANDLOCK_ACCESS_NET_CONNECT_TCP without any allow rules, so every connect()
 * call walks the full domain stack and is denied with EACCES.
 *
 * Copyright © 2026 Google LLC
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "wrappers.h"

static void usage(const char *const argv0)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS]\n", argv0);
	printf("\n");
	printf("  Benchmark Landlock TCP connect() checks\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h	help\n");
	printf("  -L	disable Landlock (as a baseline)\n");
	printf("  -l L	set number of stacked Landlock domains to L\n");
	printf("  -n N	set number of benchmark iterations to N\n");
}

static void enforce_net_domain(void)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP |
				      LANDLOCK_ACCESS_NET_BIND_TCP,
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

int main(int argc, char *argv[])
{
	bool use_landlock = true;
	size_t num_iterations = 100000;
	size_t num_layers = 1;
	int c, abi;
	struct tms start_time, end_time;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	setbuf(stdout, NULL);
	while ((c = getopt(argc, argv, "hLl:n:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'L':
			use_landlock = false;
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
	printf("%zu iterations, ", num_iterations);
	if (use_landlock)
		printf("%zu Landlock domain(s)\n", num_layers);
	else
		printf("without Landlock\n");

	if (use_landlock) {
		abi = landlock_create_ruleset(NULL, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 4)
			err(1, "Landlock ABI too low: got %d, wanted 4+", abi);

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
			err(1, "prctl");

		for (size_t layer = 0; layer < num_layers; layer++)
			enforce_net_domain();
	}

	if (times(&start_time) == -1)
		err(1, "times");

	for (size_t i = 0; i < num_iterations; i++) {
		int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

		if (sock < 0)
			err(1, "socket");

		int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

		if (use_landlock) {
			if (ret == 0)
				errx(1, "connect succeeded, expected EACCES");
			if (errno != EACCES)
				err(1, "connect expected EACCES, but got");
		}
		close(sock);
	}

	if (times(&end_time) == -1)
		err(1, "times");

	printf("*** Benchmark concluded ***\n");
	printf("System: %ld clocks\n",
	       end_time.tms_stime - start_time.tms_stime);
	printf("User  : %ld clocks\n",
	       end_time.tms_utime - start_time.tms_utime);
	printf("Clocks per second: %ld\n", CLOCKS_PER_SEC);

	return 0;
}
