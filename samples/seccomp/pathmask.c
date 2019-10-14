// SPDX-License-Identifier: GPL-2.0
/*
 * Path filtering with seccomp pathmask.
 */

#include <err.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* TODO(gnoack): Why doesn't it pick up the value from linux/include/uapi/linux/seccomp.h? */
#define SECCOMP_SET_PATH_MASK 4

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, operation, flags, args);
}

int main(int argc, char **argv)
{
	unsigned int flags = 0;
	unsigned int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--")) {
			argv[i] = NULL;  /* cut */
			break;
		}
	}

	/* Expected -- but didn't find it. */
	if (i == argc) {
		errx(1, "Usage: ./pathmask path1... -- file1...");
	}
	i++;

	/* the argument is a NULL-terminated array of char* */
	if (seccomp(SECCOMP_SET_PATH_MASK, flags, argv) < 0) {
		err(1, "seccomp");
	}

	for (; i < argc; i++) {
		const char *arg = argv[i];
		int fd = open(arg, O_RDONLY);
		if (fd < 0) {
			err(1, "open(%s)", arg);
		}
		if (close(fd) < 0) {
			err(1, "close(fd)");
		}
	}
}
