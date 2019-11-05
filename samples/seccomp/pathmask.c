// SPDX-License-Identifier: GPL-2.0
/*
 * Path filtering with seccomp pathmask.
 */

#include <err.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define USAGE								\
	"Usage: %s path1... -- file1...\n"				\
	"  to enforce whitelist path1... and attempt to open file1...\n" \
	"\n"								\
	"Usage: %s path1... --\n"					\
	"  to enforce whitelist path1... and exec /bin/bash\n"		\
	"  e.g. %s /bin/bash /usr/lib /etc /root /usr/bin/ls --\n"

/* TODO(gnoack): Why doesn't it pick up the value from linux/include/uapi/linux/seccomp.h? */
#define SECCOMP_SET_PATH_MASK 4

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, operation, flags, args);
}

int main(int argc, char **argv)
{
	unsigned int flags = 0;
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--")) {
			argv[i] = NULL;  /* cut */
			break;
		}
	}

	/* Expected -- but didn't find it. */
	if (i == argc) {
		errx(1, USAGE, argv[0], argv[0], argv[0]);
	}
	i++;

	/* the argument is a NULL-terminated array of char* */
	if (seccomp(SECCOMP_SET_PATH_MASK, flags, argv) < 0) {
		err(1, "seccomp");
	}

	if (i == argc) {
		puts("Launching a restricted subshell");
		/* If no further arguments, launch a subshell. */
		if (execl("/bin/bash", "bash", NULL) < 0) {
			err(1, "executing /bin/bash");
		}
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
