#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <paths.h>

#include <sys/pfexec.h>
#include <sys/pfexecvar.h>
#include <sys/stat.h>

/* Error types */
enum exit_status {
	EXIT_OK			= 0,
	EXIT_USAGE		= 1,
	EXIT_INVALID_PATH	= 2,
};

/* Command-line flags */
int	nflag = 0;  	/* -n: Non-interactive/batch mode */
int 	sflag = 0;  	/* -s: Execute a shell, rather than a specific cmd */
int 	uflag = 0;  	/* -u: Assume the privileges of the given user */

int findprog(char *, char *, int, int);

static __dead void
usage(void)
{
	fprintf(stderr,
	    "Usage: pfexec [options] <executable> [args...]\n"
	    "       pfexec [options] -s\n\n");

	fprintf(stderr, "Options:\n"
	    "  -u user       Assume the privileges of the given user "
	    "instead of \"root\"\n"
	    "  -n            Non-interactive/batch mode: no prompts are used\n"
	    "                if prompts are required, will fail\n"
	    "  -s            Execute a shell, rather than a specific command"
	    "\n");

	exit(EXIT_USAGE);
}

int
main(int argc, char *argv[], char *envp[])
{
	char ch, *user;

	while ((ch = getopt(argc, argv, "nsu:")) != -1) {
		switch (ch) {
		case 'n':
			nflag = 1;
			break;
		case 's':
			sflag = 1;
			break;
		case 'u':
			uflag = 1;
			user = optarg;
			break;
		default:
			usage();
		}
	}

	/* Process the set flags */
	struct pfexecve_opts opts;
	opts.pfo_flags = 0;

	if (nflag)
		opts.pfo_flags |= PFEXECVE_NOPROMPT;
	if (uflag) {
		opts.pfo_flags |= PFEXECVE_USER;
		strncpy(opts.pfo_user, user, LOGIN_NAME_MAX);
	}

	argv += optind;
	argc -= optind;

	int error;
	char *file;

	if (sflag) {
		file = getenv("SHELL");

		if (argc > 0)
			usage();
		if (file == NULL) {
			file = "/bin/ksh";
		}
		/* Need to set argv[1] to null to null terminate the list */
		argv[0] = file;
		argv[1] = NULL;
	} else {
		if (argc <= 0) {
			usage();
		}
		file = argv[0];
	}

	/* Find file path if exists (by using path) */
	char *path = getenv("PATH");
	char filepath[PATH_MAX];
	bzero(filepath, PATH_MAX);

	/* Copy the searched filepath into a buffer */
	strncpy(filepath, file, PATH_MAX);

	if ((error = findprog(filepath, path, 0, 0)) != 0) {
		errc(error, error, "findprog");
	}

	extern char **environ;

	if ((error = pfexecvpe(&opts, filepath, argv, envp))
	    < 0) {
		err(error, "pfexecve");
	}

	return error;
}

/* ERROR WE WANT IS ENOENT */
int
findprog(char *prog, char *path, int progmode, int allmatches)
{
	char *p, filename[PATH_MAX];
	int len;
	struct stat sbuf;
	char *pathcpy;

	/* Special case if prog contains '/' */
	if (strchr(prog, '/')) {
		if ((stat(prog, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(prog, X_OK) == 0) {
			return (0);
		} else {
			return (ENOENT);
		}
	}

	if ((path = strdup(path)) == NULL)
		err(1, "strdup");
	pathcpy = path;

	while ((p = strsep(&pathcpy, ":")) != NULL) {
		if (*p == '\0')
			p = ".";

		len = strlen(p);
		while (len > 0 && p[len-1] == '/')
			p[--len] = '\0';	/* strip trailing '/' */

		len = snprintf(filename, sizeof(filename), "%s/%s", p, prog);
		if (len < 0 || len >= sizeof(filename)) {
			free(path);
			return (ENAMETOOLONG);
		}
		if ((stat(filename, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(filename, X_OK) == 0) {
			strncpy(prog, filename, PATH_MAX);
			(void)free(path);
			return (0);
		}
	}
	(void)free(path);

	return (ENOENT);
}