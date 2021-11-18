/*
 * Copyright 2021, the University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <err.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/un.h>
#include <sys/pfexec.h>
#include <sys/pfexecvar.h>

#include <event.h>

#include "pfexecd.h"

const off_t CONFIG_MAX_SIZE	= 16777216LL;	/* 16 MB */
const size_t BACKLOG		= 8;

/* Variable to check the logging state */
int isLogged = 1;

struct client {
	TAILQ_ENTRY(client)		 c_entry;
	struct sockaddr_storage		 c_raddr;
	int				 c_fd;
	struct event			 c_readable;
	struct pfexec_req		 c_req;
	struct pfexec_resp		 c_resp;
};

static struct event			 pfd_acceptable;
static TAILQ_HEAD(clhead, client)	 pfd_clients;
static char				*pfd_configbuf;

static void	on_lsock_acceptable(int, short, void *);
static void	on_client_readable(int, short, void *);
static int	process_request(const struct pfexec_req *,
    struct pfexec_resp *);
static void	log_request(const struct pfexec_req *,
    const struct pfexec_resp *);

static int parseconfig(FILE *);
static int compare_config(const struct pfexec_req *, struct pfexec_resp *);
void setcred(struct passwd *, struct pfexec_resp *);
void convert_to_path(const char *, char *, char *, const char *);
int cnvrt_to_path(const char *, char *, char *);
int path_from_env(const char [], const struct pfexec_arg [], int);

void __dead
usage(const char *arg0)
{
	fprintf(stderr, "Usage: %s [-f] [-c file]\n", arg0);
	fprintf(stderr, "       %s [-c file] -t\n", arg0);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -f            Foreground operation: do not fork or "
	    "daemonise\n");
	fprintf(stderr, "  -c <file>     Use <file> as configuration file "
	    "instead of /etc/pfexecd.conf\n");
	fprintf(stderr, "  -t            Test configuration file: check "
	    "syntax and exit 0 if ok\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *optstring = "fc:t";
	const char *conf = "/etc/pfexecd.conf";
	int daemon = 1, testmode = 0;
	pid_t kid;
	int c;
	int rc, fd, lsock;
	size_t conflen;
	struct stat stat;
	ssize_t done;
	struct sockaddr_un laddr;

	TAILQ_INIT(&pfd_clients);

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'f':
			daemon = 0;
			break;
		case 't':
			testmode = 1;
			break;
		case 'c':
			conf = optarg;
			break;
		default:
			warnx("invalid argument");
			usage(argv[0]);
		}
	}

	fd = open(conf, O_RDONLY);
	if (fd < 0)
		err(1, "open(%s)", conf);
	rc = fstat(fd, &stat);
	if (rc < 0)
		err(1, "fstat(%s)", conf);
	if ((stat.st_mode & S_IFREG) == 0)
		errx(1, "config file %s is not a regular file", conf);
	if (stat.st_size > CONFIG_MAX_SIZE)
		errx(1, "config file %s is too big to be pfexecd.conf", conf);
	conflen = stat.st_size + 1;
	pfd_configbuf = calloc(1, conflen);
	if (pfd_configbuf == NULL)
		err(1, "malloc");

	for (done = 0; done < stat.st_size;) {
		ssize_t rr;
		rr = read(fd, pfd_configbuf + done, conflen - done);
		if (rr < 0)
			err(1, "read(%s)", conf);
		if (rr == 0)
			break;
		done += rr;
	}
	pfd_configbuf[conflen - 1] = '\0';
	close(fd);

	/*
	 * Open the pfexecd listening socket which the kernel will connect
	 * to. We unlink() any old socket file which exists before calling
	 * bind() (it would be nicer to have a pid file and check it first)
	 */
	if (!testmode) {
		lsock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (lsock < 0)
			err(1, "socket");

		bzero(&laddr, sizeof(laddr));
		laddr.sun_len = sizeof(laddr);
		laddr.sun_family = AF_UNIX;
		strlcpy(laddr.sun_path, PFEXECD_SOCK, sizeof(laddr.sun_path));

		unlink(PFEXECD_SOCK);
		if (bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr)))
			err(1, "bind(%s)", PFEXECD_SOCK);
		if (listen(lsock, BACKLOG))
			err(1, "listen(%s)", PFEXECD_SOCK);
	}

	if (daemon && !testmode) {
		kid = fork();
		if (kid < 0) {
			err(1, "fork");
		} else if (kid > 0) {
			/* The parent process exits immediately. */
			return (0);
		}
		umask(0);
		if (setsid() < 0) {
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			    "setsid failed: %d (%s)", errno, strerror(errno));
			exit(1);
		}
		chdir("/");

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/* Open the file before we drop privileges */
	FILE *configuration = fmemopen(pfd_configbuf, conflen -
	    sizeof(char), "r");
	if (configuration == NULL) {
		errx(1, "error opening as file");
	}

	struct passwd *pfexecd = getpwnam("_pfexecd");
	if (pfexecd == NULL) {
		errx(1, "User _pfexecd could not be found \n");
	}
	if (setuid(pfexecd->pw_uid) != 0) {
		errx(1, "Error changing UID \n");
	}

	unveil("/var/log/secure", "rw");
	unveil("/var/run/pfexecd.sock", "rw");
	unveil("/etc/pwd.db", "r");
	pledge("stdio getpw unix sendfd recvfd ", "");

	if (parseconfig(configuration) != 0)
		errx(1, "error parsing config file %s", conf);


	/* If we're in config test mode and config parsing was ok, exit now. */
	if (testmode)
		return (0);

	/*
	 * Ignore SIGPIPE if we get it from any of our sockets: we'll poll
	 * them for read/hup/err later and figure it out anyway.
	 */
	signal(SIGPIPE, SIG_IGN);

	event_init();
	event_set(&pfd_acceptable, lsock, EV_READ, on_lsock_acceptable, NULL);
	event_add(&pfd_acceptable, NULL);

	event_dispatch();

	free(pfd_configbuf);
	close(lsock);

	return (0);
}

static void
destroy_client(struct client *client)
{
	TAILQ_REMOVE(&pfd_clients, client, c_entry);
	event_del(&client->c_readable);
	close(client->c_fd);
	free(client);
}

static void
on_lsock_acceptable(int lsock, short evt, void *arg)
{
	struct sockaddr_storage raddr;
	socklen_t slen;
	int newfd, rc;
	struct client *client;
	uid_t uid;
	gid_t gid;

	slen = sizeof(raddr);
	newfd = accept(lsock, (struct sockaddr *)&raddr, &slen);

	if (newfd < 0) {
		switch (errno) {
		case ECONNABORTED:
		case ECONNRESET:
			goto out;
		default:
			syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to accept "
			    "connection, aborting: %d (%s)", errno,
			    strerror(errno));
			exit(1);
		}
	}

	/* Check that the process connecting to us is running as "root". */
	rc = getpeereid(newfd, &uid, &gid);
	if (rc != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to retrieve peer "
		    "uid/gid for new connection, closing");
		close(newfd);
		goto out;
	}
	if (uid != 0 || gid != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "rejecting connection "
		    "from non-root user: uid %d, gid %d", uid, gid);
		close(newfd);
		goto out;
	}

	/*
	 * Set the socket's send buffer size now to make sure there's enough
	 * memory for it.
	 */
	slen = sizeof(struct pfexec_resp) + 32;
	rc = setsockopt(newfd, SOL_SOCKET, SO_SNDBUF, &slen, sizeof(slen));
	if (rc < 0) {
		err(rc, "setsockopt");
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to set send buffer "
		    "size for new client, closing");
		close(newfd);
		goto out;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to allocate memory "
		    "for new client, closing");
		close(newfd);
		goto out;
	}

	client->c_fd = newfd;
	bcopy(&raddr, &client->c_raddr, sizeof(raddr));

	TAILQ_INSERT_TAIL(&pfd_clients, client, c_entry);

	event_set(&client->c_readable, newfd, EV_READ, on_client_readable,
	    client);
	event_add(&client->c_readable, NULL);

out:
	event_add(&pfd_acceptable, NULL);
}

static void
on_client_readable(int sock, short evt, void *arg)
{
	struct client *client = (struct client *)arg;
	struct msghdr hdr;
	struct iovec iov;
	ssize_t recvd;
	int rc;

	bzero(&hdr, sizeof(hdr));
	bzero(&iov, sizeof(iov));
	hdr.msg_iovlen = 1;
	hdr.msg_iov = &iov;
	iov.iov_base = &client->c_req;
	iov.iov_len = sizeof(struct pfexec_req);

	recvd = recvmsg(sock, &hdr, MSG_DONTWAIT);
	if (recvd < 0) {
		if (errno == EAGAIN)
			goto out;
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to read request "
		    "from client, closing");
		destroy_client(client);
		return;
	}
	if (recvd == 0) {
		/* EOF: the other end has closed the connection */
		destroy_client(client);
		return;
	}
	if (recvd < sizeof(struct pfexec_req)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "short request from client, "
		    "closing");
		destroy_client(client);
		return;
	}

	bzero(&client->c_resp, sizeof(struct pfexec_resp));
	rc = process_request(&client->c_req, &client->c_resp);
	if (rc != 0) {
		bzero(&client->c_resp, sizeof(struct pfexec_resp));
		client->c_resp.pfr_errno = rc;
	}
	/* Check if command is valid and isLogged is not set */
	if (!(rc == 0 && !isLogged))
		log_request(&client->c_req, &client->c_resp);

	bzero(&hdr, sizeof(hdr));
	bzero(&iov, sizeof(iov));
	hdr.msg_iovlen = 1;
	hdr.msg_iov = &iov;
	iov.iov_base = &client->c_resp;
	iov.iov_len = sizeof(struct pfexec_resp);
	recvd = sendmsg(sock, &hdr, MSG_EOR);
	if (recvd < 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to write to client, "
		    "closing");
		destroy_client(client);
		return;
	}

out:
	event_add(&client->c_readable, NULL);
}

static int
process_request(const struct pfexec_req *req, struct pfexec_resp *resp)
{
	uint i;

	/* Check for correctly formed request. */
	if (req->pfr_ngroups >= NGROUPS_MAX)
		return (EINVAL);
	if (req->pfr_req_flags & ~PFEXECVE_ALL_FLAGS)
		return (EINVAL);
	if (strlen(req->pfr_path) < 1 ||
	    strlen(req->pfr_path) >= PATH_MAX)
		return (EINVAL);
	if (req->pfr_argc >= 1024 || req->pfr_envc >= 1024)
		return (EINVAL);
	if ((req->pfr_req_flags & PFEXECVE_USER) && (
	    strlen(req->pfr_req_user) < 1 ||
	    strlen(req->pfr_req_user) >= LOGIN_NAME_MAX))
		return (EINVAL);

	/*
	 * Validate all the argument and env var references before we try to
	 * use any of them.
	 */
	for (i = 0; i < req->pfr_argc; ++i) {
		const struct pfexec_arg *a = &req->pfr_argp[i];
		if (a->pfa_offset >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_len >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_offset + a->pfa_len >= ARG_MAX)
			return (EINVAL);
	}
	for (i = 0; i < req->pfr_envc; ++i) {
		const struct pfexec_arg *a = &req->pfr_envp[i];
		if (a->pfa_offset >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_len >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_offset + a->pfa_len >= ARG_MAX)
			return (EINVAL);
	}

	return compare_config(req, resp);
}

static void
log_request(const struct pfexec_req *req, const struct pfexec_resp *resp)
{
	const char *requser = (req->pfr_req_flags & PFEXECVE_USER) ?
	    req->pfr_req_user : "root";
	if (resp->pfr_errno == 0) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "uid %d ran command %s as %s (pid %d)",
		    req->pfr_uid, req->pfr_path, requser, req->pfr_pid);
		return;
	}
	if (resp->pfr_errno == EPERM) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "denied escalation for pid %d (%s) as %s, run by uid %d",
		    req->pfr_pid, req->pfr_path, requser, req->pfr_uid);
		return;
	}
	syslog(LOG_AUTHPRIV | LOG_NOTICE,
	    "error processing esclation request from pid %d, run by uid %d: "
	    "%d: %s", req->pfr_pid, req->pfr_uid, resp->pfr_errno,
	    strerror(resp->pfr_errno));
}

static int
parseconfig(FILE *conf)
{
	extern FILE *yyfp;
	extern int yyparse(void);

	yyfp = conf;

	if (!yyfp)
		return EPERM;

	yyparse();
	fclose(yyfp);

	if (parse_errors)
		return (1);

	return (0);
}

static int
compare_config(const struct pfexec_req *req, struct pfexec_resp *resp)
{
	struct passwd *targetpwd, *identpwd, *requestpwd, *rootpwd, *requid;
	struct group *identgrp;

	/* First let's match up the user */
	for (int i = nrules - 1; i >= 0; i--) {

		if (rules[i]->ident == NULL) {
			continue;
		}

		char *group = strchr(rules[i]->ident, ':');

		/* If no leading colon treat as either an id or a name */
		if (group == NULL) {

			uid_t uid;

			/* 0 if not a long */
			if ((uid = strtoul(rules[i]->ident, NULL, 10)) != 0) {

				if ((requid = getpwuid(req->pfr_uid)) == NULL) {
					continue;
				}

				if (uid != requid->pw_uid) {
					continue;
				}

			} else {

				identpwd = getpwnam(rules[i]->ident);
				if (identpwd == NULL) {
					continue;
				}

				uid = identpwd->pw_uid;

				if ((requid = getpwuid(req->pfr_uid)) == NULL) {
					continue;
				}

				if (uid != requid->pw_uid) {
					continue;
				}
			}

		} else {
			gid_t identgid;
			/* Check that req user is in the group */
			requid = getpwuid(req->pfr_uid);
			identgrp = getgrnam(group + sizeof(char));

			if (requid == NULL || identgrp == NULL) {
				continue;
			}

			identgid = identgrp->gr_gid;

			int isInGroup = 0;

			if (requid->pw_gid != identgid) {

				int ngroups = NGROUPS_MAX;
				gid_t groups[NGROUPS_MAX];
				getgrouplist(requid->pw_name, requid->pw_gid,
				    groups, &ngroups);

				for (int l = 0; l < ngroups; l++) {

					if (identgid == groups[l]) {
						isInGroup = 1;
						break;
					}
				}

			} else {
				isInGroup = 1;
			}

			if (!isInGroup) {
				continue;
			}
		}

		/* Password prompting not implemented */
		if (!(rules[i]->options & NOPASS))
			continue;

		/* Check for logging */
		if (rules[i]->options & NOLOG) {
			isLogged = 0;
		} else {
			isLogged = 1;
		}

		/*
		 * Check that we can be target user. If we don't specify a
		 * user, assume it to be the requested usr or root
		 */
		if (rules[i]->target == NULL) {

			requestpwd = getpwnam(req->pfr_req_user);
			if ((req->pfr_req_flags & PFEXECVE_USER) &&
			    requestpwd != NULL) {
				setcred(requestpwd, resp);
			} else {
				rootpwd = getpwnam("root");
				if (rootpwd == NULL)
					return (EPERM);
				setcred(rootpwd, resp);
			}

		} else {
			if (strncmp(req->pfr_req_user, rules[i]->target,
			    LOGIN_NAME_MAX) != 0) {
				return (EPERM);
			}

			targetpwd = getpwnam(rules[i]->target);
			if (targetpwd == NULL)
				return (EPERM);
			setcred(targetpwd, resp);
		}

		/* Check if we are supposed to keep our old groups */
		if (rules[i]->options & KEEPGROUPS) {
			resp->pfr_flags &= ~(PFRESP_GID | PFRESP_GROUPS);
		}


		if (rules[i]->options & SETGROUPS) {

			struct group *g;
			if (rules[i]->group == NULL ||
			    (g = getgrnam(rules[i]->group)) == NULL) {
			/* Check if no group specified if so, invalid?? */
				bzero(resp, sizeof(struct pfexec_resp));
				continue;
			}

			resp->pfr_gid = g->gr_gid;

			uint32_t ngroups = 1;
			int k = 0;

			while (1) {

				if (rules[i]->groupargs[k] == NULL) {
					break;
				}
				g = getgrnam(rules[i]->groupargs[k]);

				if (g == NULL) {
					k++;
					continue;
				}

				resp->pfr_groups[k] = g->gr_gid;
				k++;
				ngroups++;
			}

			resp->pfr_ngroups = ngroups;
		}


		if (rules[i]->cmd == NULL) {
			resp->pfr_errno = 0;
		} else {
			char confcmd[PATH_MAX], reqcmd[PATH_MAX];
			bzero(confcmd, PATH_MAX);
			bzero(reqcmd, PATH_MAX);

			int index = path_from_env(req->pfr_envarea,
			    req->pfr_envp, req->pfr_envc);

			if (index == -1) {
				/* If we can't find a path */
				strncpy(reqcmd, req->pfr_path, PATH_MAX);
				strncpy(confcmd, rules[i]->cmd, PATH_MAX);

			} else {
				char path[ARG_MAX];
				bzero(path, ARG_MAX);

				strncpy(path, &req->pfr_envarea[req->
				    pfr_envp[index].pfa_offset + 5],
				    req->pfr_envp[index].pfa_len);
				convert_to_path(rules[i]->cmd, path, confcmd,
				    req->pfr_path);
				convert_to_path(req->pfr_path, path, reqcmd,
				    req->pfr_path);
			}

			if (strncmp(confcmd, reqcmd,
			    PATH_MAX) == 0) {
				resp->pfr_errno = 0;
			} else {
				bzero(resp, sizeof(struct pfexec_resp));
				return (EPERM);
			}
		}

		/* Check args as well */
		if (rules[i]->cmdargs) {

			int j;
			for (j = 0; rules[i]->cmdargs[j]; j++) {

				if (req->pfr_argp[j + 1].pfa_len == 0) {
					bzero(resp, sizeof(struct pfexec_resp));
					return (EPERM);
				}

				if (strcmp(rules[i]->cmdargs[j],
				    &req->pfr_argarea[req->
				    pfr_argp[j + 1].pfa_offset])) {
					bzero(resp, sizeof(struct pfexec_resp));
					return (EPERM);
				}
			}
			/* Check if the request args is too many */
			if (req->pfr_argp[j + 1].pfa_len != 0) {

				bzero(resp, sizeof(struct pfexec_resp));
				return (EPERM);
			}
		}

		if (rules[i]->options & CHROOT) {

			if (rules[i]->chroot != NULL) {
				strncpy(resp->pfr_chroot, rules[i]->chroot,
				    PATH_MAX);
			} else {
				strncpy(resp->pfr_chroot, "/var/empty/",
				    PATH_MAX);
			}
			resp->pfr_flags |= PFRESP_CHROOT;
		}

		if (rules[i]->action == PERMIT)
			return (0);
		else
			return (EPERM);
	}

	/* If we get here, no rules in the config for this user */
	return (EPERM);
}

void
setcred(struct passwd *pass, struct pfexec_resp *resp)
{
	gid_t groups[NGROUPS_MAX];
	int ngroups;
	resp->pfr_uid = pass->pw_uid;
	resp->pfr_gid = pass->pw_gid;
	getgrouplist(pass->pw_name,
	    pass->pw_gid, groups, &ngroups);

	for (int i = 0; i < ngroups; i++) {
		resp->pfr_groups[i] = groups[i];
	}

	resp->pfr_ngroups = ngroups;
	resp->pfr_flags |= PFRESP_UID | PFRESP_GID | PFRESP_GROUPS;
}

void
convert_to_path(const char *prog, char *epath, char *fullpath,
    const char *reqpath)
{
	char *p, filename[PATH_MAX];
	int len;
	char *pathcpy;

	/* Special case if prog contains '/'  just leave it as is */
	if (strchr(prog, '/')) {
		strncpy(fullpath, prog, PATH_MAX);
		return;
	}

	if ((epath = strdup(epath)) == NULL)
		err(1, "strdup");
	pathcpy = epath;
	while ((p = strsep(&pathcpy, ":")) != NULL) {
		if (*p == '\0')
			p = ".";

		len = strlen(p);
		while (len > 0 && p[len-1] == '/')
			p[--len] = '\0';	/* strip trailing '/' */

		len = snprintf(filename, sizeof(filename), "%s/%s", p, prog);

		if (len < 0 || len >= sizeof(filename)) {
			continue;
		}
		/* Path has been found */
		if (strncmp(filename, reqpath, PATH_MAX) == 0) {
			free(epath);
			strncpy(fullpath, filename, PATH_MAX);
			return;
		}

	}

	free(epath);
	strncpy(fullpath, prog, PATH_MAX);
}

int
path_from_env(const char env[], const struct pfexec_arg pfr_envp[], int envc)
{
	char path[] = "PATH=";

	for (int i = 0; i < envc; i++) {

		for (int j = 0; j < 5; j++) {
			if (j < pfr_envp[i].pfa_len &&
			    env[pfr_envp[i].pfa_offset + j] == path[j]) {
				if (j == 4) {
					return i;
				}

			} else {
				break;
			}
		}
	}
	return -1;
}