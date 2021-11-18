/*
 *
 * Copyright 2020 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <event.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cdefs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>

#include "http-parser/http_parser.h"
#include "log.h"
#include "metrics.h"

const int BACKLOG = 8;
const size_t BUFLEN = 2048;

enum response_type {
	RESP_NOT_FOUND = 0,
	RESP_METRICS
};

/*
 * Struct representing a request that's being processed and the connection it's
 * being received on (each connection can send only one request at present, so
 * these are the same).
 */
struct req {
	int id;				/* A serial number for this req */
	int done;			/* Is the request done? 1 = true */

	/* Links for the "reqs" list */
	struct req *next;
	struct req *prev;

	struct registry *registry;	/* The metrics registry */

	struct sockaddr_in raddr;	/* Remote peer */
	size_t pfdnum;			/* pollfd index, or 0 if not polled */
	int sock;			/* Client socket */
	FILE *wf;			/* Writable FILE of our client socket */

	struct http_parser *parser;
	enum response_type resp;	/* Response type based on URL+method */

	struct event ev;		/* The event for this request */
};

/*
 * Struct used to hold the information that is required by the accept_connection
 * callback. This includes the registry info and the request id.
 */
struct inf {
	int *rid;			/* The request id (rid)*/
	struct registry *registry;	/* The registry*/
	struct event ev;		/* The event being passed*/
};

/* Global list of all open reqs */
static struct req *reqs = NULL;

static int on_url(http_parser *, const char *, size_t);
static int on_header_field(http_parser *, const char *, size_t);
static int on_header_value(http_parser *, const char *, size_t);
static int on_body(http_parser *, const char *, size_t);
static int on_headers_complete(http_parser *);
static int on_message_complete(http_parser *);

/* Event callback functions */
static void handle_request(int, short, void *);
static void accept_connection(int, short, void *);

static char *stats_buf = NULL;
static size_t stats_buf_sz = 0;

static void
free_req(struct req *req)
{
	/* Remove this req from the reqs list */
	if (req->prev == NULL)
		reqs = req->next;
	if (req->prev != NULL)
		req->prev->next = req->next;
	if (req->next != NULL)
		req->next->prev = req->prev;

	/*
	 * Note that closing the writable FILE we fdopen()'d on the client
	 * socket will close the socket, too (we don't call close() here)
	 */
	fclose(req->wf);

	free(req->parser);
	free(req);
}

static __dead void
usage(const char *arg0)
{
	fprintf(stderr, "usage: %s [-f] [-l logfile] [-p port]\n", arg0);
	fprintf(stderr, "listens for prometheus http requests\n");
	exit(EXIT_USAGE);
}

extern FILE *logfile;

//static void reactor_loop(int, struct registry *, http_parser_settings *);

int
main(int argc, char *argv[])
{
	const char *optstring = "p:fl:";
	uint16_t port = 27600;
	int daemon = 1;

	int lsock;
	struct sockaddr_in laddr;
	struct registry *registry;
	int c, rid = 1;
	unsigned long int parsed;
	char *p;
	pid_t kid;

	logfile = stdout;

	/*
	 * Set up the timezone information for localtime() et al. This is used
	 * by the tslog() routines in log.c to print timestamps in local time.
	 */
	tzset();

	/* Parse our commandline arguments. */
	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'p':
			errno = 0;
			parsed = strtoul(optarg, &p, 0);
			/*
			 * If strtoul() fails, it sets errno. If there's left
			 * over characters other than a number, though, it
			 * doesn't set errno. Check if it advanced "p" all the
			 * way to the end.
			 */
			if (errno != 0 || *p != '\0') {
				errx(EXIT_USAGE, "invalid argument for "
				    "-p: '%s'", optarg);
			}
			/* Ports have to fit in a uint16_t */
			if (parsed >= UINT16_MAX) {
				errx(EXIT_USAGE, "invalid argument for "
				    "-p: '%s' (too high)", optarg);
			}
			port = parsed;
			break;
		case 'f':
			daemon = 0;
			break;
		case 'l':
			logfile = fopen(optarg, "a");
			if (logfile == NULL)
				err(EXIT_USAGE, "open('%s')", optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (daemon) {
		kid = fork();
		if (kid < 0) {
			err(EXIT_ERROR, "fork");
		} else if (kid > 0) {
			/* The parent process exits immediately. */
			return (0);
		}
		umask(0);
		if (setsid() < 0)
			tserr(EXIT_ERROR, "setsid");
		chdir("/");

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/* Initialise the collector module registry */
	registry = registry_build();

	/*
	 * Ignore SIGPIPE if we get it from any of our sockets: we'll poll
	 * them for read/hup/err later and figure it out anyway.
	 */
	signal(SIGPIPE, SIG_IGN);

	/* Now open our listening socket */

	lsock = socket(AF_INET, SOCK_STREAM, 0);
	if (lsock < 0)
		tserr(EXIT_SOCKERR, "socket()");

	if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR,
	    &(int){ 1 }, sizeof(int))) {
		tserr(EXIT_SOCKERR, "setsockopt(SO_REUSEADDR)");
	}

	/* Set our listen socket to be non-blocking (on calls to accept) */	
	if ((fcntl(lsock, F_SETFL, O_NONBLOCK)) < 0) {
		tserr(EXIT_SOCKERR, "fcntl(O_NONBLOCK)");
	}

	bzero(&laddr, sizeof(laddr));
	laddr.sin_family = AF_INET;			/* XXX: ipv6? */
	laddr.sin_port = htons(port);

	if (bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr)))
		tserr(EXIT_SOCKERR, "bind(%d)", port);

	if (listen(lsock, BACKLOG))
		tserr(EXIT_SOCKERR, "listen(%d)", port);

	tslog("listening on port %d", port);

	event_init();

	/* And begin handling requests! */
	struct inf *info = calloc(1, sizeof(struct inf));
	info->ev.ev_fd = lsock;
	info->rid = &rid;
	info->registry = registry;
	event_set(&info->ev, lsock, EV_READ|EV_PERSIST, 
	    accept_connection, info);

	event_add(&info->ev, NULL);

	event_dispatch();

	/* Shouldn't reach this unless an error occurs */	
	registry_free(registry);

	return (0);
}

/* Accept an incoming connection and register the fd for a new event */
static void
accept_connection(int fd, short revents, void *conn)
{
	struct sockaddr_in raddr;
	socklen_t len = sizeof(raddr);

	/* Typecast conn into an inf struct */
	struct inf *info = (struct inf *)conn;

	int sock = accept(fd, (struct sockaddr *)&raddr, &len);

	if (sock < 0) {
		switch (errno) {
			case ECONNABORTED:
			case ECONNRESET:
				tslog("failed to accept connection "
				    "from %s: %d (%s)",
				    inet_ntoa(raddr.sin_addr),
				    errno, strerror(errno));
				break;
			default:
				tserr(EXIT_SOCKERR, "accept()");
			}
	}

	/* Add a req on this connection fd */
	struct req *req = calloc(1, sizeof(struct req));
	if (req == NULL) {
		tserr(EXIT_MEMORY, "calloc(%zd)",
		    sizeof(struct req));
	}
	
	http_parser *parser = calloc(1, sizeof(http_parser));
	if (parser == NULL)
		tserr(EXIT_MEMORY, "calloc(%zd)",
		    sizeof(http_parser));

	http_parser_init(parser, HTTP_REQUEST);

	parser->data = req;
	req->id = (*info->rid)++; /* Extract and increment rid */
	req->sock = sock;
	req->raddr = raddr;
	req->registry = info->registry;
	req->parser = parser;

	req->wf = fdopen(sock, "w");
	if (req->wf == NULL) {
		tslog("failed to fdopen socket: %s",
			strerror(errno));
		close(req->sock);
		free(parser);
		free(req);
		return;
	}

	tslog("accepted connection from %s (req %d)",
	    inet_ntoa(raddr.sin_addr), req->id);

	/* Set our socket to be non-blocking (on calls to recv) */	
	if ((fcntl(sock, F_SETFL, O_NONBLOCK)) < 0) {
		tserr(EXIT_SOCKERR, "fcntl(O_NONBLOCK)");
	}

	req->ev.ev_fd = sock;
	event_set(&req->ev, req->ev.ev_fd,
	    EV_READ|EV_PERSIST, handle_request, req);

	/* Add the event to the scheduler with 30 seconds timeout*/
	struct timeval *tv = calloc(1, sizeof(struct timeval));
	tv->tv_sec = 30; 
	event_add(&req->ev, tv);
}

static void
handle_request(int fd, short revents, void *conn)
{
	ssize_t recvd;
	http_parser_settings settings;
	char *buf;
	size_t plen, blen;
	struct req *req = (struct req *) conn;
	struct http_parser *parser = req->parser;

	/*
	 * Set up our "settings" struct for http_parser, which contains the
	 * callbacks that will run when the parser encounters different parts
	 * of the HTTP request.
	 */
	bzero(&settings, sizeof(settings));
	settings.on_headers_complete = on_headers_complete;
	settings.on_message_complete = on_message_complete;
	settings.on_url = on_url;
	settings.on_body = on_body;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;

	blen = BUFLEN;
	buf = malloc(blen);

	/* Is ready to read? */
	if (revents & EV_READ) {
		if (buf == NULL)
			tserr(EXIT_MEMORY, "malloc(%zd)", blen);

		/* Read in data*/
		recvd = recv(req->sock, buf, blen, 0);
		if (recvd < 0) {
			tslog("error recv %d: %s",
				req->id, strerror(errno));
			event_del(&req->ev);
			free_req(req);
			free(buf);
			return;
		}

		/* File descriptor has been closed by client */
		if (recvd == 0) {
			http_parser_execute(parser, &settings, buf, 0);
			tslog("connection %d closed!", req->id);
			event_del(&req->ev);
			free_req(req);
			free(buf);
			return;		
		}


		plen = http_parser_execute(parser, &settings, buf, recvd);

		if (parser->upgrade) {
		/* we don't use this, so just close */
			tslog("upgrade? %d", req->id);
			event_del(&req->ev);
			free_req(req);
			free(buf);
			return;

		} else if (plen != recvd) {
			tslog("http-parser gave error on %d, "
				"close", req->id);
			event_del(&req->ev);
			free_req(req);
			free(buf);
			return;
		}

		if (req->done) {
			event_del(&req->ev);
			free_req(req);
			free(buf);
			return;
		}
	}
	
	/* The device or socket has been disconnected */
	if (revents & EV_TIMEOUT) {
		http_parser_execute(parser, &settings, buf, 0);
		tslog("connection %d closed! (timeout)", req->id);
		event_del(&req->ev);
		free_req(req);
		free(buf);
		return;
	}
}

static int
on_url(http_parser *parser, const char *url, size_t ulen)
{
	struct req *req = parser->data;
	if (parser->method == HTTP_GET &&
	    ulen >= strlen("/metrics") &&
	    strncmp(url, "/metrics", strlen("/metrics")) == 0) {
		req->resp = RESP_METRICS;
	}
        if (parser->method == HTTP_GET &&
            ulen >= strlen("/stopme") &&
            strncmp(url, "/stopme", strlen("/stopme")) == 0) {
		exit(0);
        }
	return (0);
}

static int
on_body(http_parser *parser, const char *data, size_t len)
{
	//struct req *req = parser->data;
	return (0);
}

static int
on_header_field(http_parser *parser, const char *hdrname, size_t hlen)
{
	//struct req *req = parser->data;
	return (0);
}

static int
on_header_value(http_parser *parser, const char *hdrval, size_t vlen)
{
	//struct req *req = parser->data;
	return (0);
}

static int
on_headers_complete(http_parser *parser)
{
	//struct req *req = parser->data;
	return (0);
}

static void
send_err(http_parser *parser, enum http_status status)
{
	struct req *req = parser->data;
	fprintf(req->wf, "HTTP/%d.%d %d %s\r\n", parser->http_major,
	    parser->http_minor, status, http_status_str(status));
	fprintf(req->wf, "Server: obsd-prom-exporter\r\n");
	fprintf(req->wf, "Connection: close\r\n");
	fprintf(req->wf, "\r\n");
	fflush(req->wf);
	req->done = 1;
}

static int
on_message_complete(http_parser *parser)
{
	struct req *req = parser->data;
	FILE *mf;
	off_t off;
	int r;

	/* If we didn't recognise the method+URL, return a 404. */
	if (req->resp == RESP_NOT_FOUND) {
		send_err(parser, 404);
		return (0);
	}

	if (stats_buf == NULL) {
		stats_buf_sz = 256*1024;
		stats_buf = malloc(stats_buf_sz);
	}
	if (stats_buf == NULL) {
		tslog("failed to allocate metrics buffer");
		send_err(parser, 500);
		return (0);
	}
	mf = fmemopen(stats_buf, stats_buf_sz, "w");
	if (mf == NULL) {
		tslog("fmemopen failed: %s", strerror(errno));
		send_err(parser, 500);
		return (0);
	}

	tslog("generating metrics for req %d...", req->id);
	r = registry_collect(req->registry);
	if (r != 0) {
		tslog("metric collection failed: %s", strerror(r));
		send_err(parser, 500);
		return (0);
	}
	print_registry(mf, req->registry);
	fflush(mf);
	off = ftell(mf);
	if (off < 0) {
		send_err(parser, 500);
		return (0);
	}
	fclose(mf);
	tslog("%d done, sending %lld bytes", req->id, off);

	fprintf(req->wf, "HTTP/%d.%d %d %s\r\n", parser->http_major,
	    parser->http_minor, 200, http_status_str(200));
	fprintf(req->wf, "Server: obsd-prom-exporter\r\n");
	/*
	 * Prometheus expects this version=0.0.4 in the content-type to
	 * indicate that it's the prometheus text format.
	 */
	fprintf(req->wf, "Content-Type: "
	    "text/plain; version=0.0.4; charset=utf-8\r\n");
	fprintf(req->wf, "Content-Length: %lld\r\n", off);
	fprintf(req->wf, "Connection: close\r\n");
	fprintf(req->wf, "\r\n");
	fflush(req->wf);

	fprintf(req->wf, "%s", stats_buf);
	fflush(req->wf);

	req->done = 1;

	return (0);
}