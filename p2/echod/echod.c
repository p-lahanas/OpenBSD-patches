#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

#include <arpa/inet.h>

/*
 * maybe useful functions. they're not static so the linker doesnt get upset.
 */
void    hexdump(const void *, size_t);
void    msginfo(const struct sockaddr_storage *, socklen_t, size_t);

__dead static void usage(void);

struct echod {
	TAILQ_ENTRY(echod)
	    entry;
	struct event ev;
};

/* 
 * Declare a new queue of type echod_list 
 * which contains elements of type 'echod' 
 */
TAILQ_HEAD(echod_list, echod);

static void
echod_recv(int fd, short revents, void *conn)
{
	struct sockaddr_in6 cliaddr;
	char buffer[100];
	memset(buffer, 0, 100);

	/* Returns the number of message bytes read*/
	int len = sizeof(cliaddr);

	int n = recvfrom(fd, buffer, sizeof(buffer), 0, 
	    (struct sockaddr*) &cliaddr, &len);
	
	/* Null terminate the received msg before sending it back*/
	buffer[n] = '\0';

	if (n < 0) {
		perror("Reading bytes failed");
		exit(1);
	}

	/* Just in case len get modified in recvfrom???*/
	ssize_t err = sendto(fd, buffer, n, 0, 
	    (struct sockaddr *) &cliaddr, len);
	
	if (err == -1) {
		perror("sending bytes failed");
	}	
}

__dead static void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-46] [-l address] [-p port]\n", __progname);
	exit(1);
}

static void
echod_bind(struct echod_list *echods, sa_family_t af,
    const char *host, const char *port)
{
	int serrno = ENOTCONN;
	const char *cause = "missing code";

	/* use getaddrinfo here */
	struct addrinfo *res, *res0;
	
	int ecode;

	/* Get information for localhost */ 
	if ((ecode = getaddrinfo(host, NULL, NULL, &res))) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ecode));
		exit(1);
	}

	res0 = res;
	/* Find the corresponding IP version address*/

	while (res0->ai_next != NULL) {
		
		if (res0->ai_family == (int)af)
			break;

		res0 = res0->ai_next;
	}

	if (res0 == NULL || res0->ai_family != af) {
		fprintf(stderr, "Could not resolve address for ai_family\n");
		exit(1);
	}
    
	if (af == AF_INET)
		/* Case sockaddr to sockaddr_in (for IPv4) */
		((struct sockaddr_in *) res0->ai_addr)->sin_port = 
		    htons(atoi(port));
	else
		/* Cast sockaddr to sockaddr_in6 for IPv6*/
		((struct sockaddr_in6 *) res0->ai_addr)->sin6_port = 
		    htons(atoi(port));

	/* Creating socket file descriptor */
	int fd;
	if ((fd = socket(af, SOCK_DGRAM, 0)) < 0) {
		perror("socket failed");
		exit(1);
	}
    
	/* Bind socket */
	if (bind(fd, res0->ai_addr, res0->ai_addrlen) < 0) {
		perror("bind failed");
		exit(1);
	}

	/* Free addressing info from getaddrinfo*/
	freeaddrinfo(res);

	/* Create a new echod with allocated memory*/
	struct echod *e = calloc(1, sizeof(struct echod));

	/* Create a new event base*/
    	e->ev.ev_fd = fd;
    	TAILQ_INSERT_TAIL(echods, e, entry);

	if (TAILQ_EMPTY(echods))
		errc(1, serrno, "host %s port %s %s", host, port, cause);
}

int
main(int argc, char *argv[])
{
	struct echod *e;
	struct echod_list echods = TAILQ_HEAD_INITIALIZER(echods);
	sa_family_t af = AF_INET;
	const char *host = "localhost";
	const char *port = "3301";
	int ch;

	while ((ch = getopt(argc, argv, "46l:p:")) != -1) {
		switch (ch) {
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;

		case 'l':
			host = (strcmp(optarg, "*") == 0) ? NULL : 
				   optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	echod_bind(&echods, af, host, port); /* this works or exits */

	event_init();

	TAILQ_FOREACH(e, &echods, entry) {
		event_set(&e->ev, EVENT_FD(&e->ev), EV_READ|EV_PERSIST,
		    echod_recv, e);
		event_add(&e->ev, NULL);
    	}

	event_dispatch();

	return (0);
}

/*
 * possibly useful functions
 */
void
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("%4zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
	    		printf("%02x ", data[i + j]);
		while (j++ < 16)
	    		printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(isprint(data[i + j]) ? data[i + j] : '.');
		printf("|\n");
	}
}

void
msginfo(const struct sockaddr_storage *ss, socklen_t sslen, size_t len)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int error;

	error = getnameinfo((const struct sockaddr *)ss, sslen,
	    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error != 0) {
		warnx("msginfo: %s", gai_strerror(error));
		return;
	}
    
	printf("host %s port %s bytes %zu\n", hbuf, sbuf, len);
}
