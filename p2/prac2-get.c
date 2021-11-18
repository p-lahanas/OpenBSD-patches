/* 
** CSSE2310/7231 - sample client - code to be commented in class
** Send a request for the top level web page (/) on some webserver and
** print out the response - including HTTP headers.
*/
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <stdlib.h>

#include <stdio.h> 
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

struct in_addr* 
name_to_IP_addr(char *hostname)
{
	int error;
	struct addrinfo* addressInfo;

	error = getaddrinfo(hostname, NULL, NULL, &addressInfo);

	if(error)
		return NULL;

	return &(((struct sockaddr_in*)(addressInfo->ai_addr))->sin_addr);
}

int 
connect_to(struct in_addr *ipAddress, int port)
{
	struct sockaddr_in socketAddr;
	int fd;
	
	/* Create TCP socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0) {
		perror("Error creating socket");
		exit(1);
	}

	/* Create a structure that represents the IP address and port number
	 * that we're connecting to.
	 */
	socketAddr.sin_family = AF_INET; /* IP v4 */
	socketAddr.sin_port = htons(port); 
	socketAddr.sin_addr.s_addr = ipAddress->s_addr;	

	/* Attempt to connect to server at that address */
	if(connect(fd, (struct sockaddr*)&socketAddr, sizeof(socketAddr)) < 0) {
		perror("Error connecting");
		exit(1);
	}

	return fd;
}

int
connect_to_host(char *hostname, int port, int ipVersion)
{
	/* Create addr info struct to get hostname info*/
	struct addrinfo hints, *res;

	/* Setup hints to ensure right IP version*/
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ipVersion;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	int ecode;
	if ((ecode = getaddrinfo(hostname, NULL, &hints, &res))) {
		/* IDK what to return if there is an error yet*/
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ecode));
		exit(1);
	}

	/* Assign res to a new pointer so we can free the memory later on*/
	struct addrinfo *res0 = res;	

	/* Find the corresponding IP version address*/
	while (res0->ai_next != NULL) {
		
		if (res0->ai_family == ipVersion)
			break;

		res0 = res0->ai_next;
	}
	
	if (res0 == NULL || res0->ai_family != ipVersion) { 
		fprintf(stderr, "Could not resolve address for ai_family\n");
		exit(1);
	}

	int fd;
	/* Create file descriptor for the socket*/ 
	fd = socket(res0->ai_family, SOCK_STREAM, 0);
	
	if (fd < 0) {
		perror("Socket error");
		exit(1);
	}

	if (ipVersion == AF_INET)
		/* Case sockaddr to sockaddr_in (for IPv4) */
		((struct sockaddr_in *) res0->ai_addr)->sin_port = htons(port);
	else
		/* Cast sockaddr to sockaddr_in6 for IPv6*/
		((struct sockaddr_in6 *) res0->ai_addr)->sin6_port 
		    = htons(port);

	if (connect(fd, res0->ai_addr, res0->ai_addrlen) < 0) {
  
		perror("Connect error");
		exit(1);
	}

	/* Free the address resolution memory*/
	freeaddrinfo(res);

	return fd;
}



void 
send_HTTP_request(int fd, char *file, char *host)
{
	char *requestString;

	/* Allocate enough space for our HTTP request */

	/* Construct HTTP request:
	 * GET / HTTP/1.0
	 * Host: hostname
	 * <blank line>
	 */
	asprintf(&requestString, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", 
	    file, host);


	/* Send our request to server */
	if(write(fd, requestString, strlen(requestString)) < 1) {
		perror("Write error");
		exit(1);
	}

	/* Free the string pointed to by requestString*/
	free(requestString);
}

void 
get_and_output_HTTP_response(int fd)
{
	char buffer[1024];
	int numBytesRead;
	int eof = 0;

	/* Repeatedly read from network fd until nothing left - write 
	 * everything out to stdout
	 */
	while(!eof) {
		numBytesRead = read(fd, buffer, 1024);
		if(numBytesRead < 0) {
			perror("Read error\n");
			exit(1);
		} else if(numBytesRead == 0) {
			eof = 1;
		} else {
			fwrite(buffer, sizeof(char), numBytesRead, stdout);
		}
	}
}

__dead void
usage(void)
{
	extern char *__progname; 

	fprintf(stderr, "usage: %s [-46] [-p Port] hostname\n", __progname);
	exit(1);
}

int 
main(int argc, char* argv[]) {

	char *url, *hostname, *path = NULL;

	const char *errstr;

	/* Default is IPv4 on port 80*/
	int port = 80, ipV = AF_INET;

	url = argv[argc - 1]; // last argument
	hostname = calloc(strlen(url), sizeof(char));

	for (int i = 0; i < strlen(url); i++) {
		/* Copy url into hostname until we encounter a '/' */
		hostname[i] = url[i];	
		
		if (url[i] == '/') {
			path = &url[i];
			hostname[i] = '\0';
			break;
		}
	}

	/* Must have a hostname*/
	if (argc < 2) {
		usage();
	}
   
	/* Check and handle command line arguments*/ 
	char ch; 

	while ((ch = getopt(argc, argv, "46p:")) != -1) {
		
		switch(ch) {
		  
		case '4':
			/* Force it to use IPv4 Address*/
			ipV = AF_INET;
			break;

		case '6':
			ipV = AF_INET6; 
			break;

		case 'p':
			port = strtonum(optarg, 0, 65535, 
				   &errstr);

			/* If error occurs port is 0*/
			if (errstr != NULL) {
				perror("Invalid Port");
				exit(1);
			}
			break;
	
		default:
			usage();
		} 
	}

	int fd;
	fd = connect_to_host(hostname, port, ipV); 
	
	if (path != NULL) 
		send_HTTP_request(fd, path, hostname);
	else   
		send_HTTP_request(fd, "/", hostname);
	
	get_and_output_HTTP_response(fd);
	close(fd);
	return 0;
}
