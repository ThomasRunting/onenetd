/*
   onenetd: a single-process inetd equivalent
   Copyright 2001, 2002, 2003, 2005 Adam Sampson <ats@offog.org>

   Please report bugs to ats@offog.org.

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdio.h>
#include "config.h"

int max_conns = 40;
int conn_count = 0;
long gid = -1;
long uid = -1;
int backlog = 10;
int no_delay = 0;
int verbose = 0;
int stderr_to_socket = 0;
char *response = NULL;
char **command;
int selfpipe[2];
int listen_fd;

typedef struct client {
	int fd;
	char *message;
	int left;
	struct client *next;
} client;
client *clients = NULL;

/* Print a warning. */
void warn(const char *msg) {
	fprintf(stderr, "%s\n", msg);
}

/* Die with an error message. */
void die(const char *msg) {
	warn(msg);
	exit(20);
}

/* Handle SIGCHLD. */
void handle_sigchld(int dummy) {
	int old_errno = errno;
	write(selfpipe[1], "c", 1);
	errno = old_errno;
}

/* Change the flags on an fd. */
int change_flags(int fd, int add, int remove) {
	int flags = fcntl(fd, F_GETFL);
	int newflags;
	if (flags == -1)
		return -1;

	newflags = (flags | add) & ~remove;

	if (newflags != flags) {
		if (fcntl(fd, F_SETFL, flags) < 0)
			return -1;
	}
	
	return 0;
}

/* Set the FD_CLOEXEC flag on an fd. */
void set_fd_cloexec(int fd) {
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		die("unable to set FD_CLOEXEC");
}

/* Add an fd to an FD_SET, updating a maximum. */
void fd_set_add(int fd, fd_set *fds, int *max) {
	FD_SET(fd, fds);
	if (fd > *max) *max = fd;
}

/* Print the usage message. */
void usage(int code) {
	fprintf(stderr, "onenetd version " VERSION "\n"
		"Copyright 2001, 2002, 2003, 2005 Adam Sampson <ats@offog.org>\n"
		"This is free software with ABSOLUTELY NO WARRANTY.\n\n"
		"Usage: onenetd [options] address port command ...\n"
		"  address  Address to bind to (specify 0 for any address)\n"
		"  port     TCP port to bind to\n"
		"  command  Command to execute\n"
		"Options:\n"
		"  -c N     limit to at most N children running (default 40).\n"
		"           Further connections will be deferred unless -r\n"
		"           is specified.\n"
		"  -g gid   setgid(gid) after binding\n"
		"  -u uid   setuid(uid) after binding\n"
		"  -U       setuid($UID) and setgid($GID) after binding\n"
		"  -b N     set listen() backlog to N\n"
		"  -D       set TCP_NODELAY option on sockets\n"
		"  -e       redirect stderr of children to socket\n"
		"  -v       be verbose\n"
		"  -r resp  once -c limit is reached, refuse clients\n"
		"           with 'resp' rather than deferring them.\n"
		"           resp may contain \\r, \\n, \\t.\n"
		"  -h       show this usage message\n");
	exit(code);
}

/* Try to send a chunk of the response to a client. Remove the client
   from the list if we've sent all of it. */
void try_to_send(client *prev_cl, client *cl) {
	int remove = 0;
	int count = write(cl->fd, cl->message, cl->left);

	if (count >= 0) {
		cl->message += count;
		cl->left -= count;

		if (cl->left == 0)
			remove = 1;
	} else if (errno == EAGAIN) {
		/* ignorable error */
	} else {
		/* another error while writing */
		remove = 1;
	}

	if (remove) {
		close(cl->fd);
		if (prev_cl) {
			prev_cl->next = cl->next;
		} else {
			clients = cl->next;
		}
		free(cl);
	}
}

int main(int argc, char **argv) {
	struct sigaction sa;
	sigset_t sig_chld;
	struct sockaddr_in listen_addr;
	char *s, *r;
	int n;
	
	while (1) {
		char c = getopt(argc, argv, "+c:g:u:Ub:ODQvehr:");
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			max_conns = atoi(optarg);
			break;
		case 'g':
			gid = atoi(optarg);
			break;
		case 'u':
			uid = atoi(optarg);
			break;
		case 'U':
			s = getenv("GID");
			if (!s)
				die("-U specified but no $GID");
			gid = atoi(s);
			s = getenv("UID");
			if (!s)
				die("-U specified but no $UID");
			uid = atoi(s);
			break;
		case 'b':
			backlog = atoi(optarg);
			break;
		case 'D':
			no_delay = 1;
			break;
		case 'Q':
			verbose = 0;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'e':
			stderr_to_socket = 1;
			break;
		case 'h':
			usage(0);
			break;
		case 'r':
			r = response = malloc(strlen(optarg) + 1);
			if (!r)
				die("out of memory");
			for (s = optarg; *s != '\0'; s++) {
				if (*s == '\\') {
					s++;
					if (*s == 'r')
						*r++ = '\r';
					else if (*s == 'n')
						*r++ = '\n';
					else if (*s == 't')
						*r++ = '\t';
					else
						usage(20);
				} else {
					*r++ = *s;
				}
			}
			*r = '\0';
			break;
		default:
			usage(20);
		}
	}

	if ((argc - optind) < 3)
		usage(20);

	listen_addr.sin_family = AF_INET;

	s = argv[optind++];
	listen_addr.sin_addr.s_addr = inet_addr(s);
	if (listen_addr.sin_addr.s_addr == -1) {
		struct hostent *he = gethostbyname(s);
		if ((!he) || (he->h_addrtype != AF_INET)
			|| (he->h_addr == 0))
			die("unable to resolve listen host");
		listen_addr.sin_addr = *(struct in_addr *)he->h_addr;
	}

	s = argv[optind++];
	n = atoi(s);
	if (n == 0 && strcmp(s, "0") != 0) {
		struct servent *se = getservbyname(s, "tcp");
		if (!se)
			die("unable to resolve listen port");
		n = se->s_port;
	} else {
		n = htons(n);
	}
	listen_addr.sin_port = n;
	command = &argv[optind];

	if (pipe(selfpipe) < 0)
		die("unable to create self-pipe");
	if (change_flags(selfpipe[1], O_NONBLOCK, 0) < 0)
		die("unable to set O_NONBLOCK");
	set_fd_cloexec(selfpipe[0]);
	set_fd_cloexec(selfpipe[1]);

	listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0)
		die("unable to create socket");
	if (change_flags(listen_fd, O_NONBLOCK, 0) < 0)
		die("unable to set O_NONBLOCK");
	set_fd_cloexec(listen_fd);
	n = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n) < 0)
		die("unable to set SO_REUSEADDR");
	if (bind(listen_fd, (struct sockaddr *)&listen_addr,
		sizeof listen_addr) < 0)
		die("unable to bind to listen address");
	if (listen(listen_fd, backlog) < 0)
		die("unable to listen");

	if (gid != -1)
		if (setgid(gid) < 0)
			die("unable to setgid");
	if (uid != -1)
		if (setuid(uid) < 0)
			die("unable to setuid");

	sigemptyset(&sig_chld);
	sigaddset(&sig_chld, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sig_chld, NULL) < 0)
		die("unable to block SIGCHLD");

	sa.sa_handler = handle_sigchld;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	while (1) {
		int full;
		client *cl, *prev_cl, *next_cl;
		fd_set read_fds, write_fds;

		do {
			sigset_t old_sigs;
			int max = -1;

			full = conn_count >= max_conns;
			FD_ZERO(&read_fds);
			fd_set_add(selfpipe[0], &read_fds, &max);
			if (!(full && !response))
				fd_set_add(listen_fd, &read_fds, &max);

			FD_ZERO(&write_fds);
			for (cl = clients; cl; cl = cl->next)
				fd_set_add(cl->fd, &write_fds, &max);

			if (sigprocmask(SIG_UNBLOCK, &sig_chld, &old_sigs) < 0)
				die("unable to unblock SIGCHLD");

			n = select(max + 1, &read_fds, &write_fds, NULL, NULL);
			if (n < 0 && errno != EINTR)
				warn("select failed");

			if (sigprocmask(SIG_SETMASK, &old_sigs, NULL) < 0)
				die("unable to restore signal mask");
		} while (n < 0);

		prev_cl = NULL;
		for (cl = clients; cl; cl = next_cl) {
			next_cl = cl->next;

			if (FD_ISSET(cl->fd, &write_fds))
				try_to_send(prev_cl, cl);
			prev_cl = cl;
		}

		if (FD_ISSET(selfpipe[0], &read_fds)) {
			char c;

			/* We don't care if this fails. */
			read(selfpipe[0], &c, 1);

			while (1) {
				n = waitpid(-1, NULL, WNOHANG);
				if (n <= 0) break;

				conn_count--;
				if (verbose)
					fprintf(stderr, "%d closed (%d/%d)\n", n, conn_count, max_conns);
			}
		}

		if (FD_ISSET(listen_fd, &read_fds)) {
			int pid;
			struct sockaddr_in local_addr, child_addr;
			int len = sizeof child_addr;
			int child_fd;

			if (full && !response)
				goto no_conn;

			child_fd = accept(listen_fd,
				(struct sockaddr *)&child_addr, &len);
			
			if (len != sizeof child_addr) {
				warn("unable to get remote address");
				goto no_conn;
			}
			if (child_fd < 0 && errno == EAGAIN)
				goto no_conn;
			if (child_fd < 0) {
				warn("accept failed");
				goto no_conn;
			}
			set_fd_cloexec(child_fd);

			len = sizeof local_addr;
			if (getsockname(child_fd,
				(struct sockaddr *)&local_addr, &len) < 0
				|| len != sizeof local_addr) {
				warn("unable to get local address");
				goto no_conn;
			}

			if (full) {
				/* Avoid overfilling the fd_set. */
				if (child_fd >= FD_SETSIZE && verbose) {
					fprintf(stderr, "- dropped from %s "
						"port %d\n",
						inet_ntoa(child_addr.sin_addr),
						ntohs(child_addr.sin_port));
				}
				if (child_fd >= FD_SETSIZE)
					goto no_conn;

				if (change_flags(child_fd, O_NONBLOCK, 0) < 0) {
					warn("unable to set O_NONBLOCK");
					goto no_conn;
				}

				cl = malloc(sizeof *cl);
				if (!cl) {
					warn("out of memory");
					goto no_conn;
				}

				cl->fd = child_fd;
				child_fd = -1;
				cl->message = response;
				cl->left = strlen(cl->message);
				cl->next = clients;
				clients = cl;

				if (verbose)
					fprintf(stderr, "- refused from %s "
						"port %d\n",
						inet_ntoa(child_addr.sin_addr),
						ntohs(child_addr.sin_port));
	
				/* Try to send the response now; if we send
				   all of it it'll get removed from the list
				   again. */
				try_to_send(NULL, cl);

				goto no_conn;
			}

			n = 1;
			if (no_delay && setsockopt(child_fd, IPPROTO_TCP,
				TCP_NODELAY, &n, sizeof n) < 0) {
				warn("unable to set TCP_NODELAY");
				goto no_conn;
			}

			pid = fork();
			if (pid < 0) {
				warn("fork failed");
				goto no_conn;
			}

			if (pid == 0) {
				char buf[80];

				dup2(child_fd, 0);
				dup2(child_fd, 1);
				if (stderr_to_socket)
					dup2(child_fd, 2);

				putenv(strdup("PROTO=TCP"));
				snprintf(buf, sizeof buf, "TCPLOCALIP=%s",
					inet_ntoa(local_addr.sin_addr));
				putenv(strdup(buf));
				snprintf(buf, sizeof buf, "TCPLOCALPORT=%d",
					ntohs(local_addr.sin_port));
				putenv(strdup(buf));
				snprintf(buf, sizeof buf, "TCPREMOTEIP=%s",
					inet_ntoa(child_addr.sin_addr));
				putenv(strdup(buf));
				snprintf(buf, sizeof buf, "TCPREMOTEPORT=%d",
					ntohs(child_addr.sin_port));
				putenv(strdup(buf));

				execvp(command[0], command);
				_exit(20);
			}

			conn_count++;
			if (verbose)
				fprintf(stderr, "%d connected from %s "
					"port %d (%d/%d)\n", pid,
					inet_ntoa(child_addr.sin_addr),
					ntohs(child_addr.sin_port),
					conn_count, max_conns);

			no_conn:
			if (child_fd >= 0)
				close(child_fd);
		}	
	}

	return 0;
}

