/*
   onenetd: a single-process inetd equivalent
   Copyright 2001, 2002, 2003, 2005, 2014 Adam Sampson <ats@offog.org>

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
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

int max_conns = 5;
int conn_count = 0;
int bind_family = AF_INET;
int use_gid = 0;
gid_t gid = 0;
int use_uid = 0;
uid_t uid = 0;
int show_port = 0;
int backlog = 10;
int no_delay = 0;
int verbose = 0;
int stderr_to_socket = 0;
char *response = NULL;
char **command;

/* This pipe is used to safely detect SIGCHLD: the SIGCHLD handler writes a
   character to it, and the main loop can then reap children later.
   (See http://cr.yp.to/docs/selfpipe.html for details.) */
int selfpipe[2];

typedef struct client {
	int fd;
	char *message;
	size_t left;
	struct client *next;
} client;
client *clients = NULL;

/* Structure big enough to contain either an IPv4 or IPv6 socket address. */
typedef union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
} either_addr_t;

/* Get the UCSPI PROTO value for an address. */
const char *get_proto(const either_addr_t *addr) {
	if (addr->v4.sin_family == AF_INET6
		&& !IN6_IS_ADDR_V4MAPPED(&addr->v6.sin6_addr))
		return "TCP6";
	else
		return "TCP";
}

/* Get the UCSPI *IP value for an address.
   Returns a pointer to a static buffer. */
const char *get_addr(const either_addr_t *addr) {
	static char buf[INET6_ADDRSTRLEN];
	const void *src;
	int family = addr->v4.sin_family;

	if (family == AF_INET) {
		src = &addr->v4.sin_addr;
	} else if (IN6_IS_ADDR_V4MAPPED(&addr->v6.sin6_addr)) {
		/* An IPv4-mapped IPv6 address; display as IPv4. */
		family = AF_INET;
		src = ((char *)(&addr->v6.sin6_addr)) + 12;
	} else {
		src = &addr->v6.sin6_addr;
	}

	const char *s = inet_ntop(family, src, buf, sizeof buf);
	if (s == NULL)
		return "-";
	return s;
}

/* Get the UCSPI *PORT value for an address. */
int get_port(const either_addr_t *addr) {
	if (addr->v4.sin_family == AF_INET)
		return ntohs(addr->v4.sin_port);
	else
		return ntohs(addr->v6.sin6_port);
}

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

/* Equivalent to putenv(strdup(s)), with error checking. */
int putenv_dup(const char *s) {
	char *copy = strdup(s);
	if (copy == NULL)
		die("strdup failed");

	return putenv(copy);
}

/* Print the usage message. */
void usage(int code) {
	fprintf(stderr, "onenetd version " VERSION "\n"
		"\n"
		"Usage: onenetd [options] address port command ...\n"
		"  address  Address to bind to (0 for all local addresses)\n"
		"  port     TCP port to bind to (0 for any available port)\n"
		"  command  Command to execute\n"
		"Options:\n"
		"  -c N     limit to at most N children running (default 40).\n"
		"           Further connections will be deferred unless -r\n"
		"           is specified.\n"
		"  -6       bind to an IPv6 address (default IPv4)\n"
		"  -g gid   setgid(gid) after binding\n"
		"  -u uid   setuid(uid) after binding\n"
		"  -U       setuid($UID) and setgid($GID) after binding\n"
		"  -1       print local port number to stdout after binding\n"
		"  -b N     set listen() backlog to N\n"
		"  -D       set TCP_NODELAY option on sockets\n"
		"  -e       redirect stderr of children to socket\n"
		"  -v       be verbose\n"
		"  -Q       don't be verbose (default)\n"
		"  -r resp  once -c limit is reached, refuse clients\n"
		"           with 'resp' rather than deferring them.\n"
		"           resp may contain \\r, \\n, \\t.\n"
		"  -h       show this usage message\n"
		"\n"
		"Report bugs to <ats@offog.org>.\n");
	exit(code);
}

/* Create and bind the listening socket. */
int make_listen_socket(const char *address, const char *port) {
	struct addrinfo hints = {};
	struct addrinfo *ai;
	int rc, n, fd;

	hints.ai_family = bind_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;

	rc = getaddrinfo(address, port, &hints, &ai);
	if (rc != 0) {
		die(gai_strerror(rc));
	}

	fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (fd < 0)
		die("unable to create socket");
	if (change_flags(fd, O_NONBLOCK, 0) < 0)
		die("unable to set O_NONBLOCK");
	set_fd_cloexec(fd);
	n = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n) < 0)
		die("unable to set SO_REUSEADDR");
	if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
		die("unable to bind to listen address");
	if (listen(fd, backlog) < 0)
		die("unable to listen");

	if (show_port) {
		either_addr_t addr;
		socklen_t size = sizeof addr;

		if (getsockname(fd, (struct sockaddr *)&addr, &size) < 0)
			die("unable to get bound address");

		printf("%d\n", get_port(&addr));
		fflush(stdout);
	}

	freeaddrinfo(ai);

	return fd;
}

/* Try to send a chunk of the response to a client. Remove the client
   from the list if we've sent all of it. */
void try_to_send(client *prev_cl, client *cl) {
	int remove = 0;
	ssize_t count = write(cl->fd, cl->message, cl->left);

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

/* Accept a new connection, and either spawn a new child process or add it to
   the list of clients to reject. */
void accept_connection(int listen_fd, int full) {
	pid_t pid;
	either_addr_t local_addr, child_addr;
	socklen_t len = sizeof child_addr;
	int child_fd;
	int n;

	child_fd = accept(listen_fd, (struct sockaddr *)&child_addr, &len);
	if (len > sizeof child_addr) {
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
	if (getsockname(child_fd, (struct sockaddr *)&local_addr, &len) < 0
		|| len > sizeof local_addr) {
		warn("unable to get local address");
		goto no_conn;
	}

	if (full) {
		client *cl;

		/* Avoid overfilling the fd_set. */
		if (child_fd >= FD_SETSIZE && verbose) {
			fprintf(stderr, "- dropped from %s port %d\n",
				get_addr(&child_addr),
				get_port(&child_addr));
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
			fprintf(stderr, "- refused from %s port %d\n",
				get_addr(&child_addr),
				get_port(&child_addr));

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

		snprintf(buf, sizeof buf, "PROTO=%s",
			get_proto(&local_addr));
		putenv_dup(buf);
		snprintf(buf, sizeof buf, "TCPLOCALIP=%s",
			get_addr(&local_addr));
		putenv_dup(buf);
		snprintf(buf, sizeof buf, "TCPLOCALPORT=%d",
			get_port(&local_addr));
		putenv_dup(buf);
		snprintf(buf, sizeof buf, "TCPREMOTEIP=%s",
			get_addr(&child_addr));
		putenv_dup(buf);
		snprintf(buf, sizeof buf, "TCPREMOTEPORT=%d",
			get_port(&child_addr));
		putenv_dup(buf);

		execvp(command[0], command);
		_exit(20);
	}

	conn_count++;
	if (verbose)
		fprintf(stderr, "%ld connected from %s port %d (%d/%d)\n",
			(long) pid,
			get_addr(&child_addr),
			get_port(&child_addr),
			conn_count, max_conns);

no_conn:
	if (child_fd >= 0)
		close(child_fd);
}

/* Check for child processes that have exited. */
void reap_children(void) {
	while (1) {
		pid_t pid = waitpid(-1, NULL, WNOHANG);
		if (pid <= 0)
			break;

		conn_count--;
		if (verbose)
			fprintf(stderr, "%ld closed (%d/%d)\n",
				(long) pid, conn_count, max_conns);
	}
}

int main(int argc, char **argv) {
	struct sigaction sa;
	sigset_t sig_chld;
	int listen_fd;
	char *s, *r;
	int n;

	while (1) {
		int c = getopt(argc, argv, "+c:6g:u:U1b:DQvehr:");
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			max_conns = atoi(optarg);
			break;
		case '6':
			bind_family = AF_INET6;
			break;
		case 'g':
			use_gid = 1;
			gid = atoi(optarg);
			break;
		case 'u':
			use_uid = 1;
			uid = atoi(optarg);
			break;
		case 'U':
			s = getenv("GID");
			if (!s)
				die("-U specified but no $GID");
			use_gid = 1;
			gid = atoi(s);
			s = getenv("UID");
			if (!s)
				die("-U specified but no $UID");
			use_uid = 1;
			uid = atoi(s);
			break;
		case '1':
			show_port = 1;
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

	listen_fd = make_listen_socket(argv[optind], argv[optind + 1]);
	command = &argv[optind + 2];

	/* Drop privileges. */
	if (use_gid)
		if (setgid(gid) < 0)
			die("unable to setgid");
	if (use_uid)
		if (setuid(uid) < 0)
			die("unable to setuid");

	/* Create the self-pipe. */
	if (pipe(selfpipe) < 0)
		die("unable to create self-pipe");
	if (change_flags(selfpipe[1], O_NONBLOCK, 0) < 0)
		die("unable to set O_NONBLOCK");
	set_fd_cloexec(selfpipe[0]);
	set_fd_cloexec(selfpipe[1]);

        /* Mask SIGCHLD, except when we're blocked in select(). This is because
           many of the system calls we use are interruptable, and we'd
           otherwise have to handle EINTR everywhere.  (It would be simpler to
           just use SA_RESTART for SIGCHLD -- but POSIX says that it's
           implementation-defined whether select() is interrupted in that case
           or not.) */
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
			/* If we're full, and we don't have a response to send,
			   then we don't want to accept new connections -- so
			   don't check listen_fd. */
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

		if (FD_ISSET(selfpipe[0], &read_fds)) {
			char c;

			/* We don't care if this fails. */
			read(selfpipe[0], &c, 1);

			reap_children();
		}

		if (FD_ISSET(listen_fd, &read_fds)) {
			accept_connection(listen_fd, full);
		}

		prev_cl = NULL;
		for (cl = clients; cl; cl = next_cl) {
			next_cl = cl->next;

			if (FD_ISSET(cl->fd, &write_fds))
				try_to_send(prev_cl, cl);
			prev_cl = cl;
		}
	}

	return 0;
}
