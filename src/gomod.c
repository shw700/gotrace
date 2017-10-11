#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <pthread.h>

#include "config.h"

//#include "zydis/include/Zydis/Decoder.h


int _gotrace_socket_fd = -1;

void *client_socket_loop(void *arg);
int set_intercept_redirect(pid_t pid, void *addr);


int set_intercept_redirect(pid_t pid, void *addr) {
/*	ZydisDecoder decoder;
	uint64_t ip = 0x007FFFFFFF400000;
	uint8_t *iptr = (uint8_t *)&addr;
	ZydisDecodedInstruction instruction;

	ZydisDecoderInit( &decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
        
	if (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, iptr, 16, ip, &instruction))) {
		fprintf(stderr, "Decoded instruction length: %u bytes\n", instruction.length);
	}
*/
	return 0;
}

static int client_loop_initialized = 0;

void *
client_socket_loop(void *arg) {
	int fd = (int)((uintptr_t)arg);
	
	client_loop_initialized = 1;

	fprintf(stderr, "Loop reading (%u).\n", (unsigned int)syscall(SYS_gettid));
	raise(SIGUSR2);
//	fprintf(stderr, "Loop continuing.\n");

	while (1) {
		gomod_data_hdr_t hdr;
		unsigned char *dbuf;
		int res;

//		fprintf(stderr, "Loop Attempting to read %zu bytes from %d\n", sizeof(hdr), fd);

		if ((res = recv(fd, &hdr, sizeof(hdr), MSG_WAITALL)) == -1) {
			perror("recv");
			fprintf(stderr, "Error receiving data from gotrace control socket.\n");
			break;
		} else if (res != sizeof(hdr)) {
			fprintf(stderr, "Unexpected error receiving data from gotrace control socket.\n");
			break;
		}

		if (hdr.magic != GOMOD_DATA_MAGIC) {
			fprintf(stderr, "Error retrieving gomod function request with unexpected data formatting.\n");
			break;
		} else if ((hdr.reqtype != GOMOD_RT_SET_INTERCEPT) && (hdr.reqtype != GOMOD_RT_CALL_FUNC)) {
			fprintf(stderr, "Error retrieving gomod function request with unrecognized type.\n");
			break;
		}

		fprintf(stderr, "Loop CMD SIZE: %u bytes / type %u\n", hdr.size, hdr.reqtype);

		if (!(dbuf = malloc(hdr.size))) {
			perror("malloc");
			break;
		}

		if ((res = recv(fd, dbuf, hdr.size, MSG_WAITALL)) != hdr.size) {
			if (res == -1)
				perror("recv");

			fprintf(stderr, "Unexpected error receiving request body data from gotrace control socket.\n");
			free(dbuf);
			break;
		}

		if (hdr.reqtype == GOMOD_RT_SET_INTERCEPT) {
			if (hdr.size % sizeof(void *)) {
				fprintf(stderr, "Error: Received set intercept request with invalid size (%u bytes).\n", hdr.size);
				free(dbuf);
				break;
			}

			fprintf(stderr, "Loop received set intercept request (n=%u).\n", (hdr.size / sizeof(void *)));
		}

		fprintf(stderr, "Loop read all data ok\n");
		free(dbuf);
        }


//	exit(0);
	fprintf(stderr, "Loop ending.\n");
	return NULL;
}


void _gomod_init(void)
{
	pthread_t ptid;
	struct sockaddr_un s_un;
	socklen_t ssize;
	char *gotrace_socket_path = NULL;
	int fd;

	if (!(gotrace_socket_path = getenv(GOTRACE_SOCKET_ENV))) {
		fprintf(stderr, "Error: could not find gotrace socket path in environment!\n");
		exit(EXIT_FAILURE);
		return;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		fprintf(stderr, "Error: could not create gotrace socket\n");
		exit(EXIT_FAILURE);
		return;
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, gotrace_socket_path, sizeof (s_un.sun_path));
//	strncpy(s_un.sun_path, "/tmp/blabla.sock", sizeof (s_un.sun_path));
	ssize = offsetof(struct sockaddr_un, sun_path) + strlen(s_un.sun_path);

	if (connect(fd, (struct sockaddr *)&s_un, ssize) == -1) {
		perror("connect");
		fprintf(stderr, "Error: could not connect to gotrace socket listener\n");
		exit(EXIT_FAILURE);
		return;
	}

	fprintf(stderr, "Loading...\n");

	if (pthread_create(&ptid, NULL, client_socket_loop, (void *)((uintptr_t)fd)) != 0) {
		perror("pthread_create");
		fprintf(stderr, "Error: could not create new thread for gotrace socket\n");
		exit(EXIT_FAILURE);
		return;
	}

	while (!client_loop_initialized) {
		int hi = 0;
		hi += 2;
		hi += getpid();
	}

	fprintf(stderr, "Client injection module initialiation complete.\n");
}

int somefunc(void) {
	void *addr;
	printf("We are in some func\n");
	addr = dlsym(RTLD_DEFAULT, "main.main");
	printf("addr = %p\n", addr);
	printf("dl error = %s\n", dlerror());
	return 0;
}
