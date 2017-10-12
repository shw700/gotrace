#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <setjmp.h>

#include "config.h"

#include "gomod_print/gomod_print.h"

//#include "zydis/include/Zydis/Decoder.h


extern void *___dlopen_stub;
int _gotrace_socket_fd = -1;

void *client_socket_loop(void *arg);
int set_intercept_redirect(pid_t pid, void *addr);
int map_stub(void);

char *call_golang_func_by_name(const char *fname, void *param);
char *call_golang_func_str(void *func, void *param);


int
call_mallocinit() {
	static jmp_buf j;

	void (*minitptr)(void);

	if (setjmp(j)) {
		fprintf(stderr, "Forcing return.\n");
		return 0;
	}

//	fprintf(stderr, "IN MALLOCINIT\n");
	minitptr = (void *)0x000000000040fb00;
	minitptr();
//	fprintf(stderr, "AFTER MALLOCINIT\n");
	longjmp(j, 1);

	return 0;
}
char *
call_golang_func_by_name(const char *fname, void *param)
{
	void *faddr;

	if (!(faddr = dlsym(RTLD_DEFAULT, fname))) {
		fprintf(stderr, "Error calling golang function \"%s\": %s\n", fname, dlerror());
		return NULL;
	}

	return call_golang_func_str(faddr, param);
}

#define arch_prctl(code,addr)	syscall(SYS_arch_prctl, code, addr)

char *
call_golang_func_str(void *func, void *param) {
	static char fs_buf[512];
	static char fs_buf_helper[512];
	static char fs_buf_helper2[512];
	static char fs_buf_helper3[512];
	unsigned long saved_fs;
	char *ret = NULL;
	int once = 1;

//	fprintf(stderr, "calling mallocinit() first\n");
	call_mallocinit();
//	fprintf(stderr, "returned from mallocinit\n");

	if (once) {
		unsigned long *pword = (unsigned long *)fs_buf;
		size_t i;

		memset(fs_buf, 0, sizeof(fs_buf));
		memset(fs_buf_helper, 0, sizeof(fs_buf_helper));
		memset(fs_buf_helper2, 0, sizeof(fs_buf_helper2));
		memset(fs_buf_helper3, 0, sizeof(fs_buf_helper3));

		for (i = 0; i < sizeof(fs_buf)/sizeof(void *); i++) {
//			*pword++ = (unsigned long)0x78bce0;
//			*pword++ = (unsigned long)&fs_buf_helper;
		if (i == 15)
			*pword++ = (unsigned long)&fs_buf_helper;
		else
			*pword++ = (unsigned long)0xc0ffee000+i;
		}


		pword = (unsigned long *)fs_buf_helper;

		for (i = 0; i < sizeof(fs_buf_helper)/sizeof(void *); i++) {
		if (!i)
			*pword++ = (unsigned long)fs_buf;
//			*pword++ = (unsigned long)0x00007fffff7fec20;
		else if ((i >= 6) && (i <= 9))
			*pword++ = (unsigned long)0x000000000078c020;
		else
			*pword++ = (unsigned long)0xdeadb000+i;
		}
//			*pword++ = (unsigned long)&fs_buf_helper2;

		pword = (unsigned long *)fs_buf_helper2;
		for (i = 0; i < sizeof(fs_buf_helper2)/sizeof(void *); i++)
			*pword++ = (unsigned long)&fs_buf_helper3;

		fs_buf_helper2[187] = 0x37;
		fs_buf_helper2[188] = 0x0;
		fs_buf_helper2[189] = 0x0;
		fs_buf_helper2[190] = 0x0;
		fs_buf_helper2[191] = 0x0;
		fs_buf_helper2[192] = 0x0;
	}

	if (arch_prctl(ARCH_GET_FS, &saved_fs) == -1) {
		perror("arch_prctl(ARCH_GET_FS)");
		return NULL;
	}

	fprintf(stderr, "saved fs: %p; new: %p\n", (void *)saved_fs, (void *)fs_buf+256);
	fprintf(stderr, "Bufs: %p, 1=%p, 2=%p, 3=%p\n", fs_buf, fs_buf_helper, fs_buf_helper2, fs_buf_helper3);
	fprintf(stderr, "Calling: %p / %p\n", func, param);

	if (arch_prctl(ARCH_SET_FS, fs_buf+128) == -1) {
		perror("arch_prctl(ARCH_SET_FS)");
		return NULL;
	}


	asm (	"push %%rdx;		\
		call *%%rbx;		\
		mov 8(%%rsp), %%rbx;	\
		nop;"
		: "=b" (ret)
		: "b" (func), "d" (param)
	);

	if (arch_prctl(ARCH_SET_FS, saved_fs) == -1) {
		perror("arch_prctl(ARCH_SET_FS)");
		return NULL;
	}

	return ret;
}

int
map_stub(void) {
	unsigned char *jmpptr, *buf;
	uint32_t search = 0xdeadbeef;

	if ((buf = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0)) == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	memset(buf, 0x90, 128);
	memcpy(buf, ___dlopen_stub, 80);

	jmpptr = buf;

	while (jmpptr < (buf+128)) {
		if (!memcmp(jmpptr, &search, sizeof(search)))
			break;

		jmpptr++;
	}

	if (jmpptr >= (buf+128)) {
		fprintf(stderr, "Error: search failed!\n");
		return -1;
	}

	//*((unsigned long *)jmpptr) = 0x4007b0;
        //somefunc = (void *)buf;
	//somefunc();

	return 0;
}


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

			fprintf(stderr, "Loop received set intercept request (n=%u).\n", (unsigned int)(hdr.size / sizeof(void *)));
		} else if (hdr.reqtype == GOMOD_RT_CALL_FUNC) {
			void *fdata;
			char *fname = (char *)dbuf;

			fdata = (void *)(fname + strlen(fdata) + 1);
			fprintf(stderr, "Loop received function call request: %s()\n", fname);
		}

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

//	char *tcptest = gotrace_print_net__TCPConn(0);
//	printf("tcptest = [%s]\n", tcptest);

	fprintf(stderr, "Loop (%lu)\n", syscall(SYS_gettid));
//	char *rx = call_golang_func_str((void *)0x000000000402100, (void *)0xc0debabe);
//	fprintf(stderr, "Loop result heh = %p\n", rx);

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
