#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <setjmp.h>
#include <sched.h>

#include "config.h"

#include "gomod_print/gomod_print.h"

#include <zydis/include/Zydis/Zydis.h>


extern void *func_hook_start, *func_hook_end;
int _gotrace_socket_fd = -1;

int client_socket_loop(void *arg);
unsigned long set_intercept_redirect(void *addr, unsigned long *ptrapaddr);

char *call_data_serializer(const char *dtype, void *addr);

golang_func_t *all_gofuncs = NULL;


typedef struct landing_pad {
	size_t total_alloc;
	size_t total_used;
	void *data;
	struct landing_pad *next;
} landing_pad_t;

landing_pad_t *landing_pads = NULL;


void
sig_handler(int signo, siginfo_t *si, void *ucontext) {
	fprintf(stderr, "gotrace module received signal: %d\n", signo);

	if (signo == SIGSEGV) {
		PRINT_ERROR("%s", "Error: caught SIGSEGV!\n");
//		backtrace_unwind(ucontext);
	}

	_exit(0);
}

char *
call_data_serializer(const char *dtype, void *addr) {
	char *result = NULL;
	size_t i = 0;

	if (!all_gofuncs) {
		PRINT_ERROR("%s", "Error calling golang data serializer; could not locate function table\n");
		return NULL;
	}

	while (all_gofuncs[i].func_name[0]) {

		if (!strcmp(all_gofuncs[i].type_name, dtype)) {
			result = call_gofunc_init(all_gofuncs, all_gofuncs[i].address, 0, 0, addr, NULL);
			break;
		}

		i++;
	}

	return result;
}

size_t
instruction_bytes_needed(void *addr, size_t minsize) {
	ZydisDecoder decoder;
	ZydisDecodedInstruction instruction;
	uint64_t rip = (uint64_t)addr;
	uint8_t *idata = (uint8_t *)addr;
	size_t total = 0, len;

	len = minsize + 16;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	while (total < minsize) {

		if (!ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, idata, len, rip, &instruction))) {
			fprintf(stderr, "Error decoding instruction at %p\n", (void *)rip);
			return 0;
		}

                idata += instruction.length;
                len -= instruction.length;
                rip += instruction.length;
                total += instruction.length;
        }

	return total;
}

#define DEFAULT_ALLOC_SIZE	65536
void *
get_landing_pad(size_t size) {
	landing_pad_t *newlp, *lptr = landing_pads;
	void *buf;

	while (lptr) {

		if ((lptr->total_alloc - lptr->total_used) >= size) {
			void *dptr = lptr->data + lptr->total_used;

			lptr->total_used += size;
			return dptr;
		}

		lptr = lptr->next;
	}

	// Didn't find the free space; will need to allocate more memory.
	lptr = landing_pads;
	while (lptr && lptr->next != NULL)
		lptr = lptr->next;

	if ((buf = mmap(NULL, DEFAULT_ALLOC_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0)) == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}

	if (!(newlp = malloc(sizeof(*newlp)))) {
		perror("malloc");
		return NULL;
	}

	memset(newlp, 0, sizeof(*newlp));
	newlp->data = buf;
	newlp->total_alloc = DEFAULT_ALLOC_SIZE;
	newlp->total_used = size;

	if (!landing_pads)
		landing_pads = newlp;
	else
		lptr->next = newlp;

	return buf;
}

unsigned long
set_intercept_redirect(void *addr, unsigned long *ptrapaddr) {
	static char *landing_code = NULL;
	static size_t landing_size = 0;
	unsigned char *trampoline;
	unsigned long uaddr;
	unsigned long addr_base, page_mask, page_size = 4096;
	size_t to_copy, to_allocate;

	if (!landing_code) {
		landing_size = (unsigned long)&func_hook_end - (unsigned long)&func_hook_start;

		if (!(landing_code = malloc(landing_size))) {
			perror("malloc");
			return 0;
		}

		memcpy(landing_code, &func_hook_start, landing_size);
	}

	page_mask = ~(page_size - 1);
	addr_base = (unsigned long)addr & page_mask;

	if ((mprotect((void *)addr_base, page_size, PROT_READ|PROT_WRITE|PROT_EXEC)) == -1) {
		perror("mprotect");
		return 0;
	}

	if (!(to_copy = instruction_bytes_needed(addr, landing_size)))
		return 0;

	// 2 bytes: trap and return
	to_allocate = to_copy + 2;

	if (!(trampoline = get_landing_pad(to_allocate)))
		return 0;

//	fprintf(stderr, "XXX to copy went from %zu to %zu\n", landing_size, to_copy);
	uaddr = (unsigned long)trampoline;
	memcpy(landing_code+2, &uaddr, sizeof(uaddr));

	*trampoline = 0xcc;
	memcpy(trampoline+1, addr, to_copy);
	trampoline[to_allocate - 1] = 0xc3;

	memset(addr, 0x90, to_copy);
	memcpy(addr, landing_code, landing_size);

	if (ptrapaddr)
		*ptrapaddr = uaddr;

	return (unsigned long)trampoline;
}

static int client_loop_initialized = 0;

int
client_socket_loop(void *arg) {
	int fd = (int)((uintptr_t)arg);
	pid_t tid = gettid();
	int first = 0;

	client_loop_initialized = 1;

	fprintf(stderr, "Loop reading (%d).\n", gettid());
	raise(SIGUSR2);
	fprintf(stderr, "Loop continuing.\n");

	while (1) {
		unsigned char *dbuf;
		size_t dblen;
		int reqtype;

		if (!(dbuf = recv_gt_msg(tid, fd, -1, &dblen, &reqtype, 0, NULL))) {
			PRINT_ERROR("%s", "Client module encountered error.... shutting down\n");
			break;
		}

		fprintf(stderr, "Loop CMD SIZE: %zu bytes / type %u\n", dblen, reqtype);

		if (reqtype == GOMOD_RT_SET_INTERCEPT) {
			unsigned long iret, *addrp, addr_new;

			if (dblen % sizeof(void *)) {
				fprintf(stderr, "Error: Received set intercept request with invalid size (%zu bytes).\n", dblen);
				free(dbuf);
				break;
			}

			fprintf(stderr, "Loop received set intercept request (n=%u).\n", (unsigned int)(dblen / sizeof(void *)));
			addrp = (unsigned long *)dbuf;
			iret = set_intercept_redirect((void *)*addrp, &addr_new);

			if (!iret) {
				fprintf(stderr, "Error: could not create intercept redirection on address %p\n",
					(void *)*addrp);
				addr_new = 0;
			}

			fprintf(stderr, "Loop: intercept on %p -> %p\n",
				(void *)*addrp, (void *)iret);

			memcpy(dbuf, &addr_new, sizeof(addr_new));

			// hdr size stays the same, and of course reqtype too
			if (send_gt_msg(tid, fd, reqtype, dbuf, dblen, first) < 0) {
				fprintf(stderr, "Unexpected error sending back response body data on gotrace control socket.\n");
				free(dbuf);
				break;
			}

			free(dbuf);
		} else if (reqtype == GOMOD_RT_SERIALIZE_DATA) {
			unsigned long *fdata;
			char *sdata, *fname = (char *)dbuf;

			fdata = (unsigned long *)(fname + strlen(fname) + 1);
			fprintf(stderr, "Loop received serialize data request: %s() / %p\n",
				fname, (void *)*fdata);
			if (!(sdata = call_data_serializer(fname, (void *)*fdata))) {
				PRINT_ERROR("Loop encountered unexpected error serializing type data: %s\n", fname);
				free(dbuf);
				break;
			} else {
//				fprintf(stderr, "Loop serialized struct data: [%s]\n", sdata);
				free(dbuf);

				if (send_gt_msg(tid, fd, reqtype, sdata, strlen(sdata), first) < 0) {
					fprintf(stderr, "Unexpected error sending back response body data on gotrace control socket.\n");
					free(sdata);
					break;
				}

				free(sdata);
			}

		}

		first = 0;
        }

	fprintf(stderr, "Loop ending.\n");
	return 0;
}

/*
 * This function takes one parameter:
 * a pointer to the start of the golang function table that the
 * injected module will need to be able to initialize its thread
 * and heap state and call native golang serializer functions.
 * This table is copied over from the heap of the tracing process.
 */
int
_gomod_init(void *data) {
	struct sigaction sa;
	struct sockaddr_un s_un;
	socklen_t ssize;
	char *gotrace_socket_path = NULL;
	int fd;

	fprintf(stderr, "Loop outer (%d) / %p\n", gettid(), data);

	all_gofuncs = data;
/*	while (all_gofuncs[i].func_name[0]) {
		fprintf(stderr, "XXX: client received gofunc table entry %s -> %p\n", all_gofuncs[i].func_name, all_gofuncs[i].address);
		i++;
	}

*/

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_sigaction = sig_handler;
	sa.sa_flags |= SA_SIGINFO;

	if (sigaction(SIGSEGV, &sa, NULL) == -1)
		PERROR("sigaction");

	if (!(gotrace_socket_path = getenv(GOTRACE_SOCKET_ENV))) {
		static char spath[128];

		fprintf(stderr, "Error: could not find gotrace socket path in environment!\n");
		fprintf(stderr, "Trying manual construction of socket path instead...\n");
		snprintf(spath, sizeof(spath), "/tmp/gotrace.sock.%d", getppid());
		gotrace_socket_path = spath;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		fprintf(stderr, "Error: could not create gotrace socket\n");
		return -1;
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, gotrace_socket_path, sizeof (s_un.sun_path));
//	strncpy(s_un.sun_path, "/tmp/blabla.sock", sizeof (s_un.sun_path));
	ssize = offsetof(struct sockaddr_un, sun_path) + strlen(s_un.sun_path);

	if (connect(fd, (struct sockaddr *)&s_un, ssize) == -1) {
		perror("connect");
		fprintf(stderr, "Error: could not connect to gotrace socket listener at %s\n", s_un.sun_path);
		return -1;
	}

	fprintf(stderr, "Loading...\n");

#define NEW_STACK_SIZE (65536*2)
	char *stack;
	int cpid, cflags = CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_VM;

	if ((stack = mmap(NULL, NEW_STACK_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN, 0, 0)) == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	cpid = clone(client_socket_loop, stack+NEW_STACK_SIZE, cflags, (void *)((uintptr_t)fd));
	fprintf(stderr, "clone() returned %d\n", cpid);

/*	while (!client_loop_initialized) {
		int hi = 0;
		hi += 2;
		hi += getpid();
	}*/

	fprintf(stderr, "Client injection module initialization complete.\n");
	return cpid;
}

int somefunc(void) {
	void *addr;
	printf("We are in some func\n");
	addr = dlsym(RTLD_DEFAULT, "main.main");
	printf("addr = %p\n", addr);
	printf("dl error = %s\n", dlerror());
	return 0;
}
