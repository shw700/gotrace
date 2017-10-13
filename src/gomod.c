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

#include <zydis/include/Zydis/Zydis.h>


extern void *___dlopen_stub;
extern void *func_hook_start, *func_hook_end;
int _gotrace_socket_fd = -1;

void *client_socket_loop(void *arg);
unsigned long set_intercept_redirect(void *addr, unsigned long *ptrapaddr);
int map_stub(void);

char *call_golang_func_by_name(const char *fname, void *param);
char *call_golang_func_str(void *func, void *param);
char *call_data_serializer(const char *dtype, void *addr);


typedef struct landing_pad {
	size_t total_alloc;
	size_t total_used;
	void *data;
	struct landing_pad *next;
} landing_pad_t;

landing_pad_t *landing_pads = NULL;


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

char *
call_data_serializer(const char *dtype, void *addr) {
	golang_serializer_func sfunc;
	unsigned long uaddr = (unsigned long)addr;
	char resbuf[1024];
	char *result;

	memset(resbuf, 0, sizeof(resbuf));
	snprintf(resbuf, sizeof(resbuf), "XXX: %s() / %p", dtype, addr);

	if ((sfunc = get_golang_serializer(dtype))) {
		char *dstr;

		dstr = sfunc(uaddr);
		strncpy(resbuf, dstr, sizeof(resbuf));
	} else
		fprintf(stderr, "Warning: serialization request on unsupported type: %s\n", dtype);

	result = strdup(resbuf);

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

void *
client_socket_loop(void *arg) {
	int fd = (int)((uintptr_t)arg);
	pid_t tid = gettid();

	client_loop_initialized = 1;

	fprintf(stderr, "Loop reading (%u).\n", (unsigned int)syscall(SYS_gettid));
	raise(SIGUSR2);
//	fprintf(stderr, "Loop continuing.\n");

	while (1) {
		unsigned char *dbuf;
		size_t dblen;
		int reqtype;

		fprintf(stderr, "Loop Attempting to read bytes from %d\n", fd);

		dbuf = recv_gt_msg(tid, fd, -1, &dblen, &reqtype);

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
			} else {
				fprintf(stderr, "Loop: intercept on %p -> %p\n",
					(void *)*addrp, (void *)iret);

				memcpy(dbuf, &addr_new, sizeof(addr_new));

				// hdr size stays the same, and of course reqtype too
				if (send_gt_msg(tid, fd, reqtype, dbuf, dblen) < 0) {
					fprintf(stderr, "Unexpected error sending back response body data on gotrace control socket.\n");
					free(dbuf);
					break;
				}

			}

			free(dbuf);
		} else if (reqtype == GOMOD_RT_SERIALIZE_DATA) {
			unsigned long *fdata;
			char *sdata, *fname = (char *)dbuf;

			fdata = (unsigned long *)(fname + strlen(fname) + 1);
//			fprintf(stderr, "Loop received function call request: %s() / %p\n",
//				fname, (void *)*fdata);
			if (!(sdata = call_data_serializer(fname, (void *)*fdata))) {
				fprintf(stderr, "Loop encountered unexpected error serializing function data.\n");
				free(dbuf);
				break;
			} else {
//				fprintf(stderr, "Loop serialized struct data: [%s]\n", sdata);
				free(dbuf);

				if (send_gt_msg(tid, fd, reqtype, sdata, strlen(sdata)) < 0) {
					fprintf(stderr, "Unexpected error sending back response body data on gotrace control socket.\n");
					free(sdata);
					break;
				}

				free(sdata);
			}

		}

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

	fprintf(stderr, "Loop (%lu)\n", syscall(SYS_gettid));
//	char *rx = call_golang_func_str((void *)0x000000000402100, (void *)0xc0debabe);
//	fprintf(stderr, "Loop result heh = %p\n", rx);

/*	sleep(1);
	fprintf(stderr, "XXX trying\n");
	unsigned long taddr;
	unsigned long iret = set_intercept_redirect((void *)0x0000000000402d60, &taddr);
	fprintf(stderr, "XXX: iret = %lx / trapping at %lx\n", iret, taddr);*/

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
