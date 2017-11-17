#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#include "config.h"
#include "gomod_print/gomod_print.h"


/*
type stack struct {
        lo uintptr
        hi uintptr
}*/

typedef struct __attribute__((packed)) {
	uintptr_t lo;
	uintptr_t hi;
} _stack_t;

typedef struct __attribute__((packed)) {
	_stack_t stack;
//	_stack_t *stack;
	uintptr_t stackguard0;
	uintptr_t stackguard1;
	void *_panic;
	void *_defer;
	void *m;
	uintptr_t stackAlloc;
} g_t;

/*type g struct {
        // Stack parameters.
        // stack describes the actual stack memory: [stack.lo, stack.hi).
        // stackguard0 is the stack pointer compared in the Go stack growth prologue.
        // It is stack.lo+StackGuard normally, but can be StackPreempt to trigger a preemption.
        // stackguard1 is the stack pointer compared in the C stack growth prologue.
        // It is stack.lo+StackGuard on g0 and gsignal stacks.
        // It is ~0 on other goroutine stacks, to trigger a call to morestackc (and crash).
        stack       stack   // offset known to runtime/cgo
        stackguard0 uintptr // offset known to liblink
        stackguard1 uintptr // offset known to liblink

        _panic         *_panic // innermost panic - offset known to liblink
        _defer         *_defer // innermost defer
        m              *m      // current m; offset known to arm liblink
        stackAlloc     uintptr // stack allocation is [stack.lo,stack.lo+stackAlloc)
        sched          gobuf
        syscallsp      uintptr        // if status==Gsyscall, syscallsp = sched.sp to use during gc
        syscallpc      uintptr        // if status==Gsyscall, syscallpc = sched.pc to use during gc
        stkbar         []stkbar       // stack barriers, from low to high (see top of mstkbar.go)
        stkbarPos      uintptr        // index of lowest stack barrier not hit
        stktopsp       uintptr        // expected sp at top of stack, to check in traceback
        param          unsafe.Pointer // passed parameter on wakeup
        atomicstatus   uint32
        stackLock      uint32 // sigprof/scang lock; TODO: fold in to atomicstatus
        goid           int64
        waitsince      int64  // approx time when the g become blocked
        waitreason     string // if status==Gwaiting
        schedlink      guintptr
        preempt        bool   // preemption signal, duplicates stackguard0 = stackpreempt
        paniconfault   bool   // panic (instead of crash) on unexpected fault address
        preemptscan    bool   // preempted g does scan for gc
        gcscandone     bool   // g has scanned stack; protected by _Gscan bit in status
        gcscanvalid    bool   // false at start of gc cycle, true if G has not run since last scan
        throwsplit     bool   // must not split stack
        raceignore     int8   // ignore race detection events
        sysblocktraced bool   // StartTrace has emitted EvGoInSyscall about this goroutine
        sysexitticks   int64  // cputicks when syscall has returned (for tracing)
        sysexitseq     uint64 // trace seq when syscall has returned (for tracing)
        lockedm        *m
        sig            uint32
        writebuf       []byte
        sigcode0       uintptr
        sigcode1       uintptr
        sigpc          uintptr
        gopc           uintptr // pc of go statement that created this goroutine
        startpc        uintptr // pc of goroutine function
        racectx        uintptr
        waiting        *sudog // sudog structures this g is waiting on (that have a valid elem ptr)

        // Per-G gcController state

        // gcAssistBytes is this G's GC assist credit in terms of
        // bytes allocated. If this is positive, then the G has credit
        // to allocate gcAssistBytes bytes without assisting. If this
        // is negative, then the G must correct this by performing
        // scan work. We track this in bytes to make it fast to update
        // and check for debt in the malloc hot path. The assist ratio
        // determines how this corresponds to scan work debt.
        gcAssistBytes int64
}
*/

/*type gobuf struct {
        // The offsets of sp, pc, and g are known to (hard-coded in) libmach.
        sp   uintptr
        pc   uintptr
        g    guintptr
        ctxt unsafe.Pointer // this has to be a pointer so that gc scans it
        ret  sys.Uintreg
        lr   uintptr
        bp   uintptr // for GOEXPERIMENT=framepointer
}*/

typedef struct __attribute__((packed)) {
	uintptr_t sp;
	uintptr_t pc;
	uintptr_t g;
	uintptr_t ctxt;
	uintptr_t ret;
	uintptr_t lr;
	uintptr_t bp;
} _gobuf_t;

typedef struct __attribute__((packed)) {
	g_t *g0;
        _gobuf_t morebuf;	// gobuf arg to morestack
	uint32_t divmod;	// div/mod denominator for arm - known to liblink
	uint32_t padding;
	uint64_t procid;
	void *gsignal;
	void *sigmask;
	uintptr_t tls[6];
	void *mstartfn;
	g_t *curg;
	uintptr_t caughtsig;
//	uintptr_t p;
	void *p;
	uintptr_t nextp;
	int32_t id;
	int32_t mallocing;
	int32_t throwing;
	int32_t padding2;
	uintptr_t preemptoff[2];
	int32_t locks;
	int32_t softfloat;
	int32_t dying;
	int32_t profilehz;
	int32_t helpgc;
	uint64_t spinning;
} m_t;

/*
type m struct {
        g0      *g     // goroutine with scheduling stack
        morebuf gobuf  // gobuf arg to morestack
        divmod  uint32 // div/mod denominator for arm - known to liblink

        // Fields not known to debuggers.
        procid        uint64     // for debuggers, but offset not hard-coded
        gsignal       *g         // signal-handling g
        sigmask       sigset     // storage for saved signal mask
        tls           [6]uintptr // thread-local storage (for x86 extern register)
        mstartfn      func()
        curg          *g       // current running goroutine
        caughtsig     guintptr // goroutine running during fatal signal
        p             puintptr // attached p for executing go code (nil if not executing go code)
        nextp         puintptr
        id            int32
        mallocing     int32
        throwing      int32
        preemptoff    string // if != "", keep curg running on this m
        locks         int32
        softfloat     int32
        dying         int32
        profilehz     int32
        helpgc        int32
        spinning      bool // m is out of work and is actively looking for work
        blocked       bool // m is blocked on a note
        inwb          bool // m is executing a write barrier
        newSigstack   bool // minit on C thread called sigaltstack
        printlock     int8
        fastrand      uint32
        ncgocall      uint64 // number of cgo calls in total
        ncgo          int32  // number of cgo calls currently in progress
        park          note
...
};*/

#define SET_WORD(addr,off,val)	do {	\
					*((unsigned long *)(((unsigned char *)addr) + off)) = (unsigned long)val;	\
				} while (0)

void *
fabricate_fs_base(int alloc_new, void **mout) {
	static void *_last = NULL;
	g_t *g;
	m_t *m;
	unsigned char *buf;
#define BSIZE	16384

	if (!alloc_new && _last)
		return _last;

	// Seems like a direct syscall is ultimately less likely to lead to TLS-related instability.
//	if (!(buf = malloc(BSIZE))) {
//		perror("malloc");
//		return NULL;
//	}
	if ((buf = mmap(NULL, BSIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		PERROR("mmap");
		return NULL;
	}

	fprintf(stderr, "+++ malloc = %p\n", buf);
//	memset(buf, 0x41, BSIZE);
	memset(buf, 0, BSIZE);

	g = (g_t *)(buf+4096);
	m = (m_t *)(buf+4096+1024);

	g->m = m;

/*	for (i = 0; i < 16384/8; i++) {
		unsigned long *x;

		x = (unsigned long *)(buf + (i * 8));
//		*x = i*8+0x4900000;
	}*/

	// Points to g area
	SET_WORD((buf+4096), -0x80, g);
	SET_WORD((buf+4096), -0x88, g);

	// Set g->m = m
	g->m = m;
//	SET_WORD(g, 0x30, m);

	// Set m->gsignal = g
//	SET_WORD(m, 0x50, g);

	// Set m->g to point back to g
	m->g0 = g;
//	SET_WORD(m, 0x0, g);

	// Prevent deferproc() from throwing an error?
	m->curg = g;

	m->p = (void *)(((unsigned char *)m)+1024);
//	SET_WORD(m, 168, ((unsigned char *)m)+1024);
	memset(m->p, 0x41, 16);

	// set m.gsignal.stack
	SET_WORD(m, 80, ((unsigned char *)m)+2048);

	// set altstack for sigaltstack()
	SET_WORD(m, 2048, ((unsigned char *)m)+3000);

	// Set m.mstartfn
	m->mstartfn = NULL;
//	SET_WORD(m, 144, 0);

	// Set m.helpgc
//	m->helpgc = 0;
//	SET_WORD(m, 232, 0);

//	m->locks = 0;

	if (mout)
		*mout = m;

	_last = buf + 4096;
	return _last;
}

char *
call_gofunc(void *addr, int set_new_fs, int no_ret, void *param, void **mout) {
	void *new_fs;
	unsigned long saved_fs;
	char *result, *buf;
	unsigned int rlen;

#define arch_prctl(code,addr)	syscall(SYS_arch_prctl, code, addr)
	if (arch_prctl(ARCH_GET_FS, &saved_fs) == -1) {
		perror("arch_prctl(ARCH_GET_FS)");
		return NULL;
	}

	if (!(new_fs = fabricate_fs_base(set_new_fs, mout))) {
		fprintf(stderr, "Error allocating new FS base!\n");
		return NULL;
	}

	fprintf(stderr, "Setting fs = %p / calling %p\n", (void *)new_fs, addr);

	if (arch_prctl(ARCH_SET_FS, new_fs) == -1) {
		perror("arch_prctl(ARCH_SET_FS)");
		return NULL;
	}

	#define PUSHA	"push %%rax;	\
			 push %%rdx;	\
			 push %%rsi;	\
			 push %%rdi;	\
			 push %%rbp;"
	#define POPA	"pop %%rbp;	\
			 pop %%rdi;	\
			 pop %%rsi;	\
			 pop %%rdx;	\
			 pop %%rax;"

/*	asm(PUSHA
		"call *%%rbx;		\
		mov 16(%%rsp), %%rcx;	\
		mov 8(%%rsp), %%rbx;	\
		nop;"
		POPA
		: "=b" (result), "=c" (rlen)
		: "b" (addr)
	);*/
	asm(PUSHA
		"sub $128, %%rsp;	\
		push %%rcx;		\
		call *%%rbx;		\
		pop %%rcx;		\
		add $128, %%rsp;		\
		mov -120(%%rsp), %%rcx;	\
		mov -128(%%rsp), %%rbx;	\
		nop;"
		POPA
		: "=b" (result), "=c" (rlen)
		: "b" (addr), "c" (param)
	);

	if (arch_prctl(ARCH_SET_FS, saved_fs) == -1) {
		perror("arch_prctl(ARCH_SET_FS)");
		return NULL;
	}

	if (no_ret)
		return NULL;

	if (rlen > 10000) {
		return (strdup("ERROR"));
	}

//	fprintf(stderr, "XXX func result: %lx / [%p]\n", (unsigned long)rlen, (void *)result);
//	fprintf(stderr, "XXX func result: %lx / [%s]\n", (unsigned long)rlen, result);

	if (!(buf = malloc(rlen+1))) {
		perror("malloc");
		return NULL;
	}

	memset(buf, 0, rlen+1);
	strncpy(buf, result, rlen);

	return buf;
}

void
diags(void) {
	g_t *g = (g_t *)NULL;
	m_t *m = (m_t *)NULL;

	fprintf(stderr, "g->m = %lx\n", (unsigned long)&(g->m));
	fprintf(stderr, "g->_defer = %lx\n", (unsigned long)&(g->_defer));
	fprintf(stderr, "m->g = %lx\n", (unsigned long)&(m->g0));
	fprintf(stderr, "m->gsignal = %lx / %d\n", (unsigned long)&(m->gsignal), (int)(uintptr_t)&(m->gsignal));
	fprintf(stderr, "m->mstartfn = %lx\n", (unsigned long)(&m->mstartfn));
	fprintf(stderr, "m->p = %lx / %d\n", (unsigned long)&(m->p), (int)(uintptr_t)&(m->p));
	fprintf(stderr, "m->helpgc = %lx / %d\n", (unsigned long)&(m->helpgc), (int)(uintptr_t)(&m->helpgc));
	fprintf(stderr, "m->locks = %lx / %d\n", (unsigned long)(&m->locks), (int)(uintptr_t)(&m->locks));
	return;
}

char *
call_gofunc_by_name_init(golang_func_t *inittable, const char *funcname, int set_new_fs, int no_ret, void *param, void **mout) {
	golang_func_t *initptr = inittable;

	while (initptr->func_name[0]) {

		if (!strcmp(initptr->func_name, funcname))
			return call_gofunc_init(inittable, initptr->address, set_new_fs, no_ret, param, mout);

		initptr++;
	}

	PRINT_ERROR("Error calling go function %s: function could not be found\n", funcname);
	return NULL;
}

char *
call_gofunc_init(golang_func_t *inittable, void *addr, int set_new_fs, int no_ret, void *param, void **mout) {
	m_t *new_m = (void *)0xdeadbeef;
	static int initialized = 0;

	if (!initialized) {

		while (inittable->func_name[0]) {
			void (*ifunc)(void) = (void *)NULL;

			if (!inittable->is_init_func) {
				inittable++;
				continue;
			}

//			fprintf(stderr, "XXX: golang init func: %s\n", inittable->func_name);
			ifunc = inittable->address;

			if (!strcmp(inittable->func_name, "runtime.mcommoninit"))
				call_gofunc(ifunc, 0, 1, (void *)new_m, (void **)&new_m);
			else
				call_gofunc(ifunc, 0, 1, (void *)0xd, (void **)&new_m);

			inittable++;
		}

	}

	initialized = 1;

	if (!addr)
		return NULL;

	return call_gofunc(addr, set_new_fs, no_ret, param, mout);
}

int
setup_gcalling(int argc, char *argv[]) {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;

	if (sigaction(SIGSEGV, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

//	diags();

	return 0;
}
