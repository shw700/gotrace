#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>

#include "config.h"


#define MAX_SO_NEEDED	64

#define elf_load_library(dso,fd,dsize,pe,ph,ps)	elf_load_object(dso,fd,dsize,ET_DYN,pe,ph,ps)
#define elf_load_program(dso,fd,dsize,pe,ph,ps)	elf_load_object(dso,fd,dsize,ET_EXEC,pe,ph,ps)


char **strarr_dup(const char **sarray);
void strarr_free(char **sarray);
int strarr_contains(const char **sarray, const char *findstr);

int elf_load_object(const char *dsopath, int *fd, size_t *dsize, int etype,
	Elf64_Ehdr **pehdr, Elf64_Phdr **pphdr, Elf64_Shdr **pshdr);

jmp_buf jb;
void *last_copy_start, *last_copy_end;


int
memcmp_remote(pid_t pid, void *lbuf, void *rbuf, size_t size) {
	void *rdata;
	size_t pctr;
	const unsigned char *p1, *p2;

	if (!(rdata = read_bytes_remote(pid, rbuf, size))) {
		PRINT_ERROR("Error reading remote bytes at %p for comparison\n", rbuf);
		return -1;
	}

	p1 = lbuf;
	p2 = rdata;

	for (pctr = 0; pctr < size; pctr++) {

		if (p1[pctr] != p2[pctr]) {
			PRINT_ERROR("WOW Error: memory regions differ at offset %zu of %zu bytes (%x vs %x)\n",
				pctr, size, p1[pctr], p2[pctr]);
			free(rdata);
			return -1;
		}
	}

	free(rdata);
	return 0;
}

const char *
get_library_abs_path(const char *soname) {
	struct link_map *lm;
	void *dladdr;

	if (strchr(soname, '/'))
		return soname;

	if (!(dladdr = dlopen(soname, RTLD_NOW | RTLD_NOLOAD))) {
		return soname;
	}

	if (dlinfo(dladdr, RTLD_DI_LINKMAP, &lm) == -1) {
		PRINT_ERROR("dlinfo(): %s\n", dlerror());
		return NULL;
	}

	return lm->l_name;
}

int
print_regs(pid_t pid) {
	struct user_regs_struct regs;

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, -1, PT_RETERROR);

	fprintf(stderr, "PID: %d, rip: %p, rax: %p, orig_rax: %p\n", pid, (void *)regs.rip, (void *)regs.rax, (void *)regs.orig_rax);
	fprintf(stderr, "    ++ rdi = %p, rsi = %p, rdx = %p, r10 = %p, r8 = %p, r9 = %p\n",
		(void *)regs.rdi, (void *)regs.rsi, (void *)regs.rdx,
		(void *)regs.r10, (void *)regs.r8, (void *)regs.r9);
	return 0;
}

/*
 * Call a library function in a remote process with the specified parameters,
 * and return the result to the caller.
 */
uintptr_t
call_remote_lib_func(pid_t pid, void *faddr, uintptr_t r1, uintptr_t r2, uintptr_t r3, uintptr_t r4,
		uintptr_t r5, uintptr_t r6, int allow_event) {
	struct user_regs_struct oregs, nregs;
	unsigned long saved_i, call_i;
	unsigned char *iptr;
	int wait_status, err = 0;

	// Step #1. Save the current registers and instruction.
	PTRACE(PTRACE_GETREGS, pid, 0, &oregs, -1, PT_RETERROR);

	PTRACE_PEEK(saved_i, PTRACE_PEEKTEXT, pid, oregs.rip, -1, PT_RETERROR);

	// Step #2. Replace the registers with the function parameters and
	// prime the instruction pointer to call the library function
	memset(&call_i, 0xcc, sizeof(call_i));
	iptr = (unsigned char *)&call_i;
	// What we have is the call to *%rbx followed by a trap landing pad.
	*iptr++ = 0xff;
	*iptr++ = 0xd3;

	PTRACE(PTRACE_POKETEXT, pid, oregs.rip, call_i, -1, PT_RETERROR);

	memcpy(&nregs, &oregs, sizeof(nregs));
	nregs.rdi = r1;
	nregs.rsi = r2;
	nregs.rdx = r3;
	nregs.rcx = r4;
	nregs.r8 = r5;
	nregs.r9 = r6;
	nregs.rbx = (unsigned long)faddr;

	PTRACE(PTRACE_SETREGS, pid, 0, &nregs, -1, PT_RETERROR);

	if (MAGIC_FUNCTION && (void *)MAGIC_FUNCTION == faddr) {
		fprintf(stderr, "Starting trace at magic function: %p\n", faddr);
		trace_forever(pid);
		PRINT_ERROR("%s", "Magic function trace ended... exiting.\n");
		exit(EXIT_SUCCESS);
	}

	// Step #3. Call into the library and wait for the return.
	PTRACE(PTRACE_CONT, pid, NULL, NULL, -1, PT_RETERROR);

	if (waitpid(pid, &wait_status, 0) == -1) {
		perror_pid("waitpid", pid);
		err = 1;
	} else if (!WIFSTOPPED(wait_status) || (WSTOPSIG(wait_status) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		dump_wait_state(pid, wait_status, 1);
		dump_instruction_state(pid);
		err = 1;
	}

	if (allow_event && ((wait_status >> 8) == (SIGTRAP | (allow_event << 8)))) {
		PRINT_ERROR("XXX Detected event %d\n", allow_event);

		PTRACE(PTRACE_CONT, pid, NULL, NULL, -1, PT_RETERROR);

		if (waitpid(pid, &wait_status, 0) == -1) {
			perror_pid("waitpid", pid);
			return -1;
		}
	}

	if (!err && (ptrace(PTRACE_GETREGS, pid, 0, &nregs) == -1)) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		err = 1;
	}

	// Step #4. Restore the original registers and instruction and continue.
	PTRACE(PTRACE_POKETEXT, pid, oregs.rip, saved_i, -1, PT_RETERROR);
	PTRACE(PTRACE_SETREGS, pid, 0, &oregs, -1, PT_RETERROR);

	if (err)
		return -1;

	fprintf(stderr, "+++  Remote library call returning: %llx\n", nregs.rax);

	return nregs.rax;
}

/*
 * Inject a system call into the remote process with the specified parameters,
 * execute it, and return the raw result to the caller.
 */
unsigned long
call_remote_syscall(pid_t pid, int syscall_no, unsigned long r1, unsigned long r2, unsigned long r3,
		unsigned long r4, unsigned long r5, unsigned long r6) {
	unsigned long saved_i, syscall_i;
	unsigned char *iptr;
	struct user_regs_struct oregs, nregs;
	int wait_status, err = 0;

	// Step #1. Save the current registers and instruction.
	PTRACE(PTRACE_GETREGS, pid, 0, &oregs, -1, PT_RETERROR);

	PTRACE_PEEK(saved_i, PTRACE_PEEKTEXT, pid, oregs.rip, -1, PT_RETERROR);

	// Step #2. Replace the registers with syscall parameters and
	// prime the instruction pointer to call the syscall
	memset(&syscall_i, 0xcc, sizeof(syscall_i));
	iptr = (unsigned char *)&syscall_i;
	// What we have is the "syscall" instruction followed by a trap landing pad.
	*iptr++ = 0x0f;
	*iptr++ = 0x05;

	PTRACE(PTRACE_POKETEXT, pid, oregs.rip, syscall_i, -1, PT_RETERROR);

	memcpy(&nregs, &oregs, sizeof(nregs));
	nregs.rax = syscall_no;
	nregs.rdi = r1;
	nregs.rsi = r2;
	nregs.rdx = r3;
	nregs.r10 = r4;
	nregs.r8 = r5;
	nregs.r9 = r6;

	PTRACE(PTRACE_SETREGS, pid, 0, &nregs, -1, PT_RETERROR);

	// Step #3. Run the syscall and get the result.
	// First step into the syscall.
	PTRACE(PTRACE_SYSCALL, pid, NULL, NULL, -1, PT_RETERROR);

	if (waitpid(pid, &wait_status, 0) == -1) {
		perror_pid("waitpid", pid);
		err = 1;
	} else if (!WIFSTOPPED(wait_status) || ((WSTOPSIG(wait_status) & ~0x80) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		err = 1;
	} else if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
		perror_pid("ptrace(PTRACE_SYSCALL)", pid);
		err = 1;
	} else if (waitpid(pid, &wait_status, 0) == -1) {
		perror_pid("waitpid", pid);
		err = 1;
	} else if (!WIFSTOPPED(wait_status) || ((WSTOPSIG(wait_status) & ~0x80) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		err = 1;
	}

	if (!err && (ptrace(PTRACE_GETREGS, pid, 0, &nregs) == -1)) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		err = 1;
	}

	// Step #4. Restore the original registers and instruction and continue.
	PTRACE(PTRACE_POKETEXT, pid, oregs.rip, saved_i, -1, PT_RETERROR);
	PTRACE(PTRACE_SETREGS, pid, 0, &oregs, -1, PT_RETERROR);

	if (err)
		return -1;

//	fprintf(stderr, "+++  Remote syscall returning: %llx\n", nregs.rax);
	return nregs.rax;
}

/*
 * Get the %fs segment base address of a remote process.
 */
unsigned long
get_fs_base_remote(pid_t pid) {
	unsigned long saved_i, syscall_i, fs_result;
	unsigned char *iptr;
	struct user_regs_struct oregs, nregs;
	int wait_status, err = 0;

	// Step #1. Save the current registers and instruction.
	PTRACE(PTRACE_GETREGS, pid, 0, &oregs, -1, PT_RETERROR);
	PTRACE_PEEK(saved_i, PTRACE_PEEKTEXT, pid, oregs.rip, -1, PT_RETERROR);

	// Step #2. Replace the registers with syscall parameters and
	// prime the instruction pointer to call the syscall
	memset(&syscall_i, 0xcc, sizeof(syscall_i));
	iptr = (unsigned char *)&syscall_i;
	// What we have is the "syscall" instruction followed by a trap landing pad.
	*iptr++ = 0x0f;
	*iptr++ = 0x05;

	PTRACE(PTRACE_POKETEXT, pid, oregs.rip, syscall_i, -1, PT_RETERROR);

	memcpy(&nregs, &oregs, sizeof(nregs));
	nregs.rax = SYS_arch_prctl;
//	nregs.rdi = ARCH_SET_FS;
	nregs.rdi = 0x1002;
	nregs.rsi = oregs.rsp - sizeof(void *);

	PTRACE(PTRACE_SETREGS, pid, 0, &nregs, -1, PT_RETERROR);

	// Step #3. Run the syscall and get the result.
	// First step into the syscall.
	PTRACE(PTRACE_SYSCALL, pid, NULL, NULL, -1, PT_RETERROR);

	if (waitpid(pid, &wait_status, 0) == -1) {
		perror_pid("waitpid", pid);
		err = 1;
	} else if (!WIFSTOPPED(wait_status) || ((WSTOPSIG(wait_status) & ~0x80) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		err = 1;
	} else if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
		perror_pid("ptrace(PTRACE_SYSCALL)", pid);
		err = 1;
	} else if (waitpid(pid, &wait_status, 0) == -1) {
		perror_pid("waitpid", pid);
		err = 1;
	} else if (!WIFSTOPPED(wait_status) || ((WSTOPSIG(wait_status) & ~0x80) != SIGTRAP)) {
		PRINT_ERROR("Unexpected error: process %d did not return with trace trap\n", pid);
		err = 1;
	}

	if (!err && (ptrace(PTRACE_GETREGS, pid, 0, &nregs) == -1)) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		err = 1;
	}

	// Step #4. Restore the original registers and instruction and continue.
	PTRACE(PTRACE_POKETEXT, pid, oregs.rip, saved_i, -1, PT_RETERROR);
	PTRACE(PTRACE_SETREGS, pid, 0, &oregs, -1, PT_RETERROR);

	if (err)
		return -1;

	if (nregs.rax != 0) {
		fprintf(stderr, "+++  Remote read fs base returning error: %llx\n", nregs.rax);
		return nregs.rax;
	}

	PTRACE_PEEK(fs_result, PTRACE_PEEKDATA, pid, oregs.rsp - sizeof(void *), -1, PT_RETERROR);
	fprintf(stderr, "+++  Remote read fs base returning: %lx\n", fs_result);

	return fs_result;
}

unsigned long
call_remote_mmap(pid_t pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
        signed long ret;

	ret = call_remote_syscall(pid, SYS_mmap, (unsigned long)addr, length, prot, flags, fd, offset);

	if (ret < 0) {
		errno = -(ret);
		return -1;
	}

	return ret;
}

int
call_remote_mprotect(pid_t pid, void *addr, size_t len, int prot) {
	signed long ret;

	ret = call_remote_syscall(pid, SYS_mprotect, (unsigned long)addr, len, prot, 0, 0, 0);

	if (ret < 0) {
		errno = -(ret);
		return -1;
	}

	return ret;
}

unsigned long
call_remote_shmat(pid_t pid, int shmid, const void *shmaddr, int shmflg) {
	signed long ret;

	ret = call_remote_syscall(pid, SYS_shmat, shmid, (unsigned long)shmaddr, shmflg, 0, 0, 0);

	if (ret < 0) {
		errno = -(ret);
		return -1;
	}

	return ret;
}

void
school_bus(int signo) {
	PRINT_ERROR("Last copy range before signal delivery: %p <-> %p\n",
		last_copy_start, last_copy_end);

	if (signo == SIGBUS) {
		PRINT_ERROR("%s", "Received SIGBUS\n");
		siglongjmp(jb, 666);
	} else
		PRINT_ERROR("Received unexpected signal: %d\n", signo);

	return;
}

void *
get_remote_vma(pid_t pid, unsigned long base, size_t size, int prot, void *fixed) {
	void *vma, *mbase = NULL;
	int map_flags = MAP_ANONYMOUS | MAP_PRIVATE;

	if (fixed) {
		mbase = fixed;
		map_flags |= MAP_FIXED;
	}

	if ((vma = (void *)call_remote_mmap(pid, mbase, size, prot | PROT_WRITE | PROT_READ, map_flags, 0, 0)) == MAP_FAILED) {
		perror_pid("mmap", pid);
		return NULL;
	}

	// XXX: This should probably be working.
//	memset(vma, 0, size);

	fprintf(stderr, "Trying to make remote mmap(): %p to %p (%zu)\n", vma, vma+size, size);

	if (!(prot & PROT_READ)) {
		if (mprotect((void *)base, size, prot|PROT_READ) == -1) {
			PERROR("mprotect");
			return NULL;
		}
	}

	// XXX: restore this?

	if (write_bytes_remote(pid, vma, (void *)base, size) < 0) {
		PRINT_ERROR("%s", "Error copying DSO data to remote buffer\n");
		return NULL;
	}

	if (!(prot & PROT_WRITE)) {
		if (call_remote_mprotect(pid, vma, size, prot) == -1) {
			perror_pid("mprotect", pid);
			return NULL;
		}

	}

	return vma;
}

void *
get_remote_vma_shm(pid_t pid, int shmid, unsigned long base, size_t size, int prot, void *fixed) {
	void *shma, *mbase = NULL;
	int shmflag = 0;

	if (!(prot & PROT_READ))
		shmflag = SHM_RDONLY;

//	if (prot & PROT_EXEC)
//		shmflag = SHM_EXEC;

	if (fixed)
		mbase = fixed;

	if ((shma = (void *)call_remote_shmat(pid, shmid, mbase, shmflag)) == (void *)-1) {
		char errbuf[32];

		snprintf(errbuf, sizeof(errbuf), "shmat(%d) / %x", shmid, prot);
		perror_pid(errbuf, pid);
		return NULL;
	}

	if (prot & PROT_EXEC) {

		if (call_remote_mprotect(pid, mbase, size, prot) == -1) {
			perror_pid("mprotect", pid);
			return NULL;
		}
	}

	if (!(prot & PROT_READ)) {
		if (mprotect((void *)base, size, prot|PROT_READ) == -1) {
			PERROR("mprotect");
			return NULL;
		}
	}

	return shma;
}

void
jmp_memcpy(void *dest, const void *src, size_t n) {
	int failed = 0;

	if (sigsetjmp(jb, 1)) {
		PRINT_ERROR("%s", "Error detected in sigsetjmp\n");
		failed = 1;
	}

	if (!failed) {
		last_copy_start = (void *)src;
		last_copy_end = (void *)src + n;
		memcpy(dest, src, n);
	} else
		PRINT_ERROR("%s", "Recovering from failure.\n");

	return;
}

void *
get_local_vma(unsigned long base, size_t size, int prot, void *fixed) {
	void *vma, *mbase = NULL;
	int failed = 0;
	int map_flags = MAP_ANONYMOUS | MAP_PRIVATE;

	if (fixed) {
		mbase = fixed;
		map_flags |= MAP_FIXED;
	}

	if ((vma = mmap(mbase, size, prot | PROT_WRITE | PROT_READ, map_flags, 0, 0)) == MAP_FAILED) {
		PERROR("mmap");
		return NULL;
	}

	memset(vma, 0, size);

	fprintf(stderr, "Trying local mmap(): %p to %p (%zu)\n", (void *)base, (void *)base+size, size);

	if (!(prot & PROT_READ)) {
		if (mprotect((void *)base, size, prot|PROT_READ) == -1) {
			PERROR("mprotect");
			return NULL;
		}
	}

//	fprintf(stderr, "%s", "memcpy 1\n");

	if (sigsetjmp(jb, 1)) {
		PRINT_ERROR("%s", "Error detected in sigsetjmp\n");
		failed = 1;
	}

	if (!failed) {
		last_copy_start = vma;
		last_copy_end = vma + size;
		memcpy(vma, (void *)base, size);
//		fprintf(stderr, "%s", "memcpy 2\n");
	} else
		PRINT_ERROR("%s", "Recovering from failure.\n");

/*	if (!(prot & PROT_WRITE)) {
		if (mprotect(vma, size, prot) == -1) {
			PERROR("mprotect");
			return NULL;
		}

	}*/

//	fprintf(stderr, "GOT IT (%p)\n", vma);
	return vma;
}

int
elf_load_object(const char *dsopath, int *fd, size_t *dsize, int etype,
		Elf64_Ehdr **pehdr, Elf64_Phdr **pphdr, Elf64_Shdr **pshdr) {
	struct stat sb;
	unsigned char *bindata;

	if ((*fd = open(dsopath, O_RDONLY)) < 0) {
		PERROR("open");
		return -1;
	}

	if (fstat(*fd, &sb) < 0) {
		PERROR("fstat");
		close(*fd);
		return -1;
	}

	if (sb.st_size < sizeof(Elf64_Ehdr)) {
		PRINT_ERROR("File \"%s\" is not large enough to be valid ELF object!\n", dsopath);
		close(*fd);
		return -1;
	}

	*dsize = sb.st_size;

	if ((bindata = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, *fd, 0)) == MAP_FAILED) {
		PERROR("mmap");
		close(*fd);
		return -1;
	}

	*pehdr = (Elf64_Ehdr *)bindata;

	if (memcmp((*pehdr)->e_ident, ELFMAG, SELFMAG)) {
		PRINT_ERROR("File \"%s\" does not appear to be a valid ELF object!\n", dsopath);
		goto errout;
	} else if ((*pehdr)->e_ident[EI_CLASS] != ELFCLASS64) {
		PRINT_ERROR("File \"%s\" does not appear to be a 64 bit ELF object!\n", dsopath);
		goto errout;
	} else if ((*pehdr)->e_ident[EI_VERSION] != EV_CURRENT) {
		PRINT_ERROR("File \"%s\" contained unexpected ELF header version!\n", dsopath);
		goto errout;
	} else if ((*pehdr)->e_type != etype) {
		PRINT_ERROR("File \"%s\" did not match expected ELF object type!\n", dsopath);
		goto errout;
	} else if ((*pehdr)->e_machine != EM_X86_64) {
		PRINT_ERROR("File \"%s\" was not for a supported architecture (X86_64)!\n", dsopath);
		goto errout;
	}

	if ((*pehdr)->e_shentsize != sizeof(Elf64_Shdr)) {
		PRINT_ERROR("File \"%s\" contained unexpected section header size!\n", dsopath);
		goto errout;
	} else if (((*pehdr)->e_shoff + (*pehdr)->e_shnum * (*pehdr)->e_shentsize) > sb.st_size) {
		PRINT_ERROR("File \"%s\" contained a section header table that was out of bounds!\n", dsopath);
		goto errout;
	} else if (((*pehdr)->e_phoff + (*pehdr)->e_phnum * (*pehdr)->e_phentsize) > sb.st_size) {
		PRINT_ERROR("File \"%s\" contained a program header table that was out of bounds!\n", dsopath);
		goto errout;
	}

	*pphdr = (Elf64_Phdr *)(bindata + (*pehdr)->e_phoff);
	*pshdr = (Elf64_Shdr *)(bindata + (*pehdr)->e_shoff);
	return 0;

errout:
	munmap(bindata, sb.st_size);
	close(*fd);
	return -1;
}

char **
strarr_dup(const char **sarray) {
	const char **sptr = sarray;
	char **result;
	size_t i, rlen, nents = 0;

	while (*sptr) {
		nents++;
		sptr++;
	}

	rlen = sizeof(char *) * (nents + 1);

	if (!(result = malloc(rlen))) {
		PERROR("malloc");
		return NULL;
	}

	memset(result, 0, rlen);

	for (i = 0; i < nents; i++) {
		result[i] = strdup(sarray[i]);

		if (!result[i]) {
			PERROR("strdup");
			free(result);
			return NULL;
		}

	}

	return result;
}

void
strarr_free(char **sarray) {
	char **sptr = sarray;

	if (!sarray)
		return;

	while (*sptr) {
		free(*sptr);
		*sptr = NULL;
		sptr++;
	}

	free(sarray);
	return;
}

int
strarr_contains(const char **sarray, const char *findstr) {
	const char **sptr = sarray;

	if (!sarray)
		return 0;

	while (*sptr) {

		if (!strcmp(*sptr, findstr))
			return 1;

		sptr++;
	}

	return 0;
}

char **
get_all_so_needed(const char *dsopath, char **curdeps) {
	char *needed[MAX_SO_NEEDED+1];
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Dyn *dyn = NULL;
	unsigned char *bindata, *strtab = NULL;
	char **result = NULL;
	size_t fsize, i, dind = 0;//, strtab_size = 0;
	int fd;

//	dsopath = get_library_abs_path(dsopath);
	if (!strchr(dsopath, '/')) {
		struct link_map *lm;
		void *dladdr;

//		fprintf(stderr, "XXX: looking up relative path: %s\n", dsopath);

		if (!(dladdr = dlopen(dsopath, RTLD_NOW))) {
			PRINT_ERROR("dlopen(): %s\n", dlerror());
			NULL;
		}

		if (dlinfo(dladdr, RTLD_DI_LINKMAP, &lm) == -1) {
			PRINT_ERROR("dlinfo(): %s\n", dlerror());
			NULL;
		}

//		fprintf(stderr, "XXX: got it: [%s]\n", lm->l_name);
		dsopath = lm->l_name;
	}


	if (elf_load_library(dsopath, &fd, &fsize, &ehdr, &phdr, &shdr) < 0) {
		PRINT_ERROR("%s", "Error looking up shared object dependencies\n");
		return NULL;
	}

	bindata = (unsigned char *)ehdr;
	memset(&needed, 0, sizeof(needed));

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_STRTAB) {
//			printf("XXX: STR Section header %zu: type %u, size %lu\n", i+1, shdr[i].sh_type, shdr[i].sh_size);
			// XXX: BAD
//			if (shdr[i].sh_size > strtab_size) {
			if (!strtab) {
				strtab = (void *)(bindata + shdr[i].sh_offset);
//				strtab_size = shdr[i].sh_size;
			}

		} else if (shdr[i].sh_type == SHT_DYNAMIC)
			dyn = (Elf64_Dyn *)(bindata + shdr[i].sh_offset);
	}

	if (!dyn) {
		PRINT_ERROR("Error: could not find dynamic section of soname: %s\n", dsopath);
		goto out;
	} else if (!strtab) {
		PRINT_ERROR("Error: could not find string table in soname: %s\n", dsopath);
		goto out;
	}

	while (dyn->d_tag != DT_NULL) {
		switch(dyn->d_tag) {
			case DT_NEEDED:
			case DT_INIT:
			case DT_FINI:
			case DT_SONAME:
			case DT_INIT_ARRAY:
			case DT_FINI_ARRAY:
			case DT_INIT_ARRAYSZ:
			case DT_FINI_ARRAYSZ:
				break;
			default:
				dyn++;
				continue;
				break;
		}

//		if (dyn->d_tag != DT_NEEDED)
//			fprintf(stderr, "DYNAMIC: %lu -> %lu\n", dyn->d_tag, dyn->d_un.d_val);

		if (dyn->d_tag == DT_NEEDED) {
//			PRINT_ERROR("STR: [%s]\n", strtab+dyn->d_un.d_val);

			if (dind < MAX_SO_NEEDED) {
				needed[dind] = (char *)strtab + dyn->d_un.d_val;
				dind++;
			}
		}

		dyn++;
	}

	// Remove any of the found dependencies that were already tracked by curdeps.
	if (curdeps) {

		i = 0;
		while (needed[i]) {
			char **cptr = curdeps;

			while (*cptr) {
				if (!strcmp(*cptr, needed[i])) {
					size_t nleft = sizeof(needed) - (sizeof(needed[0]) * (i + 1));
//fprintf(stderr, "XXX needed: [%s] / %zu of %zu\n", *cptr, nleft, sizeof(needed));
					memmove(&(needed[i]), &(needed[i+1]), nleft);
					i--;
					break;
				}

				cptr++;
			}

			i++;
		}

	}

	if (!needed[0])
		goto out;

	i = 0;
	while (needed[i]) {
		char **rneeded, **rptr;

		rptr = rneeded = get_all_so_needed(needed[i], needed);
//		fprintf(stderr, "rneeded = %p (%s)\n", rneeded, needed[i]);

		if (rptr) {
			while (*rptr) {
//				PRINT_ERROR("- RN on %s: [%s]\n", needed[i], *rptr);

				if (!strarr_contains((const char **)needed, *rptr)) {
					if (dind == MAX_SO_NEEDED)
						PRINT_ERROR("%s", "Warning: detected new SO dependency but maximum number entries in use.\n");
					else {
						size_t to_copy = sizeof(needed) - (sizeof(needed[0]) * 2);

						memmove(&(needed[1]), &needed[0], to_copy);

						if (!(needed[0] = strdup(*rptr))) {
							PERROR("malloc");
							strarr_free(rneeded);
							goto out;
						}

						dind++;
					}

				}

				rptr++;
			}

			strarr_free(rneeded);
		}

		i++;
	}

	i = 0;
	while (needed[i])
		i++;

	result = strarr_dup((const char **)needed);

out:
	munmap(ehdr, fsize);
	close(fd);
	return result;
}

size_t
elf_read_vaddr(unsigned char *bindata, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, void *base_addr, size_t reqsize) {
	size_t offset = 0;

	while (phdr->p_type != PT_NULL) {
		size_t file_offset;

		if (phdr->p_type != PT_LOAD) {
			phdr++;
			continue;
		}

		if (!((base_addr >= (void *)phdr->p_vaddr) && (base_addr <= (void *)phdr->p_vaddr+phdr->p_memsz))) {
			phdr++;
			continue;
		}

		if ((base_addr + reqsize) > (void *)(phdr->p_vaddr + phdr->p_memsz)) {
			PRINT_ERROR("Virtual memory area %p:%zu would be fall out of bounds loaded program segment %p <-> %p\n",
				base_addr, reqsize, (void *)phdr->p_vaddr, (void *)(phdr->p_vaddr + phdr->p_memsz));
			return 0;
		}

//		PRINT_ERROR("PROGRAM HDR: %p -> %p (%lu)\n", (void *)phdr->p_vaddr, (void *)phdr->p_vaddr+phdr->p_memsz, phdr->p_memsz);
		file_offset = phdr->p_offset + (unsigned long)base_addr - phdr->p_vaddr;
		return file_offset;
	}

	return offset;
}

/*
type _func struct {
        entry   uintptr // start pc
        nameoff int32   // function name

        args int32 // in/out args size
        _    int32 // previously legacy frame size; kept for layout compatibility

        pcsp      int32
        pcfile    int32
        pcln      int32
        npcdata   int32
        nfuncdata int32
}
*/

typedef struct __attribute__((packed)) {
	void *entry;
	uint32_t nameoff;
	uint32_t args;
	uint32_t legacy;
	uint32_t pcsp;
	uint32_t pcfile;
	uint32_t pcln;
	uint32_t npcdata;
	uint32_t nfuncdata;
} _func_t;

/*
type moduledata struct {
        pclntable    []byte
        ftab         []functab
        filetab      []uint32
        findfunctab  uintptr
        minpc, maxpc uintptr

        text, etext           uintptr
        noptrdata, enoptrdata uintptr
        data, edata           uintptr
        bss, ebss             uintptr
        noptrbss, enoptrbss   uintptr
        end, gcdata, gcbss    uintptr

        typelinks []*_type

        modulename   string
        modulehashes []modulehash

        gcdatamask, gcbssmask bitvector

        next *moduledata
}*/

/*
type slice struct {
	array unsafe.Pointer
	len   int
	cap   int
}*/

#define SLICE_SZ_W	3
#define STRING_SZ_W	2
#define SL_IND_PTR	0
#define SL_IND_SZ	1

typedef struct __attribute__((packed)) {
	unsigned long pclntable[SLICE_SZ_W];
	unsigned long ftab[SLICE_SZ_W];
	unsigned long filetab[SLICE_SZ_W];
	void *findfunctab;
	void *minpc, *maxpc;
	void *text, *etext;
	void *noptrdata, *enoptrdata;
	void *data, *edata;
	void *bss, *ebss;
	void *noptrbss, *enoptrbss;
	void *end, *gcdata, *gcbss;
	unsigned long typelinks[SLICE_SZ_W];
	unsigned long modulename[STRING_SZ_W];
	unsigned long modulehashes[SLICE_SZ_W];
} moduledata_t ;

/*
type findfuncbucket struct {
	idx        uint32
	subbuckets [16]byte
}
*/

typedef struct __attribute__((packed)) {
	uint32_t idx;
	unsigned char subbuckets[16];
} findfuncbucket_t;

/*func readvarint(p []byte) (newp []byte, val uint32) {
        var v, shift uint32
        for {
                b := p[0]
                p = p[1:]
                v |= (uint32(b) & 0x7F) << shift
                if b&0x80 == 0 {
                        break
                }
                shift += 7
        }
        return p, v
}*/

uint32_t readvarint(void *ptr, void **pnext) {
	unsigned char *bptr, *p;
	uint32_t v = 0, shift = 0;

	p = bptr = (unsigned char *)ptr;

	while (1) {
		unsigned char b;

		b = p[0];
		p++;
		v |= ((uint32_t)b & 0x7f) << shift;

		if (!(b & 0x80))
			break;

		shift += 7;
	}

	*pnext = p;
	return v;
}

int
get_pcdata(const char *dsopath, void *base_addr, symbol_mapping_t *symmap, size_t mapsize) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	moduledata_t md;
	unsigned char *bindata;
	unsigned long preamble[10];
	unsigned long pclntab_addr, filetab_addr, strtab_addr;
	unsigned long functab_off, pclntab_off, filetab_off, strtab_off, findfunctab_off;
	size_t fsize, i, file_offset, fntab_size, filetab_size;
	int fd, result = -1;

	if (elf_load_program(dsopath, &fd, &fsize, &ehdr, &phdr, &shdr) < 0) {
		PRINT_ERROR("%s", "Error looking up PCDATA table\n");
		return -1;
	}

	bindata = (unsigned char *)ehdr;

	if (!(file_offset = elf_read_vaddr(bindata, ehdr, phdr, base_addr, 0))) {
		PRINT_ERROR("Error reading program firstmoduledata at virtual address: %p\n", base_addr);
		goto out;
	}

	memcpy(&md, bindata + file_offset, sizeof(md));
	memcpy(&preamble, &md, sizeof(preamble));
	pclntab_addr = md.pclntable[SL_IND_PTR];
	fntab_size = md.ftab[SL_IND_SZ];
	filetab_addr = md.filetab[SL_IND_PTR];
	filetab_size = md.filetab[SL_IND_SZ];
	strtab_addr = filetab_addr + (filetab_size * sizeof(uint32_t));

	if (!(functab_off = elf_read_vaddr(bindata, ehdr, phdr, (void *)preamble[3], fntab_size))) {
		PRINT_ERROR("Error reading program functab at virtual address: %p\n", (void *)preamble[3]);
		goto out;
	}

	if (!(pclntab_off = elf_read_vaddr(bindata, ehdr, phdr, (void *)pclntab_addr, md.pclntable[SL_IND_SZ]))) {
		PRINT_ERROR("Error reading program pclntab at virtual address: %p\n", (void *)pclntab_addr);
		goto out;
	}

	if (!(filetab_off = elf_read_vaddr(bindata, ehdr, phdr, (void *)filetab_addr, filetab_size))) {
		PRINT_ERROR("Error reading program filetab at virtual address: %p\n", (void *)filetab_addr);
		goto out;
	}

	if (!(strtab_off = elf_read_vaddr(bindata, ehdr, phdr, (void *)strtab_addr, 0))) {
		PRINT_ERROR("Error reading program strtab at virtual address: %p\n", (void *)strtab_addr);
		goto out;
	}

	if (!(findfunctab_off = elf_read_vaddr(bindata, ehdr, phdr, md.findfunctab, 0))) {
		PRINT_ERROR("Error reading program findfunctab at virtual address: %p\n", md.findfunctab);
		goto out;
	}

//	PRINT_ERROR("Found a total of %zu entries in fntab\n", fntab_size);

	memcpy(&preamble, bindata + functab_off, sizeof(preamble));

/*	type functab struct {
		entry   uintptr
		funcoff uintptr
	}*/

	for (i = 0; i < fntab_size; i++) {
		_func_t *fptr;
		unsigned char *funcptr;
		unsigned long *tabentry;
		size_t j;

		tabentry = (unsigned long *)(bindata + functab_off + (i * sizeof(void *) * 2));
//		fprintf(stderr, "%zu: %p | %p\n", i, (void *)tabentry[0], (void *)tabentry[1]);

		for (j = 0; j < mapsize; j++) {
			if (symmap[j].addr == tabentry[0])
				break;
		}

		if (j == mapsize) {
			PRINT_ERROR("Warning: found pctab entry for PC value %p but could not map it to a symbol!\n",
				(void *)tabentry[0]);
//			continue;
		}

		funcptr = (unsigned char *)bindata + pclntab_off + tabentry[1];
		fptr = (_func_t *)funcptr;

		if (fptr->entry != (void *)tabentry[0]) {
			PRINT_ERROR("Warning: mismatched function entry (expected %p; got %p)\n",
				(void *)tabentry[0], fptr->entry);
		} else {
//			fprintf(stderr, "Value at offset (%lu): %p; nameoff = %u, args = %u, legacy = %x, pcfile = %x/%u (0x%lx), pcln = %x/%u (0x%lx), npcdata = %u, nfuncdata = %u / [%s]\n",
//				tabentry[1], fptr->entry, fptr->nameoff, fptr->args, fptr->legacy, fptr->pcfile, fptr->pcfile, pclntab_addr+fptr->pcfile, fptr->pcln, fptr->pcln, pclntab_addr+fptr->pcln, fptr->npcdata, fptr->nfuncdata,
//				(bindata + pclntab_off + fptr->nameoff));
			symmap[j].argsize = fptr->args;

			void *nextf, *nextl, *pfile, *pln;
			uint32_t ifile, iln;
			pfile = bindata + pclntab_off + fptr->pcfile;
			pln = bindata + pclntab_off + fptr->pcln;
			ifile = readvarint(pfile, &nextf);
			iln = readvarint(pln, &nextl);
			uint32_t find = (ifile / 2) - 1;
			uint32_t *ftp;

			ftp = (uint32_t *)(bindata + filetab_off + (find * sizeof(uint32_t)));
//			fprintf(stderr, "----------- OK: %s: file: %p, %u / line: %p, %u\n", (bindata + pclntab_off + fptr->nameoff), nextf, ifile, nextl, iln);

			if (fptr->pcfile && fptr->pcln) {
				char *fname, *fname_short;

#define FNAME_TRUNC_MARKER	"/src/"
				fname = (char *)(bindata + pclntab_off + *ftp);
				fname_short = strstr(fname, FNAME_TRUNC_MARKER);

				if (!fname_short)
					fname_short = fname;
				else
					fname_short += strlen(FNAME_TRUNC_MARKER);

//				fprintf(stderr, "----------- OK: %s: file: %u / line: %u / %s\n",
//					(bindata + pclntab_off + fptr->nameoff), find, iln, fname);

				// XXX: this is a lot of unnecessary duplication... should be fixed.
				symmap[j].fname = strdup(fname_short);
				symmap[j].lineno = iln;
			}

		}

	}

/*
	for (i = 0; i < filetab_size; i++) {
		uint32_t *ftp = (uint32_t *)(bindata + filetab_off + (i * sizeof(uint32_t)));
		fprintf(stderr, "XXX filetab %zu: %x (%u) / %s\n", i, *ftp, *ftp, (bindata + pclntab_off + *ftp));
	}

	size_t nbuckets = ((unsigned long)md.etext + 4095 - (unsigned long)md.text) / 4096;
//	fprintf(stderr, "start of strtab = %s\n", (bindata + strtab_off));
//	fprintf(stderr, "md text from %p <-> %p (%lu bytes)\n", md.text, md.etext, (unsigned long)md.etext-(unsigned long)md.text);
//	fprintf(stderr, "nbuckets = %zu\n", nbuckets);

	for (i = 0; i < nbuckets; i++) {
//		findfuncbucket_t *fb = (findfuncbucket_t *)(bindata + findfunctab_off + (i * sizeof(findfuncbucket_t)));
		unsigned long pc_start, pc_end;

		pc_start = (unsigned long)md.text + (i * 4096);
		pc_end = pc_start + 4096;

		if (pc_end > (unsigned long)md.maxpc)
			pc_end = (unsigned long)md.maxpc;

		pc_start -= (unsigned long)md.minpc;
		pc_end -= (unsigned long)md.minpc;
//		PRINT_ERROR("XXX bucket %zu: %u: %lx <-> %lx\n", i, fb->idx, pc_start, pc_end);
	}

//	fprintf(stderr, "minpc = %p, maxpc = %p\n", md.minpc, md.maxpc);
*/

	result = 0;

out:
	munmap(bindata, fsize);
	close(fd);

	return result;
}

/*
 * If an entry point can be found in the shared library's dynamic section,
 * return it as the result - or NULL otherwise.
 *
 * init_arr is an optional pointer that will will receive an allocated
 * array of initialization pointers as specified by the INIT_ARRAY section,
 * if it exists and is populated with non-NULL pointers.
 * The final entry in this returned list is NULL. The caller must deallocate.
 */
void *
get_entry_point(const char *dsopath, void ***init_arr) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Dyn *dyn = NULL;
	void *result = NULL;
	unsigned char *bindata;
	unsigned long init_array_vaddr = 0;
	size_t fsize, i, j, nfuncs = 0;
	int fd;

	dsopath = get_library_abs_path(dsopath);

	if (elf_load_library(dsopath, &fd, &fsize, &ehdr, &phdr, &shdr) < 0) {
		PRINT_ERROR("%s", "Error looking up shared object dependencies\n");
		return NULL;
	}

	bindata = (unsigned char *)ehdr;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_DYNAMIC) {
			dyn = (Elf64_Dyn *)(bindata + shdr[i].sh_offset);
			break;
		}

	}

	if (!dyn) {
		PRINT_ERROR("Error: could not find dynamic section of soname: %s\n", dsopath);
		goto out;
	}

	while (dyn->d_tag != DT_NULL) {
		switch(dyn->d_tag) {
			case DT_INIT:
				result = (void *)dyn->d_un.d_val;
				break;
			case DT_INIT_ARRAY:
				init_array_vaddr = dyn->d_un.d_val;
				break;
			case DT_INIT_ARRAYSZ:

				if (dyn->d_un.d_val % sizeof(void *))
					PRINT_ERROR("Section advertised improperly aligned size: %lu\n", shdr[i].sh_size);
				else
					nfuncs = dyn->d_un.d_val / sizeof(void *);

				break;
			default:
				break;
		}

//		fprintf(stderr, "XXX DYNAMIC section (%s): %lu -> 0x%lx\n", dsopath, dyn->d_tag, dyn->d_un.d_val);
		dyn++;
	}

	if (init_arr && nfuncs && init_array_vaddr) {
		unsigned long ia_off, *funcptr;

		if (!(ia_off = elf_read_vaddr(bindata, ehdr, phdr, (void *)init_array_vaddr, (nfuncs * sizeof(void *)))))
			PRINT_ERROR("Error reading contents of INIT_ARRAY at virtual address: %p\n", (void *)init_array_vaddr);
		else {
			if (!(*init_arr = malloc(sizeof(void *) * (nfuncs+1)))) {
				PERROR("malloc");
				result = NULL;
				goto out;
			}

			memset(*init_arr, 0, sizeof(void *) * (nfuncs + 1));
			funcptr = (unsigned long *)(bindata + ia_off);

			for (i = 0, j = 0; i < nfuncs; i++) {
				if (funcptr[i])
					(*init_arr)[j++] = (void *)funcptr[i];
			}

		}

	}

out:
	munmap(bindata, fsize);
	close(fd);
	return result;
}

int check_mapped(void *addr) {
	static void *mapped_addrs[1024];
	static size_t nmapped;
	size_t i;

	for (i = 0; i < nmapped; i++) {
		if (mapped_addrs[i] == addr)
			return 1;
	}

	mapped_addrs[nmapped] = addr;
	nmapped++;
	return 0;
}


typedef struct vmap_region {
	unsigned long start;
	unsigned long end;
	int prot;
	char *objname;
	void *new_base;
	key_t shmk;
	int shmid;
} vmap_region_t;

#define MAX_VMA 16

#define DESTROY_VMAP(vmaps,n)	do {	\
					size_t i;	\
					for (i = 0; i < n; i++) {	\
						if (vmaps[i].objname) {	\
							free(vmaps[i].objname);	\
							vmaps[i].objname = NULL;	\
						}	\
					}	\
				} while (0)


int
open_dso_and_get_segments(const char *soname, pid_t pid, void **pinit_func, void **reloc_base, int open_all) {
	vmap_region_t vmas[MAX_VMA];
	FILE *f;
	void *dladdr;
	char realname[PATH_MAX+1];
	size_t vind = 0, i;
	int no_load = 0;

	signal(SIGBUS, school_bus);

	memset(realname, 0, sizeof(realname));

	if (!strchr(soname, '/')) {
		struct link_map *lm;

		if (!(dladdr = dlopen(soname, RTLD_NOW | RTLD_NOLOAD))) {
			PRINT_ERROR("dlopen(): %s\n", dlerror());
			return -1;
		}

		if (dlinfo(dladdr, RTLD_DI_LINKMAP, &lm) == -1) {
			PRINT_ERROR("dlinfo(): %s\n", dlerror());
			return -1;
		}

		soname = lm->l_name;
		no_load = 1;
	}

	if (!(realpath(soname, realname))) {
		PERROR("realpath");
		return -1;
	}

//	PRINT_ERROR("REAL NAME: [%s]\n", realname);

	if (!no_load && (!(dladdr = dlopen(realname, RTLD_NOW | RTLD_DEEPBIND)))) {
		PRINT_ERROR("dlopen(): %s\n", dlerror());
		return -1;
	}

	if (reloc_base) {
		struct link_map *lm;

		if (dlinfo(dladdr, RTLD_DI_LINKMAP, &lm) == -1) {
			PRINT_ERROR("dlinfo(): %s\n", dlerror());
			return -1;
		}

		*reloc_base = (void *)lm->l_addr;
	}

	if (pinit_func)
		*pinit_func = dlsym(dladdr, GOMOD_INIT_FUNC);

	if ((f = fopen("/proc/self/maps", "r")) == NULL) {
		perror_pid("fopen(/proc/self/maps", 0);
		return -1;
	}

	memset(vmas, 0, sizeof(vmas));

	char last_named[256];
	memset(last_named, 0, sizeof(last_named));

	while (!feof(f)) {
		unsigned long start, end;
		char mline[512], *hyph;
		char *tok, *range, *perms, *foffset, *objname;
		int err = 0;

		memset(mline, 0, sizeof(mline));

		if (!fgets(mline, sizeof(mline), f))
			break;
		else if (!mline[0])
			continue;

		mline[strlen(mline)-1] = 0;

		if (!(range = tok = strtok(mline, " ")))
			continue;

		if (!(perms = tok = strtok(NULL, " ")))
			continue;

		if (!(foffset = tok = strtok(NULL, " ")))
			continue;

		if ((!strtok(NULL, " ")) || (!strtok(NULL, " ")))
			continue;

		if ((!(objname = tok = strtok(NULL, " "))) && !open_all) {

			if (strstr(last_named, "libc")) {
				memset(last_named, 0, sizeof(last_named));
			} else {
				memset(last_named, 0, sizeof(last_named));
				continue;
			}

		}

		if (objname && *objname) {
			strncpy(last_named, objname, sizeof(last_named));

			if (*objname != '/')
				continue;
			else if (strcmp(objname, realname))
				continue;
		}

		if (!(hyph = strchr(range, '-')))
			continue;

		*hyph++ = 0;

		errno = 0;
		start = strtoul(range, NULL, 16);

		if (errno)
			err = 1;
		else {
			errno = 0;
			end = strtoul(hyph, NULL, 16);

			if (errno)
				err = 1;
		}

		if (err)
			continue;

//		check_mapped((void *)start);

		fprintf(stderr, "Range: [%lx to %lx], perms: [%s], offset: [%s], name: [%s]\n", start, end, perms, foffset, objname);

		vmas[vind].start = start;
		vmas[vind].end = end;
		vmas[vind].prot = 0;

		if (strchr(perms, 'r'))
			vmas[vind].prot |= PROT_READ;
		if (strchr(perms, 'w'))
			vmas[vind].prot |= PROT_WRITE;
		if (strchr(perms, 'x'))
			vmas[vind].prot |= PROT_EXEC;

		vind++;

		if (vind == MAX_VMA) {
			PRINT_ERROR("%s", "Unexpected high number of mapped virtual memory areas; exiting scan.\n");
			break;
		}

	}

	for (i = 0; i < vind; i++) {
		void *v;

		fprintf(stderr, "HEH: %lx -> %lx\n", vmas[i].start, vmas[i].end);
		v = get_local_vma(vmas[i].start, vmas[i].end-vmas[i].start, vmas[i].prot, NULL);
		vmas[i].new_base = v;
		PRINT_ERROR("v = %p\n", v);
	}

//	if (dlclose(dladdr) == -1)
//		PRINT_ERROR("dlclose(): %s\n", dlerror());

	for (i = 0; i < vind; i++) {
		void *v2;

		fprintf(stderr, "NOW: %p\n", vmas[i].new_base);
		v2 = get_remote_vma(pid, (unsigned long)vmas[i].new_base, vmas[i].end-vmas[i].start, vmas[i].prot, (void *)vmas[i].start);
		PRINT_ERROR("v2 = %p\n", v2);
	}

/*	if (strstr(soname, "libc")) {
		for (i = 0; i < vind; i++) {
			fprintf(stderr, "XXX: %p <-> %p\n", (void *)vmas[i].start, (void *)vmas[i].end);
			fprintf(stderr, "XXX: %d\n", memcmp_remote(pid, (void *)vmas[i].start, vmas[i].end-vmas[i].start, 0));
		}
	}*/


	return 0;
}

int
parse_process_maps(pid_t pid, vmap_region_t *vmas, size_t nvmas) {
	FILE *f;
	char mappath[32];
	size_t vind = 0;

	snprintf(mappath, sizeof(mappath), "/proc/%d/maps", pid);

	if ((f = fopen(mappath, "r")) == NULL) {
		perror_pid("fopen(/proc/pid/maps", 0);
		return -1;
	}

	memset(vmas, 0, (sizeof(vmap_region_t) * nvmas));

	while (!feof(f)) {
		unsigned long start, end;
		char mline[512], *hyph;
		char *tok, *range, *perms, *foffset, *objname;
		int err = 0;

		memset(mline, 0, sizeof(mline));

		if (!fgets(mline, sizeof(mline), f))
			break;
		else if (!mline[0])
			continue;

		mline[strlen(mline)-1] = 0;

		if (!(range = tok = strtok(mline, " ")))
			continue;

		if (!(perms = tok = strtok(NULL, " ")))
			continue;

		if (!(foffset = tok = strtok(NULL, " ")))
			continue;

		if ((!strtok(NULL, " ")) || (!strtok(NULL, " ")))
			continue;

		objname = tok = strtok(NULL, " ");

		if (!(hyph = strchr(range, '-')))
			continue;

		*hyph++ = 0;

		errno = 0;
		start = strtoul(range, NULL, 16);

		if (errno)
			err = 1;
		else {
			errno = 0;
			end = strtoul(hyph, NULL, 16);

			if (errno)
				err = 1;
		}

		if (err)
			continue;

		vmas[vind].start = start;
		vmas[vind].end = end;
		vmas[vind].prot = 0;
		vmas[vind].objname = objname ? strdup(objname) : NULL;

		if (strchr(perms, 'r'))
			vmas[vind].prot |= PROT_READ;
		if (strchr(perms, 'w'))
			vmas[vind].prot |= PROT_WRITE;
		if (strchr(perms, 'x'))
			vmas[vind].prot |= PROT_EXEC;

		vind++;

		if (vind >= (nvmas - 1)) {
			char execbuf[32];

			PRINT_ERROR("%s", "Unexpected high number of mapped virtual memory areas; exiting scan.\n");
			fclose(f);
			sprintf(execbuf, "cat /proc/%d/maps", pid);
			system(execbuf);
			return 1;
		}

	}

	return 0;
}

#define MAX_REPLICATE_VMA	96

int
replicate_process_remotely(pid_t pid, int **shmids) {
	char exename[PATH_MAX+1], exelookup[64];
	vmap_region_t vmas[MAX_REPLICATE_VMA+1];
	size_t i = 0, j;

	memset(exename, 0, sizeof(exename));
	snprintf(exelookup, sizeof(exelookup), "/proc/self/exe");

	if (!(realpath(exelookup, exename))) {
		PERROR("realpath");
		return -1;
	}

	if (parse_process_maps(getpid(), vmas, MAX_REPLICATE_VMA+1) < 0) {
		PRINT_ERROR("Error parsing process maps: %d\n", getpid());
		return -1;
	}

	signal(SIGBUS, school_bus);

	while (vmas[i].end != 0) {
		void *pattach;

		if (vmas[i].objname) {

			if (!strcmp(vmas[i].objname, "[vsyscall]")) {
				PRINT_ERROR("Skipping over vsyscall entry: %p <-> %p\n",
					(void *)vmas[i].start, (void *)vmas[i].end);
				i++;
				continue;
			} else if (!strcmp(vmas[i].objname, exename)) {
				PRINT_ERROR("Skipping over self exe: %s\n", vmas[i].objname);
				i++;
				continue;
			} else if (!strcmp(vmas[i].objname, "/dev/zero")) {
				i++;
				continue;
			}

		}

		errno = 0;
		ptrace(PTRACE_PEEKDATA, pid, vmas[i].start, 0);
		if (!errno)
			PRINT_ERROR("Warning: peek failed at %p\n", (void *)vmas[i].start);
		else {
			ptrace(PTRACE_PEEKDATA, pid, vmas[i].end, 0);
			if (!errno)
				PRINT_ERROR("Warning: peek failed at %p\n", (void *)vmas[i].end);
		}

		// No longer necessary with the use of shared memory.
//		v = get_local_vma(vmas[i].start, vmas[i].end-vmas[i].start, vmas[i].prot, NULL);
//		vmas[i].new_base = v;
//		PRINT_ERROR("v = %p\n", v);
		vmas[i].new_base = (void *)vmas[i].start;

		vmas[i].shmk = (getpid() * 100) + i;

		if ((vmas[i].shmid = shmget(vmas[i].shmk, vmas[i].end-vmas[i].start, IPC_CREAT | 0666)) < 0) {
			PERROR("shmget");
			return -1;
		}

		if ((!(vmas[i].prot & PROT_READ)) &&
				(mprotect((void *)vmas[i].start, vmas[i].end-vmas[i].start, vmas[i].prot|PROT_READ)))
			PERROR("mprotect");

		pattach = shmat(vmas[i].shmid, NULL, 0);
		if (pattach == (void *)-1) {
			PERROR("shmat");
			return -1;
		}

//		memcpy(pattach, vmas[i].new_base, vmas[i].end-vmas[i].start);
		jmp_memcpy(pattach, (void *)vmas[i].start, vmas[i].end-vmas[i].start);

		if (shmdt(pattach) == -1) {
			PERROR("shmdt");
			return -1;
		}

		if ((!(vmas[i].prot & PROT_READ)) &&
			(mprotect((void *)vmas[i].start, vmas[i].end-vmas[i].start, vmas[i].prot)))
			PERROR("mprotect");

		i++;
	}

	i = j = 0;

	if (shmids) {

		if (!(*shmids = malloc(sizeof(**shmids) * (MAX_REPLICATE_VMA + 1)))) {
			PERROR("malloc");
			return -1;
		}

		memset(*shmids, 0, sizeof(**shmids) * (MAX_REPLICATE_VMA + 1));
	}

	while (vmas[i].end != 0) {

		if (!vmas[i].new_base) {
			i++;
			continue;
		}

		if (shmids)
			(*shmids)[j++] = vmas[i].shmid;

		if (!(get_remote_vma_shm(pid, vmas[i].shmid, (unsigned long)vmas[i].new_base, vmas[i].end-vmas[i].start, vmas[i].prot, (void *)vmas[i].start))) {
			char execbuf[128];

			PRINT_ERROR("VMA error in mapping: %p -> %p\n", (void *)vmas[i].start, (void *)vmas[i].end);
			sprintf(execbuf, "cat /proc/%d/maps", pid);
			system(execbuf);
			DESTROY_VMAP(vmas, MAX_REPLICATE_VMA);
			return -1;
		}

//		PRINT_ERROR("SHMAT OK: %zu (%d) / %x\n", i, vmas[i].shmid, vmas[i].prot);
//		fprintf(stderr, "XXX: %d\n", memcmp_remote(pid, (void *)vmas[i].start, vmas[i].end-vmas[i].start, 0));
		i++;
	}

	DESTROY_VMAP(vmas, MAX_REPLICATE_VMA);
	return 0;
}

void *
replicate_environ(pid_t pid) {
	struct user_regs_struct regs;
	unsigned char *ebuf;
	char **eptr = environ, *ebufdata, *ebufdata_v;
	size_t esize = sizeof(char *), edatasize = 0, ebuf_ind = 0;
	void *res = NULL;

	PTRACE(PTRACE_GETREGS, pid, 0, &regs, NULL, PT_RETERROR);

	while (*eptr) {
//		printf("eptr = %p [%s]\n", *eptr, *eptr);
		edatasize += strlen(*eptr) + 1;
		esize += strlen(*eptr) + 1 + sizeof(char *);
		eptr++;
	}

	if (!(ebuf = malloc(esize))) {
		PERROR("malloc");
		return NULL;
	}

	regs.rsp -= esize;
	regs.rsp &= ~(sizeof(void *)-1);

	memset(ebuf, 0, esize);
	ebufdata = (char *)(ebuf + (esize - edatasize));
	ebufdata_v = (char *)regs.rsp + (esize - edatasize);
	eptr = environ;

	while (*eptr) {
		((char **)ebuf)[ebuf_ind++] = ebufdata_v;
		strcpy((char *)ebufdata, *eptr);
		ebufdata += strlen(*eptr) + 1;
		ebufdata_v += strlen(*eptr) + 1;
		eptr++;
	}

	((char **)ebuf)[ebuf_ind] = NULL;

	if (write_bytes_remote(pid, (void *)regs.rsp, ebuf, esize) < 0)
		PRINT_ERROR("Error copying environment to remote process %d\n", pid);
	else
		res = (void *)regs.rsp;

	free(ebuf);

	if (res)
		PTRACE(PTRACE_SETREGS, pid, 0, &regs, NULL, PT_RETERROR);

	return res;
}

int
do_intersect(vmap_region_t *region1, vmap_region_t *region2) {

	if ((region1->start >= region2->start) && (region1->start < region2->end))
		return 1;
	else if ((region1->end <= region2->end) && (region1->end > region2->start))
		return 1;

	return 0;
}

#define VSYSCALL_NAME	"[vsyscall]"
int
check_vma_collision(pid_t pid1, pid_t pid2, int exclude_vsyscall, int exclude_self) {
	vmap_region_t vr1[MAX_REPLICATE_VMA], vr2[MAX_REPLICATE_VMA];
	char exename1[PATH_MAX+1], exename2[PATH_MAX+1];
	int r1, r2;
	size_t i, j;
	int ret = 0;

	if ((r1 = parse_process_maps(pid1, vr1, MAX_REPLICATE_VMA)) < 0)
		return -1;

	if ((r2 = parse_process_maps(pid2, vr2, MAX_REPLICATE_VMA)) < 0) {
		DESTROY_VMAP(vr1, MAX_REPLICATE_VMA);
		return -1;
	}

	if ((r1 > 0) || (r2 > 0))
		PRINT_ERROR("%s", "Warning: collision comparison might be bad because of VMA overflow\n");

	if (exclude_self) {
		char exelookup1[32], exelookup2[32];
		int err = 0;

		memset(exename1, 0, sizeof(exename1));
		memset(exename2, 0, sizeof(exename2));
		snprintf(exelookup1, sizeof(exelookup1), "/proc/%d/exe", pid1);
		snprintf(exelookup2, sizeof(exelookup2), "/proc/%d/exe", pid2);

		if (!(realpath(exelookup1, exename1))) {
			PERROR("realpath");
			err = 1;
		} else if (!(realpath(exelookup2, exename2))) {
			PERROR("realpath");
			err = 1;
		}

		if (err) {
			exclude_self = 0;
			PRINT_ERROR("%s", "Warning: could not lookup processes so collision detection might not work match self properly.\n");
		}

	}

	for (i = 0; (i < MAX_REPLICATE_VMA) && (vr1[i].end != 0); i++) {

		for (j = 0; (j < MAX_REPLICATE_VMA) && (vr2[j].end != 0); j++) {

			if (exclude_vsyscall && ((vr1[i].objname && (!strcmp(vr1[i].objname, VSYSCALL_NAME))) ||
				(vr2[j].objname && (!strcmp(vr2[j].objname, VSYSCALL_NAME)))))
				continue;

			if (exclude_self && vr1[i].objname && (!strcmp(vr1[i].objname, exename1)))
				continue;
			else if (exclude_self && vr2[j].objname && (!strcmp(vr2[j].objname, exename2)))
				continue;

			if (do_intersect(&vr1[i], &vr2[j])) {
				PRINT_ERROR("Warning: VMA intersection detected: %p-%p (%d) / %s | %p-%p (%d) / %s\n",
					(void *)vr1[i].start, (void *)vr1[i].end, pid1, vr1[i].objname,
					(void *)vr2[j].start, (void *)vr2[j].end, pid2, vr2[j].objname);
				ret = 1;
			}

		}
	}

	DESTROY_VMAP(vr1, MAX_REPLICATE_VMA);
	DESTROY_VMAP(vr2, MAX_REPLICATE_VMA);
	return ret;
}

/*
 * Resolve a symbol in a shared object that has local scope visibility,
 * since rtld won't do this for us.
 * Also, assume that the specified target library has already been
 * loaded and memory. Use this preexisting library handle to calculate
 * the relocated virtual memory address of the symbol, which is
 * returned as the result.
 */
void *
resolve_local_symbol(const char *libpath, const char *funcname) {
	struct link_map *lm;
	void *hnd, *result = NULL;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Sym *symtab = NULL;
	unsigned char *bindata;
	char *strtab = NULL;
	size_t fsize, i, strtab_size = 0, symtab_size;
	int fd;

	if ((hnd = dlopen(libpath, RTLD_NOW|RTLD_NOLOAD|RTLD_NODELETE)) == NULL) {
		PRINT_ERROR("dlopen(%s): %s\n", libpath, dlerror());
		return NULL;
	}

	if (dlinfo(hnd, RTLD_DI_LINKMAP, &lm) == -1) {
		PRINT_ERROR("dlinfo(%s): %s\n", libpath, dlerror());
		return NULL;
	}

	if (dlclose(hnd) != 0)
		PRINT_ERROR("dlclose(%s): %s\n", libpath, dlerror());

       if (elf_load_library(libpath, &fd, &fsize, &ehdr, &phdr, &shdr) < 0) {
                PRINT_ERROR("%s", "Error looking up shared object dependencies\n");
                return NULL;
        }

        bindata = (unsigned char *)ehdr;

        for (i = 0; i < ehdr->e_shnum; i++) {

		if (shdr[i].sh_type == SHT_STRTAB) {

			printf("STRTAB: %zu, flags = %lu, link = %u, info = %u\n", shdr[i].sh_size, shdr[i].sh_flags, shdr[i].sh_link, shdr[i].sh_info);
			if (shdr[i].sh_size > strtab_size) {
				strtab = (char *)(bindata + shdr[i].sh_offset);
				strtab_size = shdr[i].sh_size;
			}

		} else if (shdr[i].sh_type == SHT_SYMTAB) {
			symtab = (Elf64_Sym *)(bindata + shdr[i].sh_offset);
			symtab_size = shdr[i].sh_size;
		}

	}

	if (!symtab) {
		PRINT_ERROR("Error: could not find symbol table in DSO: %s\n", libpath);
		goto out;
	} else if (!strtab) {
		PRINT_ERROR("Error: could not find string table in DSO: %s\n", libpath);
		goto out;
	} else if (!strtab_size) {
		PRINT_ERROR("Error: could not determine string table size in DSO: %s\n", libpath);
		goto out;
	}

	for (i = 0; i < symtab_size/sizeof(Elf64_Sym); i++) {

		if (!strcmp((strtab + symtab[i].st_name), funcname)) {
			result = (void *)symtab[i].st_value;
			break;
		}

	}

	if (result)
		result += lm->l_addr;

out:
	munmap(ehdr, fsize);
	close(fd);
	return result;
}

int
flash_remote_library_memory(pid_t pid, const char *dsopath) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	struct link_map *lm;
	void *hnd;
	unsigned char *bindata;
	unsigned long reloc_base;
	const char *strtab = NULL;
	size_t fsize, i, strtab_size = 0;
	int fd, result = 0;

	if ((hnd = dlopen(dsopath, RTLD_NOW|RTLD_NOLOAD|RTLD_NODELETE)) == NULL) {
		PRINT_ERROR("dlopen(%s): %s\n", dsopath, dlerror());
		return -1;
	}

	if (dlinfo(hnd, RTLD_DI_LINKMAP, &lm) == -1) {
		PRINT_ERROR("dlinfo(%s): %s\n", dsopath, dlerror());
		return -1;
	}

	if (dlclose(hnd) != 0)
		PRINT_ERROR("dlclose(%s): %s\n", dsopath, dlerror());

	reloc_base = lm->l_addr;

	dsopath = get_library_abs_path(dsopath);

	if (elf_load_library(dsopath, &fd, &fsize, &ehdr, &phdr, &shdr) < 0) {
		PRINT_ERROR("Error loading shared object: %s\n", dsopath);
		return -1;
	}

	bindata = (unsigned char *)ehdr;

	for (i = 0; i < ehdr->e_shnum; i++) {

		if ((shdr[i].sh_type == SHT_STRTAB) && (i == ehdr->e_shstrndx)) {
			strtab_size = shdr[i].sh_size;
			strtab = (char *)(bindata + shdr[i].sh_offset);
		}

	}

	if (!strtab) {
		PRINT_ERROR("Error flashing DSO %s: could not locate string table\n", dsopath);
		result = -1;
		goto out;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {

		if ((shdr[i].sh_type != SHT_PROGBITS) && (shdr[i].sh_type != SHT_NOBITS))
			continue;
		else if (!shdr[i].sh_addr)
			continue;
		else if (!(shdr[i].sh_flags & SHF_ALLOC))
			continue;
		else if (!(shdr[i].sh_flags & SHF_WRITE))
			continue;

		if (shdr[i].sh_type == SHT_NOBITS) {
			char *zbuf;

//			printf("BSS: %lx -> %lx\n", shdr[i].sh_addr, shdr[i].sh_addr+reloc_base);

			// Lazy but easy way to do this
			if (!(zbuf = malloc(shdr[i].sh_size))) {
				PERROR("malloc");
				result = -1;
				goto out;
			}

			memset(zbuf, 0, shdr[i].sh_size);

			if (write_bytes_remote(pid, (void *)(shdr[i].sh_addr + reloc_base), zbuf, shdr[i].sh_size) < 0) {
				PRINT_ERROR("Error flashing zero-byte section (%p) of remote DSO %s at PID %d\n",
					(void *)shdr[i].sh_addr, dsopath, pid);
				result = -1;
			}

			free(zbuf);
			continue;
		}

//		printf("SH[%2zu]: %u: %p / %lu | %lx: %s\n", i, shdr[i].sh_type, (void *)shdr[i].sh_addr, shdr[i].sh_size, shdr[i].sh_flags, strtab+shdr[i].sh_name);

		char *excluded_sections[] = { ".data.rel.ro", ".got", ".got.plt", ".data", NULL };
		char **excluded = excluded_sections;
		int skip = 0;

		while (*excluded) {

/*			if ((!strcmp(strtab+shdr[i].sh_name, ".data") && !strcmp(".data", *excluded))) {
				fprintf(stderr, "  +++ data memcmp (%s) / %s : %lu  = %d\n", dsopath, strtab+shdr[i].sh_name, shdr[i].sh_size,
					memcmp_remote(pid, (bindata + shdr[i].sh_offset), (void *)(shdr[i].sh_addr + reloc_base), shdr[i].sh_size));
				skip = 1;
				break;

			}*/

			if (!strcmp(*excluded, strtab+shdr[i].sh_name)) {
				skip = 1;
				break;
			}

			excluded++;
		}

		if (skip)
			continue;

		if (write_bytes_remote(pid, (void *)(shdr[i].sh_addr + reloc_base), (bindata + shdr[i].sh_offset), shdr[i].sh_size) < 0) {
			PRINT_ERROR("Error flashing data section (%p) of remote DSO %s at PID %d\n",
				(void *)shdr[i].sh_addr, dsopath, pid);
			result = -1;
		}
	}

out:
	munmap(bindata, fsize);
	close(fd);

	return result;
}
