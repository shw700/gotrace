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
#include <sys/ptrace.h>

#include "config.h"


#define MAX_SO_NEEDED	64


char **strarr_dup(const char **sarray);
void strarr_free(char **sarray);
int strarr_contains(const char **sarray, const char *findstr);


jmp_buf jb;
void *last_copy_start, *last_copy_end;


int
memcmp_remote(pid_t pid, void *buf, size_t size, unsigned long watch_val) {
	void *rdata;
	size_t pctr;
	const unsigned char *p1, *p2;

	if (!(rdata = read_bytes_remote(pid, buf, size)))
		return -1;

	p1 = buf;
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

void
print_regs(pid_t pid) {
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return;
	}

	fprintf(stderr, "PID: %d, rip: %p, rax: %p, orig_rax: %p\n", pid, (void *)regs.rip, (void *)regs.rax, (void *)regs.orig_rax);
	fprintf(stderr, "    ++ rdi = %p, rsi = %p, rdx = %p, r10 = %p, r8 = %p, r9 = %p\n",
		(void *)regs.rdi, (void *)regs.rsi, (void *)regs.rdx,
		(void *)regs.r10, (void *)regs.r8, (void *)regs.r9);
	return;
}

uintptr_t
call_remote_lib_func(pid_t pid, void *faddr, uintptr_t r1, uintptr_t r2, uintptr_t r3, uintptr_t r4,
		uintptr_t r5, uintptr_t r6, int allow_event) {
	struct user_regs_struct oregs, nregs;
	unsigned long saved_i, call_i;
	unsigned char *iptr;
	int wait_status, err = 0;

	// Step #1. Save the current registers and instruction.
	if (ptrace(PTRACE_GETREGS, pid, 0, &oregs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	errno = 0;
	saved_i = ptrace(PTRACE_PEEKTEXT, pid, oregs.rip, 0);
	if (errno != 0) {
		perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
		return -1;
	}

	// Step #2. Replace the registers with the function parameters and
	// prime the instruction pointer to call the library function
	memset(&call_i, 0xcc, sizeof(call_i));
	iptr = (unsigned char *)&call_i;
	// What we have is the call to *%rbx followed by a trap landing pad.
	*iptr++ = 0xff;
	*iptr++ = 0xd3;

	if (ptrace(PTRACE_POKETEXT, pid, oregs.rip, call_i) == -1) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	memcpy(&nregs, &oregs, sizeof(nregs));
	nregs.rdi = r1;
	nregs.rsi = r2;
	nregs.rdx = r3;
	nregs.rcx = r4;
	nregs.r8 = r5;
	nregs.r9 = r6;
	nregs.rbx = (unsigned long)faddr;

	if (ptrace(PTRACE_SETREGS, pid, 0, &nregs) == -1) {
		perror_pid("ptrace(PTRACE_SETREGS)", pid);
		return -1;
	}

	// Step #3. Call into the library and wait for the return.
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		perror_pid("ptrace(PTRACE_CONT)", pid);
		return -1;
	} else if (waitpid(pid, &wait_status, 0) == -1) {
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

		if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
			perror_pid("ptrace(PTRACE_CONT)", pid);
			return -1;
		} else if (waitpid(pid, &wait_status, 0) == -1) {
			perror_pid("waitpid", pid);
			return -1;
		}
	}

	if (!err && (ptrace(PTRACE_GETREGS, pid, 0, &nregs) == -1)) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		err = 1;
	}

	// Step #4. Restore the original registers and instruction and continue.
	if (ptrace(PTRACE_POKETEXT, pid, oregs.rip, saved_i) == -1) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	if (ptrace(PTRACE_SETREGS, pid, 0, &oregs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	if (err)
		return -1;

	fprintf(stderr, "+++  Remote library call returning: %llx\n", nregs.rax);

	return nregs.rax;
}

unsigned long
call_remote_syscall(pid_t pid, int syscall_no, unsigned long r1, unsigned long r2, unsigned long r3,
		unsigned long r4, unsigned long r5, unsigned long r6) {
	unsigned long saved_i, syscall_i;
	unsigned char *iptr;
	struct user_regs_struct oregs, nregs;
	int wait_status, err = 0;

	// Step #1. Save the current registers and instruction.
	if (ptrace(PTRACE_GETREGS, pid, 0, &oregs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	errno = 0;
	saved_i = ptrace(PTRACE_PEEKTEXT, pid, oregs.rip, 0);
	if (errno != 0) {
		perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
		return -1;
	}

	// Step #2. Replace the registers with syscall parameters and
	// prime the instruction pointer to call the syscall
	memset(&syscall_i, 0xcc, sizeof(syscall_i));
	iptr = (unsigned char *)&syscall_i;
	// What we have is the "syscall" instruction followed by a trap landing pad.
	*iptr++ = 0x0f;
	*iptr++ = 0x05;

	if (ptrace(PTRACE_POKETEXT, pid, oregs.rip, syscall_i) == -1) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	memcpy(&nregs, &oregs, sizeof(nregs));
	nregs.rax = syscall_no;
	nregs.rdi = r1;
	nregs.rsi = r2;
	nregs.rdx = r3;
	nregs.r10 = r4;
	nregs.r8 = r5;
	nregs.r9 = r6;

	if (ptrace(PTRACE_SETREGS, pid, 0, &nregs) == -1) {
		perror_pid("ptrace(PTRACE_SETREGS)", pid);
		return -1;
	}

	// Step #3. Run the syscall and get the result.
	// First step into the syscall.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
		perror_pid("ptrace(PTRACE_SYSCALL)", pid);
		return -1;
	} else if (waitpid(pid, &wait_status, 0) == -1) {
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
	if (ptrace(PTRACE_POKETEXT, pid, oregs.rip, saved_i) == -1) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	if (ptrace(PTRACE_SETREGS, pid, 0, &oregs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	if (err)
		return -1;

	fprintf(stderr, "+++  Remote syscall returning: %llx\n", nregs.rax);

	return nregs.rax;
}

unsigned long
get_fs_base_remote(pid_t pid) {
	unsigned long saved_i, syscall_i, fs_result;
	unsigned char *iptr;
	struct user_regs_struct oregs, nregs;
	int wait_status, err = 0;

	// Step #1. Save the current registers and instruction.
	if (ptrace(PTRACE_GETREGS, pid, 0, &oregs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	errno = 0;
	saved_i = ptrace(PTRACE_PEEKTEXT, pid, oregs.rip, 0);
	if (errno != 0) {
		perror_pid("ptrace(PTRACE_PEEKTEXT)", pid);
		return -1;
	}

	// Step #2. Replace the registers with syscall parameters and
	// prime the instruction pointer to call the syscall
	memset(&syscall_i, 0xcc, sizeof(syscall_i));
	iptr = (unsigned char *)&syscall_i;
	// What we have is the "syscall" instruction followed by a trap landing pad.
	*iptr++ = 0x0f;
	*iptr++ = 0x05;

	if (ptrace(PTRACE_POKETEXT, pid, oregs.rip, syscall_i) == -1) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	memcpy(&nregs, &oregs, sizeof(nregs));
	nregs.rax = SYS_arch_prctl;
//	nregs.rdi = ARCH_SET_FS;
	nregs.rdi = 0x1002;
	nregs.rsi = oregs.rsp - sizeof(void *);

	if (ptrace(PTRACE_SETREGS, pid, 0, &nregs) == -1) {
		perror_pid("ptrace(PTRACE_SETREGS)", pid);
		return -1;
	}

	// Step #3. Run the syscall and get the result.
	// First step into the syscall.
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
		perror_pid("ptrace(PTRACE_SYSCALL)", pid);
		return -1;
	} else if (waitpid(pid, &wait_status, 0) == -1) {
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
	if (ptrace(PTRACE_POKETEXT, pid, oregs.rip, saved_i) == -1) {
		perror_pid("ptrace(PTRACE_POKETEXT)", pid);
		return -1;
	}

	if (ptrace(PTRACE_SETREGS, pid, 0, &oregs) == -1) {
		perror_pid("ptrace(PTRACE_GETREGS)", pid);
		return -1;
	}

	if (err)
		return -1;

	if (nregs.rax != 0) {
		fprintf(stderr, "+++  Remote read fs base returning error: %llx\n", nregs.rax);
		return nregs.rax;
	}

	errno = 0;
	fs_result = ptrace(PTRACE_PEEKDATA, pid, oregs.rsp - sizeof(void *), 0);
	if (errno != 0) {
		perror_pid("ptrace(PTRACE_PEEKDATA)", pid);
		return -1;
	}

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

	if (!(prot & PROT_WRITE)) {
		if (mprotect(vma, size, prot) == -1) {
			PERROR("mprotect");
			return NULL;
		}

	}

//	fprintf(stderr, "GOT IT (%p)\n", vma);
	return vma;
}

int
elf_load_library(const char *dsopath, int *fd, size_t *dsize, Elf64_Ehdr **pehdr,
		Elf64_Phdr **pphdr, Elf64_Shdr **pshdr) {
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
	} else if ((*pehdr)->e_type != ET_DYN) {
		PRINT_ERROR("File \"%s\" was not an ELF dynamic object!\n", dsopath);
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

void *
get_entry_point(const char *dsopath) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Dyn *dyn = NULL;
	void *result = NULL;
	unsigned char *bindata;
	size_t fsize, i;
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
		} else if ((shdr[i].sh_type == SHT_INIT_ARRAY) || (shdr[i].sh_type == SHT_FINI_ARRAY)) {
			unsigned long *funcptr;
			size_t nfunc;

			if (shdr[i].sh_size % sizeof(void *)) {
				PRINT_ERROR("Section advertised improperly aligned size: %lu\n", shdr[i].sh_size);
				continue;
			}

			nfunc = shdr[i].sh_size / sizeof(void *);
			
			PRINT_ERROR("LOCATED INITS: %s / %zu entries\n", (shdr[i].sh_type == SHT_INIT_ARRAY) ? "init" : "fini", nfunc);
			PRINT_ERROR("   addr = %lx, off = %lx, size = %lu\n", shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size);

			funcptr = (unsigned long *)(bindata + shdr[i].sh_offset);
			PRINT_ERROR("   + func1 = %p\n", (void *)*funcptr);

			if (shdr[i].sh_type == SHT_INIT_ARRAY)
				result = (void *)*funcptr;

		}

	}

	if (!dyn) {
		PRINT_ERROR("Error: could not find dynamic section of soname: %s\n", dsopath);
		goto out;
	}

	while (dyn->d_tag != DT_NULL) {
		switch(dyn->d_tag) {
			case DT_INIT:
//			case DT_FINI:
//			case DT_INIT_ARRAY:
//			case DT_FINI_ARRAY:
//			case DT_INIT_ARRAYSZ:
//			case DT_FINI_ARRAYSZ:
				break;
			default:
				dyn++;
				continue;
				break;
		}

		fprintf(stderr, "DYNAMIC (%s): %lu -> 0x%lx\n", dsopath, dyn->d_tag, dyn->d_un.d_val);
		result = (void *)dyn->d_un.d_val;
		break;
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
	void *new_base;
} vmap_region_t;

#define MAX_VMA 16


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

#define MAX_REPLICATE_VMA 128

int
replicate_process_remotely(pid_t pid) {
	char exename[PATH_MAX+1], exelookup[64];
	vmap_region_t vmas[MAX_REPLICATE_VMA];
	FILE *f;
	size_t vind = 0, i;

	memset(exename, 0, sizeof(exename));
	snprintf(exelookup, sizeof(exelookup), "/proc/self/exe");

	if (!(realpath(exelookup, exename))) {
		PERROR("realpath");
		return -1;
	}

	signal(SIGBUS, school_bus);

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

		if ((objname = tok = strtok(NULL, " "))) {
			if (!strcmp(objname, "[vsyscall]")) {
				PRINT_ERROR("Skipping over vsyscall entry: %s\n", range);
				continue;
			} else if (!strcmp(objname, exename)) {
				PRINT_ERROR("Skipping over self exe: %s\n", objname);
				continue;
			}
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

		errno = 0;
		ptrace(PTRACE_PEEKDATA, pid, start, 0);
		if (!errno)
			PRINT_ERROR("Warning: peek failed at %p\n", (void *)start);
		else {
			ptrace(PTRACE_PEEKDATA, pid, end, 0);
			if (!errno)
				PRINT_ERROR("Warning: peek failed at %p\n", (void *)end);
		}

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

		if (vind == MAX_REPLICATE_VMA) {
			PRINT_ERROR("%s", "Unexpected high number of mapped virtual memory areas; exiting scan.\n");
			break;
		}

	}

	for (i = 0; i < vind; i++) {
		void *v;

		v = get_local_vma(vmas[i].start, vmas[i].end-vmas[i].start, vmas[i].prot, NULL);
		vmas[i].new_base = v;
		PRINT_ERROR("v = %p\n", v);
	}

	for (i = 0; i < vind; i++) {

		if (!(get_remote_vma(pid, (unsigned long)vmas[i].new_base, vmas[i].end-vmas[i].start, vmas[i].prot, (void *)vmas[i].start))) {
			char execbuf[128];

			PRINT_ERROR("VMA error in mapping: %p -> %p\n", (void *)vmas[i].start, (void *)vmas[i].end);
			sprintf(execbuf, "cat /proc/%d/maps", pid);
			system(execbuf);
			return -1;
		}

	}

	return 0;
}
