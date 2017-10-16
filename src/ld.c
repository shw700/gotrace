#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <dlfcn.h>
#include <elf.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "config.h"


jmp_buf jb;


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

	fprintf(stderr, "Remote syscall returning: %llx\n", nregs.rax);

	return nregs.rax;
}

unsigned long
call_remote_mmap(pid_t pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	return (call_remote_syscall(pid, SYS_mmap, (unsigned long)addr, length, prot, flags, fd, offset));
}

int
call_remote_mprotect(pid_t pid, void *addr, size_t len, int prot) {
	return (call_remote_syscall(pid, SYS_mprotect, (unsigned long)addr, len, prot, 0, 0, 0));
}

void
school_bus(int signo) {

	if (signo == SIGBUS) {
		PRINT_ERROR("%s", "Received SIGBUS\n");
		siglongjmp(jb, 666);
	} else
		PRINT_ERROR("Received unexpected signal: %d\n", signo);

	return;
}

void *
get_remote_vma(unsigned long base, size_t size, int prot, void *fixed) {
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

	printf("Trying: %p to %p (%zu)\n", (void *)base, (void *)base+size, size);
	fflush(stdout);

	if (!(prot & PROT_READ)) {
		fprintf(stderr, "HMM\n");
		if (mprotect((void *)base, size, prot|PROT_READ) == -1) {
			PERROR("mprotect");
			return NULL;
		}
	}

	fprintf(stderr, "%s", "memcpy 1\n");

	if (sigsetjmp(jb, 1)) {
		PRINT_ERROR("%s", "Error detected in sigsetjmp\n");
		failed = 1;
	}

	if (!failed) {
		memcpy(vma, (void *)base, size-1);
		fprintf(stderr, "%s", "memcpy 2\n");
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

void *
get_entry_point(const char *dsopath) {
	struct stat sb;
	Elf64_Ehdr *eheader;
	Elf64_Phdr *pheaders;
	Elf64_Shdr *sheaders;
	Elf64_Sym *symtab = NULL;
	void *strtab = NULL, *result = NULL;
	unsigned char *bindata;
	size_t strtab_size = 0, i;
	int fd;

	if ((fd = open(dsopath, O_RDONLY)) < 0) {
		PERROR("open");
		return NULL;
	}

	if (fstat(fd, &sb) < 0) {
		PERROR("fstat");
		close(fd);
		return NULL;
	}

	if (sb.st_size < sizeof(Elf64_Ehdr)) {
		PRINT_ERROR("File \"%s\" is not large enough to be valid ELF object!\n", dsopath);
		close(fd);
		return NULL;
	}

	if ((bindata = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		PERROR("mmap");
		close(fd);
		return NULL;
	}

	eheader = (Elf64_Ehdr *)bindata;

	if (memcmp(eheader->e_ident, ELFMAG, SELFMAG)) {
		PRINT_ERROR("File \"%s\" does not appear to be a valid ELF object!\n", dsopath);
		goto out;
	} else if (eheader->e_ident[EI_CLASS] != ELFCLASS64) {
		PRINT_ERROR("File \"%s\" does not appear to be a 64 bit ELF object!\n", dsopath);
		goto out;
	} else if (eheader->e_ident[EI_VERSION] != EV_CURRENT) {
		PRINT_ERROR("File \"%s\" contained unexpected ELF header version!\n", dsopath);
		goto out;
	} else if (eheader->e_type != ET_DYN) {
		PRINT_ERROR("File \"%s\" was not an ELF dynamic object!\n", dsopath);
		goto out;
	} else if (eheader->e_machine != EM_X86_64) {
		PRINT_ERROR("File \"%s\" was not for a supported architecture (X86_64)!\n", dsopath);
		goto out;
	}

	if (eheader->e_shentsize != sizeof(Elf64_Shdr)) {
		PRINT_ERROR("File \"%s\" contained unexpected section header size!\n", dsopath);
		goto out;
	} else if ((eheader->e_shoff + eheader->e_shnum * eheader->e_shentsize) > sb.st_size) {
		PRINT_ERROR("File \"%s\" contained a section header table that was out of bounds!\n", dsopath);
		goto out;
	} else if ((eheader->e_phoff + eheader->e_phnum * eheader->e_phentsize) > sb.st_size) {
		PRINT_ERROR("File \"%s\" contained a program header table that was out of bounds!\n", dsopath);
		goto out;
	}

	pheaders = (Elf64_Phdr *)(bindata + eheader->e_phoff);
	sheaders = (Elf64_Shdr *)(bindata + eheader->e_shoff);

	for (i = 0; i < eheader->e_phnum; i++) {
		if (pheaders[i].p_type != PT_LOAD)
			continue;

		fprintf(stderr, "Program header: %zu of %u: type = %x\n", i+1, eheader->e_phnum, pheaders[i].p_type);
		fprintf(stderr, "    flags = %x, offset = %lx, vaddr = %lx, paddr = %lx, fsize = %lu, memsz = %lu, align = %lx\n",
			pheaders[i].p_flags, pheaders[i].p_offset, pheaders[i].p_vaddr, pheaders[i].p_paddr,
			pheaders[i].p_filesz, pheaders[i].p_memsz, pheaders[i].p_align);
	}

	for (i = 0; i < eheader->e_shnum; i++) {
		if (sheaders[i].sh_type == SHT_SYMTAB) {
			printf("Section header %zu: type %u, size %lu\n", i+1, sheaders[i].sh_type, sheaders[i].sh_size);
			symtab = (void *)(bindata + sheaders[i].sh_offset);

			if (sheaders[i].sh_entsize != sizeof(Elf64_Sym)) {
				PRINT_ERROR("File \"%s\" contained unexpected symbol table entry size!\n", dsopath);
				goto out;
			}

		} else if (sheaders[i].sh_type == SHT_STRTAB) {
			printf("Section header %zu: type %u, size %lu\n", i+1, sheaders[i].sh_type, sheaders[i].sh_size);
			// XXX: this is very wrong
			if (sheaders[i].sh_size > strtab_size) {
				strtab = (void *)(bindata + sheaders[i].sh_offset);
				strtab_size = sheaders[i].sh_size;
			}

		} else if (sheaders[i].sh_type == SHT_DYNAMIC) {
			PRINT_ERROR("%s", "LOCATED DYNAMIC SECTION\n");
		} else if ((sheaders[i].sh_type == SHT_INIT_ARRAY) || (sheaders[i].sh_type == SHT_FINI_ARRAY)) {
			unsigned long *funcptr;
			size_t nfunc;

			if (sheaders[i].sh_size % sizeof(void *)) {
				PRINT_ERROR("Section advertised improperly aligned size: %lu\n", sheaders[i].sh_size);
				continue;
			}

			nfunc = sheaders[i].sh_size / sizeof(void *);
			
			PRINT_ERROR("LOCATED INITS: %s / %zu entries\n", (sheaders[i].sh_type == SHT_INIT_ARRAY) ? "init" : "fini", nfunc);
			PRINT_ERROR("   addr = %lx, off = %lx, size = %lu\n", sheaders[i].sh_addr, sheaders[i].sh_offset, sheaders[i].sh_size);

			funcptr = (unsigned long *)(bindata + sheaders[i].sh_offset);
			PRINT_ERROR("   + func1 = %p\n", (void *)*funcptr);

			if (sheaders[i].sh_type == SHT_INIT_ARRAY)
				result = (void *)*funcptr;

		} else if ((sheaders[i].sh_type > SHT_PROGBITS) && (sheaders[i].sh_type < SHT_GNU_ATTRIBUTES)) {
			if (sheaders[i].sh_type != SHT_NOTE)
				PRINT_ERROR("FOUND %x: %lu bytes\n", sheaders[i].sh_type, sheaders[i].sh_size);
		}

	}

out:
	munmap(bindata, sb.st_size);
	close(fd);
	return result;
}


typedef struct vmap_region {
	unsigned long start;
	unsigned long end;
	int prot;
	void *new_base;
} vmap_region_t;

#define MAX_VMA 16


int
open_dso_and_get_segments(const char *soname) {
	vmap_region_t vmas[MAX_VMA];
	FILE *f;
	void *dladdr, *ep, *init_func;
	char realname[1024];
	char execbuf[128], execbuf2[128];
	size_t vind = 0, i;

	sprintf(execbuf, "echo 1; cat /proc/%d/maps | grep libgomod", getpid());
	sprintf(execbuf2, "echo 2; cat /proc/%d/maps | grep libgomod", getpid());

	signal(SIGBUS, school_bus);

	memset(realname, 0, sizeof(realname));

	if (readlink(soname, realname, sizeof(realname)) == -1) {
		if (errno == EINVAL)
			strncpy(realname, soname, sizeof(realname));
		else {
			PERROR("readlink");
			return -1;
		}
	}

	ep = get_entry_point(realname);
	fprintf(stderr, "Entry point: %p\n", ep);

	if (!(dladdr = dlopen(realname, RTLD_NOW | RTLD_DEEPBIND))) {
		PRINT_ERROR("dlopen(): %s\n", dlerror());
		return -1;
	}

	init_func = dlsym(dladdr, "_gomod_init");

	if ((f = fopen("/proc/self/maps", "r")) == NULL) {
		perror_pid("fopen(/proc/self/maps", 0);
		return -1;
	}

	memset(vmas, 0, sizeof(vmas));

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

		if (!(objname = tok = strtok(NULL, " ")))
			continue;

		if (*objname != '/')
			continue;
		else if (strcmp(objname, realname))
			continue;

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

		fprintf(stdout, "Range: [%lx to %lx], perms: [%s], offset: [%s], name: [%s]\n", start, end, perms, foffset, objname);
		fflush(stdout);

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

	system(execbuf);

	for (i = 0; i < vind; i++) {
		void *v;

		fprintf(stderr, "HEH: %lx -> %lx\n", vmas[i].start, vmas[i].end);
		v = get_remote_vma(vmas[i].start, vmas[i].end-vmas[i].start, vmas[i].prot, NULL);
		vmas[i].new_base = v;
		PRINT_ERROR("v = %p\n", v);
	}

	if (dlclose(dladdr) == -1)
		PRINT_ERROR("dlclose(): %s\n", dlerror());

	fprintf(stderr, "Shop all closed up\n");
	system(execbuf2);

	fprintf(stderr, "\n\n\nFINAL PUSH\n");
	for (i = 0; i < vind; i++) {
		void *v2;

		fprintf(stderr, "NOW: %p\n", vmas[i].new_base);
		v2 = get_remote_vma((unsigned long)vmas[i].new_base, vmas[i].end-vmas[i].start, vmas[i].prot, (void *)vmas[i].start);
		PRINT_ERROR("v2 = %p\n", v2);
	}
	system(execbuf);

/*	void (*ffunc)(void);
	ffunc = (void *)init_func;
	fprintf(stderr, "About to call init func: %p\n", ffunc);
	ffunc();*/


	return 0;
}
