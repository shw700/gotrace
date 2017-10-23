#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <pthread.h>

#include "config.h"
#include "elfh.h"


link_symbols_t symbol_store[128];
addr_mapping_t *addr_mappings = NULL;
size_t addr_mapping_used = 0, addr_mapping_size = 0;

pthread_rwlock_t mapping_lock = PTHREAD_RWLOCK_INITIALIZER;


void
dump_address_mappings(void) {
	size_t i;

	pthread_rwlock_rdlock(&mapping_lock);
	fprintf(stderr, "A total of %zu mappings exist out of %zu allocated.\n", addr_mapping_used, addr_mapping_size);

	for (i = 0; i < addr_mapping_used; i++) {
		fprintf(stderr, "%zu: %p / %zu bytes: %s\n", i+1, addr_mappings[i].addr, addr_mappings[i].size,
			addr_mappings[i].name);
	}

	pthread_rwlock_unlock(&mapping_lock);
	return;
}

size_t
bsearch_address_mapping_unlocked(void *symaddr, size_t size, int *needs_insert) {
	unsigned char *caddr = (unsigned char *)symaddr;
	size_t i = 0, start_range, end_range;
	int keep_searching  = 1;

	start_range = 0;
	end_range = addr_mapping_used - 1;

	if (!addr_mapping_used) {
		*needs_insert = 1;
		return 0;
	}

	while (keep_searching) {
		i = start_range + ((end_range - start_range) / 2);

		if (start_range == end_range)
			keep_searching = 0;

		if (caddr < addr_mappings[i].addr) {
			end_range = i;

			if (end_range && (end_range > start_range))
				end_range--;

			continue;
		}

		if ((caddr >= addr_mappings[i].addr) && (caddr+size <= addr_mappings[i].addr+addr_mappings[i].size)) {
			*needs_insert = 0;
			return i;
		}

		if (end_range == start_range)
			break;

		start_range = i+1;
	}

	*needs_insert = 1;

	if (caddr < addr_mappings[i].addr)
		return i;

	return i+1;
}

void
add_address_mapping(void *symaddr, size_t size, const char *name) {
	size_t ind;
	int insert;

	pthread_rwlock_wrlock(&mapping_lock);

	if (!addr_mapping_size) {
		addr_mapping_size = 128;
		addr_mappings = malloc(sizeof(*addr_mappings) * addr_mapping_size);
	} else if (addr_mapping_used == addr_mapping_size) {
		addr_mapping_size *= 2;
		addr_mappings = realloc(addr_mappings, (sizeof(*addr_mappings) * addr_mapping_size));
	}

	if (!addr_mappings) {
		PERROR("Error allocating memory for address mapping");
		return;
	}

	ind = bsearch_address_mapping_unlocked(symaddr, size, &insert);

	if (insert) {
		if (ind != addr_mapping_used) {
			memmove(&addr_mappings[ind+1], &addr_mappings[ind], sizeof(addr_mappings[0]) * (addr_mapping_used-ind));
		}

		addr_mappings[ind].addr = symaddr;
		addr_mappings[ind].size = size;
		addr_mappings[ind].name = strdup(name);
		addr_mapping_used++;
	} else {
		// For now, only permit a perfect overwrite
		if ((addr_mappings[ind].addr == symaddr) && (addr_mappings[ind].size == size)) {
			free(addr_mappings[ind].name);
			addr_mappings[ind].name = strdup(name);
		}

	}

	// XXX: the strdup/assignments above need error checking.

	pthread_rwlock_unlock(&mapping_lock);
	return;
}

void
remove_address_mapping(void *symaddr, size_t size, const char *hint, int null_ok) {
	unsigned char *caddr = (unsigned char *)symaddr;
	size_t ind;
	int insert;

	if (null_ok && !symaddr)
		return;

	pthread_rwlock_wrlock(&mapping_lock);

	ind = bsearch_address_mapping_unlocked(symaddr, size, &insert);

	if (insert) {

		if (hint)
			PRINT_ERROR("Warning: failed to lookup address mapping requested (%s) for removal at %p:%zu\n", hint, symaddr, size);
		else
			PRINT_ERROR("Warning: failed to lookup address mapping requested for removal at %p:%zu\n", symaddr, size);

	} else {

		// Freeing the whole thing or part of it?
		// Free the whole thing if our size requests match, or if size==0 was specified
		if ((addr_mappings[ind].addr == caddr) && ((size == addr_mappings[ind].size) || !size)) {
			free(addr_mappings[ind].name);
			memmove(&addr_mappings[ind], &addr_mappings[ind+1], sizeof(addr_mappings[0]) * (addr_mapping_used-(ind+1)));
			addr_mapping_used--;
		} else {

			// For right now only support removal at the beginning or end
			if (caddr == addr_mappings[ind].addr) {
				addr_mappings[ind].addr += addr_mappings[ind].size - size;
				addr_mappings[ind].size -= size;
			} else if (caddr + size == addr_mappings[ind].addr + addr_mappings[ind].size) {
				addr_mappings[ind].addr = caddr;
				addr_mappings[ind].size = size;
			}

		}

	}

	pthread_rwlock_unlock(&mapping_lock);
	return;
}

const char *
get_address_mapping(void *symaddr, size_t *size, size_t *offset) {
	unsigned char *caddr = (unsigned char *)symaddr;
	const char *name = NULL;
	size_t ind;
	int insert;

	pthread_rwlock_rdlock(&mapping_lock);

	ind = bsearch_address_mapping_unlocked(symaddr, 0, &insert);

	if (!insert) {
		name = addr_mappings[ind].name;

		if (size)
			*size = addr_mappings[ind].size;

		if (offset)
			*offset = (size_t)(caddr - addr_mappings[ind].addr);
	}

	pthread_rwlock_unlock(&mapping_lock);
	return name;
}

void
store_link_map_symbols(struct link_map *l, symbol_mapping_t *m, size_t sz) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {

		if (!symbol_store[i].l) {
			symbol_store[i].l = l;
			symbol_store[i].map = m;
			symbol_store[i].msize = sz;
			break;
		}

	}

	return;
}

void *
lookup_symbol(const char *name) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		void *addr;

		if (!symbol_store[i].l)
			continue;

		if ((addr = get_sym_addr(symbol_store[i].map, symbol_store[i].msize, name)))
			return addr;
			
	}

	return NULL;
}

const char *
lookup_addr(void *addr) {
	size_t i;

	for (i = 0; i < sizeof(symbol_store)/sizeof(symbol_store[0]); i++) {
		const char *name;

		if (!symbol_store[i].l)
			continue;

		if ((name = get_addr_name(symbol_store[i].map, symbol_store[i].msize, addr)))
			return name;
			
	}

	return NULL;
}

int _get_all_symbols(symbol_mapping_t **pmap, size_t *msize, void *strtab, size_t strtab_size, ELF_SYM *symtab,
	size_t syment_size, size_t reloc_off);

int
get_all_funcs_in_object(const char *filename) {
	struct stat sb;
	Elf64_Ehdr *eheader;
	Elf64_Shdr *sheaders;
	Elf64_Sym *symtab = NULL;
	symbol_mapping_t *pmap = NULL;
	void *strtab = NULL;
	unsigned char *bindata;
	size_t strtab_size = 0, msize = 0, i;
	int fd, result = 0;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		PERROR("open");
		return 0;
	}

	if (fstat(fd, &sb) < 0) {
		PERROR("fstat");
		close(fd);
		return 0;
	}

	if (sb.st_size < sizeof(Elf64_Ehdr)) {
		PRINT_ERROR("File \"%s\" is not large enough to be valid ELF object!\n", filename);
		close(fd);
		return 0;
	}


	if ((bindata = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		PERROR("mmap");
		close(fd);
		return 0;
	}

	eheader = (Elf64_Ehdr *)bindata;

	if (memcmp(eheader->e_ident, ELFMAG, SELFMAG)) {
		PRINT_ERROR("File \"%s\" does not appear to be a valid ELF object!\n", filename);
		goto out;
	} else if (eheader->e_ident[EI_CLASS] != ELFCLASS64) {
		PRINT_ERROR("File \"%s\" does not appear to be a 64 bit ELF object!\n", filename);
		goto out;
	} else if (eheader->e_ident[EI_VERSION] != EV_CURRENT) {
		PRINT_ERROR("File \"%s\" contained unexpected ELF header version!\n", filename);
		goto out;
	} else if (eheader->e_type != ET_EXEC) {
		PRINT_ERROR("File \"%s\" was not an ELF executable!\n", filename);
		goto out;
	} else if (eheader->e_machine != EM_X86_64) {
		PRINT_ERROR("File \"%s\" was not for a supported architecture (X86_64)!\n", filename);
		goto out;
	}

	if (eheader->e_shentsize != sizeof(Elf64_Shdr)) {
		PRINT_ERROR("File \"%s\" contained unexpected section header size!\n", filename);
		goto out;
	} else if ((eheader->e_shoff + eheader->e_shnum * eheader->e_shentsize) > sb.st_size) {
		PRINT_ERROR("File \"%s\" contained a section header table that was out of bounds!\n", filename);
		goto out;
	}

	sheaders = (Elf64_Shdr *)(bindata + eheader->e_shoff);
	for (i = 0; i < eheader->e_shnum; i++) {
		if (sheaders[i].sh_type == SHT_SYMTAB) {
//			printf("Section header %zu: type %u, size %lu\n", i+1, sheaders[i].sh_type, sheaders[i].sh_size);
			symtab = (void *)(bindata + sheaders[i].sh_offset);

			if (sheaders[i].sh_entsize != sizeof(Elf64_Sym)) {
				PRINT_ERROR("File \"%s\" contained unexpected symbol table entry size!\n", filename);
				goto out;
			}

		} else if (sheaders[i].sh_type == SHT_STRTAB) {
//			printf("Section header %zu: type %u, size %lu\n", i+1, sheaders[i].sh_type, sheaders[i].sh_size);
			// XXX: this is very wrong
			if (sheaders[i].sh_size > strtab_size) {
				strtab = (void *)(bindata + sheaders[i].sh_offset);
				strtab_size = sheaders[i].sh_size;
			}

		}

	}

	if (!strtab || !strtab_size) {
		PRINT_ERROR("File \"%s\" did not contain locatable string table!\n", filename);
		goto out;
	} else if (!symtab) {
		PRINT_ERROR("File \"%s\" did not contain locatable symbol table!\n", filename);
		goto out;
	}

	result = _get_all_symbols(&pmap, &msize, strtab, strtab_size, symtab, sizeof(Elf64_Sym), 0);

	if (result == 1) {
		struct link_map lm;

		memset(&lm, 0, sizeof(lm));
		lm.l_addr = 0;
		lm.l_name = strdup(filename);
		lm.l_ld = NULL;
		store_link_map_symbols(&lm, pmap, msize);
	}

out:
	munmap(bindata, sb.st_size);
	close(fd);

	return result;
}

int
_get_all_symbols(symbol_mapping_t **pmap, size_t *msize, void *strtab, size_t strtab_size, ELF_SYM *symtab,
		size_t syment_size, size_t reloc_off) {
	symbol_mapping_t *result, *rptr;
	void *osym = symtab;
	char *rstrtab;
	size_t rsize = 0, nsyms = 0;

	if (!strtab_size || !syment_size || !strtab || !symtab)
		return 0;

	while (1) {

		if (symtab->st_name >= strtab_size)
			break;

		if (symtab->st_value == 0) {
			symtab++;
			continue;
		}

		if (symtab->st_size == 0) {
			symtab++;
			continue;
		}

		if ((ELF_ST_TYPE(symtab->st_info) == STT_OBJECT) || (ELF_ST_TYPE(symtab->st_info) == STT_TLS))
			add_address_mapping((void *)symtab->st_value+reloc_off, symtab->st_size, strtab+symtab->st_name);

/*		if (ELF_ST_TYPE(symtab->st_info) != STT_FUNC) {
			symtab++;
			continue;
		}*/

		symtab++, nsyms++;
	}

	rsize = strtab_size + (nsyms * sizeof(symbol_mapping_t));

	if (!(result = malloc(rsize))) {
		PERROR("malloc");
		return 0;
	}

	memset(result, 0, rsize);
	rstrtab = (char *)result + rsize - strtab_size;
	memcpy(rstrtab, strtab, strtab_size);

	symtab = (ELF_SYM *)osym;
	rptr = result;

	while (1) {

		if (symtab->st_name >= strtab_size)
			break;

		if (symtab->st_value == 0) {
			symtab++;
			continue;
		}

		if (symtab->st_size == 0) {
			symtab++;
			continue;
		}

/*		if (ELF_ST_TYPE(symtab->st_info) != STT_FUNC) {
			symtab++;
			continue;
		}*/

		rptr->addr = (unsigned long)reloc_off + symtab->st_value;
		rptr->name = rstrtab + symtab->st_name;

		if (ELF_ST_TYPE(symtab->st_info) == STT_FUNC)
			rptr->is_func = 1;

//printf("sym name: %s / %p [%lu]\n", rptr->name, rptr->addr, symtab->st_size);
		symtab++, rptr++;
	}


	*pmap = result;
	*msize = nsyms;

	return 1;
}

int
get_all_symbols(struct link_map *lm, symbol_mapping_t **pmap, size_t *msize, int debug) {
	symbol_mapping_t *result, *rptr;
	ELF_DYN *dyn = (ELF_DYN *)lm->l_ld;
	ELF_SYM *symtab = NULL;
	void *osym = NULL;
	char *strtab = NULL, *rstrtab;
	size_t strtab_size = 0, syment_size = 0, rsize = 0, nsyms = 0;

	if (debug)
		fprintf(stderr, "ELF debug: base addr = %p\n", (void *)lm->l_addr);

	while (dyn->d_tag != DT_NULL) {

		if (dyn->d_tag == DT_STRSZ)
			strtab_size = dyn->d_un.d_val;
		else if (dyn->d_tag == DT_SYMENT)
			syment_size = dyn->d_un.d_val;
		else if (dyn->d_tag == DT_STRTAB)
			strtab = (void *)dyn->d_un.d_ptr;
		else if (dyn->d_tag == DT_SYMTAB)
			osym = symtab = (ELF_SYM *)dyn->d_un.d_ptr;

		if (debug) {
			if (dyn->d_tag == DT_RELENT)
				fprintf(stderr, "ELF debug: relent = %lu\n", dyn->d_un.d_val);
			else if (dyn->d_tag == DT_RELSZ)
				fprintf(stderr, "ELF debug: relsz = %lu\n", dyn->d_un.d_val);
			else if (dyn->d_tag == DT_PLTRELSZ)
				fprintf(stderr, "ELF debug: plt relsz = %lu\n", dyn->d_un.d_val);
			else if (dyn->d_tag == DT_PLTGOT)
				fprintf(stderr, "ELF debug: pltgot = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_RELA)
				fprintf(stderr, "ELF debug: rela = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_REL)
				fprintf(stderr, "ELF debug: rel = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_TEXTREL)
				fprintf(stderr, "ELF debug: textrel = %p\n", (void *)dyn->d_un.d_ptr);
			else if (dyn->d_tag == DT_JMPREL)
				fprintf(stderr, "ELF debug: jmprel = %p\n", (void *)dyn->d_un.d_ptr);
		}

		dyn++;
	}

	if (!strtab_size || !syment_size || !strtab || !symtab)
		return 0;

	while (1) {

		if (symtab->st_name >= strtab_size)
			break;

		if (symtab->st_value == 0) {
			symtab++;
			continue;
		}

		if ((ELF_ST_TYPE(symtab->st_info) == STT_OBJECT) || (ELF_ST_TYPE(symtab->st_info) == STT_TLS))
			add_address_mapping((void *)symtab->st_value+lm->l_addr, symtab->st_size, strtab+symtab->st_name);

		if (ELF_ST_TYPE(symtab->st_info) != STT_FUNC) {
			symtab++;
			continue;
		}

		symtab++, nsyms++;
	}

	rsize = strtab_size + (nsyms * sizeof(symbol_mapping_t));

	if (!(result = malloc(rsize))) {
		PERROR("malloc");
		return 0;
	}

	memset(result, 0, rsize);
	rstrtab = (char *)result + rsize - strtab_size;
	memcpy(rstrtab, strtab, strtab_size);

	symtab = (ELF_SYM *)osym;
	rptr = result;

	while (1) {

		if (symtab->st_name >= strtab_size)
			break;

		if (symtab->st_value == 0) {
			symtab++;
			continue;
		}

		if (ELF_ST_TYPE(symtab->st_info) != STT_FUNC) {
			symtab++;
			continue;
		}

		rptr->addr = (unsigned long)lm->l_addr + symtab->st_value;
		rptr->name = rstrtab + symtab->st_name;
		symtab++, rptr++;
	}


	*pmap = result;
	*msize = nsyms;

	return 1;
}

void *
get_sym_addr(symbol_mapping_t *map, size_t sz, const char *name) {
	size_t i;

	for (i = 0; i < sz; i++) {

		if (!strcmp(map[i].name, name))
			return (void *)map[i].addr;

	}

	return NULL;
}

const char *
get_addr_name(symbol_mapping_t *map, size_t sz, void *addr) {
	size_t i;

	for (i = 0; i < sz; i++) {

		if (((void *)map[i].addr == addr))
			return (void *)map[i].name;

	}

	return NULL;
}

char *resolve_sym(void *addr, int exact, char *buf, size_t buflen, const char **filename)
{
	Dl_info dinfo;

	memset(buf, 0, buflen);

	if (!dladdr(addr, &dinfo))
		return NULL;

	if (!dinfo.dli_saddr)
		return NULL;

	if (filename)
		*filename = dinfo.dli_fname;

	if (dinfo.dli_saddr == addr)
		strncpy(buf, dinfo.dli_sname, buflen);
	else if (exact)
		return NULL;
	else {
		char dbuf[16];
		long int diff = (unsigned long)addr - (unsigned long)dinfo.dli_saddr;

		if (diff < 0)
			snprintf(dbuf, sizeof(dbuf), "-0x%lx", 0-diff);
		else
			snprintf(dbuf, sizeof(dbuf), "+0x%lx", diff);

		snprintf(buf, buflen, "%s%s", dinfo.dli_sname, dbuf);
	}

	return buf;
}
