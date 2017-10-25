#ifndef ELFH_H
#define ELFH_H

#include <link.h>
#include <elf.h>


typedef struct symbol_mapping {
	unsigned long addr;
	int is_func;
	char *name;
	unsigned short argsize;
	char *fname;
	size_t lineno;
} symbol_mapping_t;

typedef struct link_symbols {
	struct link_map *l;
	symbol_mapping_t *map;
	size_t msize;
} link_symbols_t;

typedef struct address_mapping {
	unsigned char *addr;
	size_t size;
	char *name;
} addr_mapping_t;

extern link_symbols_t symbol_store[128];


void store_link_map_symbols(struct link_map *l, symbol_mapping_t *m, size_t sz);
int get_all_symbols(struct link_map *lh, symbol_mapping_t **pmap, size_t *msize, int debug);
void *lookup_symbol(const char *name);
const char *lookup_addr(void *addr);
const char *lookup_addr_info(void *addr, size_t *pargsize, char **fname, size_t *line_no);
void *get_sym_addr(symbol_mapping_t *map, size_t sz, const char *name);
const char *get_addr_name(symbol_mapping_t *map, size_t sz, void *addr,
	size_t *pargsize, char **pfilename, size_t *pline_no);

const char *get_address_mapping(void *symaddr, size_t *size, size_t *offset);
void add_address_mapping(void *symaddr, size_t size, const char *name);
void remove_address_mapping(void *symaddr, size_t size, const char *hint, int null_ok);

char *resolve_sym(void *addr, int exact, char *buf, size_t buflen, const char **filename);

#endif
