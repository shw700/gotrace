#ifndef GOMOD_PRINT_H
#define GOMOD_PRINT_H


typedef struct golang_func {
	const char func_name[64];
	void *address;
	unsigned long param;
	int is_init_func;
	const char type_name[64];
} golang_func_t;

extern golang_func_t golang_function_table[];


extern void *get_golang_serializer(const char *typename);
extern int is_type_serialization_supported(const char *typename);


#endif
