#ifndef GOMOD_PRINT_H
#define GOMOD_PRINT_H

typedef char *(*golang_serializer_func)(unsigned long);


typedef struct golang_type_serializer {
	const char *name;
	golang_serializer_func serializer;
} golang_type_serializer_t;

extern golang_type_serializer_t golang_serializer_table[];


extern golang_serializer_func get_golang_serializer(const char *typename);


extern char *gotrace_print_net__TCPConn(unsigned long);

#endif
