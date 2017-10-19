#  Copyright (C) 2008, 2009, 2010 Jiri Olsa <olsajiri@gmail.com>
#
#  This file is part of the latrace.
#
#  The latrace is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  The latrace is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with the latrace (file COPYING).  If not, see 
#  <http://www.gnu.org/licenses/>.

ZYDIS_LIB=./zydis/build/libZydis.a

GOTRACE_BIN=gotrace
GOTRACE_LDFLAGS=$(LDFLAGS) -Wl,--no-as-needed -Wl,--export-dynamic
#gcc -ggdb -O0 -Wall -D_GNU_SOURCE -Wl,--export-dynamic
GOTRACE_LIBS=$(LIBS) $(LEXLIB) -ldl -lelf -lpthread $(ZYDIS_LIB)

GOTRACE_OBJS=\
	src/gtrace.o \
	src/audit.o \
	src/audit-init.o \
	src/output.o \
	src/symbol.o \
	src/elf.o \
	src/lib-include.o \
	src/args-bison.o \
	src/args-flex.o \
	src/args.o \
	src/thread.o \
	src/serializer.o \
	src/network.o \
	src/misc.o \
	src/ld.o \
	src/sysdeps/$(CONFIG_SYSDEP_DIR)/stack.o

OBJS+=$(GOTRACE_OBJS) $(GOMOD_OBJS)
PROGRAMS+= $(GOTRACE_BIN)
# no dependency for flex and bison definitions
OBJS_DEPS_OMIT+=\
	src/args-flex.o \
	src/args-bison.o \
	src/dlopen_stub.o \
	src/serializer_mod.o \
	src/intercept.o

$(GOTRACE_BIN): $(GOTRACE_OBJS)
	$(QUIET_LD)$(CC) $(CFLAGS) $(GOTRACE_LDFLAGS) -o $@ $^ $(GOTRACE_LIBS)


# injected binary
GOMOD_BIN=libgomod.so.$(CONFIG_VERSION)
#GOMOD_LDFLAGS="-Wl,-init=_gomod_init" -fPIC -shared $(LDFLAGS)
GOMOD_LDFLAGS=-fPIC -shared $(LDFLAGS)
GOMOD_LIB=-ldl -lpthread gomod_printlib.a $(ZYDIS_LIB)
GOMOD_OBJS=\
	src/gomod.o \
	src/network.o \
	src/misc.o \
	src/dlopen_stub.o \
	src/serializer_mod.o \
	src/intercept.o

OBJS+=$(GOMOD_OBJS)
PROGRAMS+=$(GOMOD_BIN)

GCCGO=gccgo
GO=go

$(GOMOD_BIN): $(GOMOD_OBJS)
	GOPATH=`pwd`/src/gomod_print $(GO) build -buildmode=c-shared -o gomod_printlib.a gomod_print
	$(QUIET_LD)$(CC) $(CFLAGS) $(GOMOD_LDFLAGS) -o $@ $^ $(GOMOD_LIB)

CPPFLAGS+=-I./zydis/include -I./zydis/build
CPPFLAGS+=-DCONFIG_LIBDIR=\"$(libdir)\"
CPPFLAGS+=-DGT_CONF_DIR=\"$(sysconfdir)/gotrace.d\"
CPPFLAGS+=-DGT_CONF_HEADERS_DIR=\"$(sysconfdir)/gotrace.d/headers\"
CPPFLAGS+=-DGT_CONF_TRANSFORMERS_DIR=\"$(sysconfdir)/gotrace.d/transformers\"
CPPFLAGS+=-DGT_CONF_HEADERS_FILE=\"$(sysconfdir)/gotrace.d/headers/gotrace.go\"
# no dependency for flex and bison definitions
OBJS_DEPS_OMIT+=\
	src/config-flex.o

clean::
	$(call remove, src/args-bison.[ch] src/args-flex.c)
	$(call remove, src/args-bison.output)
