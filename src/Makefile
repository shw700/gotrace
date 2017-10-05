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


GOTRACE_BIN=gotrace
GOTRACE_LDFLAGS=$(LDFLAGS) -Wl,--no-as-needed -Wl,--export-dynamic
#gcc -ggdb -O0 -Wall -D_GNU_SOURCE -Wl,--export-dynamic
GOTRACE_LIBS=$(LIBS) $(LEXLIB) -ldl -lelf -lpthread

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
	src/sysdeps/$(CONFIG_SYSDEP_DIR)/stack.o

OBJS+=$(GOTRACE_OBJS)
PROGRAMS+= $(GOTRACE_BIN)
# no dependency for flex and bison definitions
OBJS_DEPS_OMIT+=\
	src/args-flex.o \
	src/args-bison.o

$(GOTRACE_BIN): $(GOTRACE_OBJS)
	$(QUIET_LD)$(CC) $(CFLAGS) $(GOTRACE_LDFLAGS) -o $@ $^ $(GOTRACE_LIBS)


CPPFLAGS+=-DCONFIG_LIBDIR=\"$(libdir)\"
CPPFLAGS+=-DLT_CONF_DIR=\"$(sysconfdir)/latrace.d\"
#CPPFLAGS+=-DLT_CONF_HEADERS_DIR=\"$(sysconfdir)/latrace.d/headers\"
CPPFLAGS+=-DLT_CONF_TRANSFORMERS_DIR=\"$(sysconfdir)/latrace.d/transformers\"
#CPPFLAGS+=-DLT_CONF_HEADERS_FILE=\"$(sysconfdir)/latrace.d/headers/latrace.h\"
# no dependency for flex and bison definitions
OBJS_DEPS_OMIT+=\
	src/config-flex.o

clean::
	$(call remove, src/args-bison.[ch] src/args-flex.c)
	$(call remove, src/args-bison.output)
