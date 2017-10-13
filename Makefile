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


-include src/autoconf.make

confdir     := $(sysconfdir)/gotrace.d
headdir     := $(sysconfdir)/gotrace.d/headers
headarchdir := $(sysconfdir)/gotrace.d/headers/sysdeps/$(CONFIG_SYSDEP_DIR)

# looks like DESTDIR is a standard, but prioritize ROOTDIR anyway
ifdef DESTDIR
ifndef ROOTDIR
ROOTDIR=$(DESTDIR)
endif
endif

ifneq ($(findstring $(MAKEFLAGS),w),w)
PRINT_DIR = --no-print-directory
else # "make -w"
NO_SUBDIR = :
endif

# nice output definition
# Mostly copied from kernel and git makefiles.

ifndef V
	QUIET_CC          = @echo "  CC" $@;
	QUIET_LD          = @echo "  LD" $@;
	QUIET_LEX         = @echo "  LE" $@;
	QUIET_YACC        = @echo "  YA" $@;
	QUIET_DEP         = @echo "  DEP" $@;
	QUIET_GEN         = @echo "  GEN" $@;
	QUIET_ASCIIDOC    = @echo "  ASCIIDOC" $@;
	QUIET_XMLTO       = @echo "  XMLTO" $@;
	QUIET_PKG         = @echo -n "  PKG ";
	QUIET_INSTALL     = @echo -n "  INSTALL ";
	QUIET_LN          = @echo -n "  LN ";
	QUIET_RM          = @echo -n "  CLEAN ";
	QUIET_MKDIR       = @echo -n "  MKDIR ";
endif

# install file, arguments:
#    1 - file to install
#    2 - directory to install to
#    3 - permissions
define install
	$(QUIET_INSTALL) echo $(ROOTDIR)$2/$(notdir $1) | sed 's:[/]\+:/:g'; \
	mkdir -p $(ROOTDIR)$2; \
	install -m $3 $1 $(ROOTDIR)$2;
endef

# install link, arguments:
#    1 - source
#    2 - dest
#    3 - directory
define link
	$(QUIET_LN) echo $(ROOTDIR)$3/$(notdir $2) | sed 's:[/]\+:/:g'; \
	$(RM) -f $(ROOTDIR)$3/$(notdir $2); \
	(cd $(ROOTDIR)/$3; ln -s $1 $2)
endef

# remove file/dir
define remove
	$(QUIET_RM) echo $1; $(RM) -rf $1
endef

.PHONY: all clean tags install .FORCE-GOTRACE-CFLAGS

all::

install:: all
	$(call install,etc/gotrace.d/gotrace.conf,$(confdir),644)
	$(call install,etc/gotrace.d/headers/gotrace.go,$(headdir),644)
ifeq ($(CONFIG_SYSDEP_DIR),x86_64)
	@mkdir -p $(ROOTDIR)/$(confarch)
	$(call install,etc/gotrace.d/headers/sysdeps/$(CONFIG_SYSDEP_DIR)/syscall.go,$(headarchdir),644)
endif


ifeq (,$(filter clean mrproper,$(MAKECMDGOALS)))
-include deps.make
endif


# main building schema
# Module subdir (src,libsf) are supposed to fill PROGRAMS and
# OBJS variables, and rule to link the module. The top makefile
# will do the rest.

PROGRAMS=
OBJS=

include src/Makefile

INCLUDES= -I. -Isrc -Isrc/sysdeps/$(CONFIG_SYSDEP_DIR)
ALL_CFLAGS=$(CPPFLAGS) $(CFLAGS) -ggdb -O0 -fPIC -Wall $(INCLUDES)
ALL_CFLAGS+=-D_GNU_SOURCE -imacros src/autoconf.h


%.o: %.c GOTRACE-CFLAGS
	$(QUIET_CC)$(CC) -o $*.o -c $(ALL_CFLAGS) $<

src/dlopen_stub.o: src/dlopen_stub.S
	$(QUIET_CC)$(CC) -o $*.o -c $(ALL_CFLAGS) $<

src/intercept.o: src/intercept.S
	$(QUIET_CC)$(CC) -o $*.o -c $(ALL_CFLAGS) $<

src/serializer_mod.o: src/serializer.c
	$(QUIET_CC)$(CC) -o $*.o -c $(ALL_CFLAGS) -DMODULE=1 $<


.SECONDARY:

%.c: %.l GOTRACE-CFLAGS
	$(QUIET_LEX)$(LEX) -t $< > $(basename $<).c

%.c: %.y GOTRACE-CFLAGS
	$(QUIET_YACC)$(YACC) -v $< -d -o $(basename $<).c


all:: $(PROGRAMS) GOTRACE-CFLAGS

clean::
	$(call remove, $(OBJS) $(PROGRAMS))
	$(call remove, lib bin share deps.make gotrace-$(CONFIG_VERSION))

mrproper::
	git clean -xdf

snapshot:
	@$(MAKE) $(PRINT_DIR) PKG_VER=$(CONFIG_VERSION)-`date "+%m%d%Y"`

release:
	@$(MAKE) $(PRINT_DIR) PKG_VER=$(CONFIG_VERSION)


# dependencies
# The gcc -M depedencies generation needs to repaired to include
# subdirectory name within the target.. at least I haven't find any
# gcc option to do that.
DEPS_OBJS=$(filter-out $(OBJS_DEPS_OMIT),$(OBJS))

deps.make:
	$(QUIET_DEP)$(RM) -f deps.make; \
	(for obj in $(DEPS_OBJS); do \
	src=`echo $$obj | sed "s/\.o/.c/"`; \
	$(CC) $(ALL_CFLAGS) -M -MT$$obj $$src;  \
	done) > deps.make

# utilities
tags:
	$(QUIET_GEN)$(RM) -f tags; \
	$(FIND) . -name '*.[hc]' -print | xargs ctags -a

cscope:
	$(QUIET_GEN)$(RM) -f cscope*; \
	$(FIND) . -name '*.[hc]' -print > cscope.files; \
	cscope -b -icscope.files

# detect prefix and cflags changes
TRACK_CFLAGS = $(subst ','\'',$(ALL_CFLAGS)):\
             $(prefix):$(exec_prefix):$(bindir):$(libdir):$(sysconfdir) #'

GOTRACE-CFLAGS: .FORCE-GOTRACE-CFLAGS
	@FLAGS='$(TRACK_CFLAGS)'; \
	if test x"$$FLAGS" != x"`cat GOTRACE-CFLAGS 2>/dev/null`" ; then \
		echo "$$FLAGS" >GOTRACE-CFLAGS; \
	fi
