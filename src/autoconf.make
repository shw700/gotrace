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


# src/autoconf.make.  Generated from autoconf.make.in by configure.

prefix                = /usr/local
exec_prefix           = ${prefix}
bindir                = ${exec_prefix}/bin
libdir                = ${exec_prefix}/lib
datadir               = ${datarootdir}
mandir                = ${datarootdir}/man
datarootdir           = ${prefix}/share
sysconfdir            = ${prefix}/etc

RM                    = rm
FIND                  = find
CC                    = gcc
LEX                   = flex
LEXLIB                = -lfl
YACC                  = bison -y
CPPFLAGS              = 
CFLAGS                = -g -O2
LDFLAGS               = 
LIBS                  = -liberty 

ASCIIDOC              = :
XMLTO                 = :

CONFIG_SYSDEP_DIR     = x86_64

CONFIG_VERSION        = 0.5.12
CONFIG_ARCH_HAVE_ARGS = y
CONFIG_ARCH_HAVE_TEST = y
