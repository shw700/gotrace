/*
  Copyright (C) 2008, 2009, 2010 Jiri Olsa <olsajiri@gmail.com>

  This file is part of the latrace.

  The latrace is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The latrace is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the latrace (file COPYING).  If not, see 
  <http://www.gnu.org/licenses/>.
*/

%option prefix="lt_args_"

%{

#include <string.h>

#include "config.h"
#include "args-bison.h"
#include "lib-include.h"

extern struct lt_include *lt_args_sinc;
char *got_filename = NULL;
int launch_preprocessor = 0;

%}

alphnum		[-0-9a-zA-Z_]
type_prefix     [a-zA-z_]+\.\(
name		([-0-9a-zA-Z_\.|/|\\])+
filename	([-0-9a-zA-Z\./_])+
whitespace	([ \t])

%x comment import
%%
 /* We need to delay return of the preprocessor filename because our grammar parser
    tries to read in the next file's contents before it has transitioned out of the
    import state. */
	if (launch_preprocessor) {
		got_filename = NULL;
		launch_preprocessor = 0;
		BEGIN(INITIAL);
		return '"';
	}

"//".*\n		{ lt_inc_stack(lt_args_sinc)->lineno++; BEGIN(INITIAL); }

"/*"			BEGIN(comment);
<comment>[^*\n]*	/* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*	/* eat up '*'s not followed by '/'s */
<comment>\n		{ lt_inc_stack(lt_args_sinc)->lineno++; }
<comment>"*"+"/"	BEGIN(INITIAL);

"import"		{ BEGIN(import); return IMPORT; }
<import>{filename}	{ got_filename = strdup(lt_args_text); }
<import>"\""		{ if (!got_filename) return '"'; }
<import>\n		{ lt_inc_stack(lt_args_sinc)->lineno++;
			  if (!got_filename) { BEGIN(INITIAL); }
			 else {
				launch_preprocessor = 1;
				lt_args_lval.s = got_filename;
				return FILENAME;
			}
			}
<import>.		{ ; }

"const"			{ return CONST; }
<<EOF>>			{ return END; }
"struct"		{ return STRUCT; }
"func"			{ return FUNC; }
{name}[!~^]?(\/[opxduh])?	{ lt_args_lval.s = strdup(lt_args_text); return NAME; }
{type_prefix}		{ lt_args_lval.s = strdup(lt_args_text); return TYPE_PREFIX; }
"\*"+			{ lt_args_lval.s = strdup(lt_args_text); return POINTER; }
"[]"			{ return SLICE; }
")"			{ return ')'; }
"("			{ return '('; }
"}"			{ return '}'; }
"{"			{ return '{'; }
";"			{ return ';'; }
","			{ return ','; }
"="			{ return '='; }
\			{ ; }
\n			{ lt_inc_stack(lt_args_sinc)->lineno++; return NEWLINE; }
.			{ ; }

%%

#ifndef yywrap
int yywrap()
{
	return 1; 
	/* XXX not to get the compiler 'not used' warning */
	yyunput(0, NULL); 
	input();
}
#endif

void lt_args_error(const char *m)
{
	PRINT_ERROR("header file [%s] line %d: %s\n", 
		lt_inc_stack(lt_args_sinc)->file,
		lt_inc_stack(lt_args_sinc)->lineno,
		m);
}
