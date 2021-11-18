/* $OpenBSD: parse.y,v 1.29 2021/01/27 17:02:50 millert Exp $ */
/*
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

%{
#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include "pfexecd.h"

typedef struct {
	union {
		struct {
			int action;
			int options;
			const char *cmd;
			const char **cmdargs;
			const char *group;
			const char **groupargs;
			const char *chroot;
		};
		const char **strlist;
		const char *str;
	};
	int lineno;
	int colno;
} yystype;
#define YYSTYPE yystype

FILE *yyfp;

struct rule **rules;
size_t nrules;
static size_t maxrules;

int parse_errors = 0;

static void yyerror(const char *, ...);
static int yylex(void);

static size_t
arraylen(const char **arr)
{
	size_t cnt = 0;

	while (*arr) {
		cnt++;
		arr++;
	}
	return cnt;
}

%}

%token TPERMIT TDENY TAS TCMD TARGS TCHROOT
%token TNOPASS TNOLOG
%token TKEEPGROUPS TSETGROUPS
%token TSTRING

%%

grammar:	/* empty */
		| grammar '\n'
		| grammar rule '\n'
		| grammar rule
		| error '\n'
		;

rule:		action ident target cmd {
			struct rule *r;
			r = calloc(1, sizeof(*r));
			if (!r)
				errx(1, "can't allocate rule");
			r->action = $1.action;
			r->options = $1.options;
			r->group = $1.group;
			r->groupargs = $1.groupargs;
			r->chroot = $1.chroot;
			r->ident = $2.str;
			r->target = $3.str;
			r->cmd = $4.cmd;
			r->cmdargs = $4.cmdargs;
			if (nrules == maxrules) {
				if (maxrules == 0)
					maxrules = 32;
				rules = reallocarray(rules, maxrules,
				    2 * sizeof(*rules));
				if (!rules)
					errx(1, "can't allocate rules");
				maxrules *= 2;
			}
			rules[nrules++] = r;
		} ;

action:		TPERMIT options {
			$$.action = PERMIT;
			$$.options = $2.options;
			$$.groupargs = $2.groupargs;
			$$.group = $2.group;
			$$.chroot = $2.chroot;
		} | TDENY options {
			$$.action = DENY;
			$$.options = $2.options;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = NULL;
		} ;

options:	/* none */ {
			$$.options = 0;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = NULL;
		} | options option {
			$$.options = $1.options | $2.options;
			$$.groupargs = $1.groupargs;
			$$.group = $2.group;
			$$.chroot = $2.chroot;

			if ($2.groupargs) {
				if ($$.groupargs) {
					yyerror("can't have two groupargs"
					    "sections");
					YYERROR;
				} else
					$$.groupargs = $2.groupargs;
			}
		} ;

option:		TNOPASS {
			$$.options = NOPASS;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = NULL;
		} | TNOLOG {
			$$.options = NOLOG;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = NULL;
		} | TKEEPGROUPS {
			$$.options = KEEPGROUPS;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = NULL;
		} | TCHROOT '{' '}' {
			$$.options = CHROOT;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = NULL;
		} | TCHROOT '{' TSTRING '}' {
			$$.options = CHROOT;
			$$.groupargs = NULL;
			$$.group = NULL;
			$$.chroot = $3.str;

		} | TSETGROUPS '{' TSTRING strlist '}' {
			$$.options = SETGROUPS;
			$$.groupargs = $4.strlist;
			$$.group = $3.str;
		};

strlist:	/* empty */ {
			if (!($$.strlist = calloc(1, sizeof(char *))))
				errx(1, "can't allocate strlist");
		} | strlist TSTRING {
			int nstr = arraylen($1.strlist);
			if (!($$.strlist = reallocarray($1.strlist, nstr + 2,
			    sizeof(char *))))
				errx(1, "can't allocate strlist");
			$$.strlist[nstr] = $2.str;
			$$.strlist[nstr + 1] = NULL;
		} ;


ident:		TSTRING {
			$$.str = $1.str;
		} ;

target:		/* optional */ {
			$$.str = NULL;
		} | TAS TSTRING {
			$$.str = $2.str;
		} ;

cmd:		/* optional */ {
			$$.cmd = NULL;
			$$.cmdargs = NULL;
		} | TCMD TSTRING args {
			$$.cmd = $2.str;
			$$.cmdargs = $3.cmdargs;
		} ;

args:		/* empty */ {
			$$.cmdargs = NULL;
		} | TARGS strlist {
			$$.cmdargs = $2.strlist;
		} ;

%%

void
yyerror(const char *fmt, ...)
{
	va_list va;
	fprintf(stderr, "config: ");
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, " at line %d\n", yylval.lineno + 1);
	parse_errors++;
}

static struct keyword {
	const char *word;
	int token;
} keywords[] = {
	{ "deny", TDENY },
	{ "permit", TPERMIT },
	{ "as", TAS },
	{ "cmd", TCMD },
	{ "args", TARGS },
	{ "nopass", TNOPASS },
	{ "nolog", TNOLOG },
	{ "setgroups", TSETGROUPS },
	{ "keepgroups", TKEEPGROUPS },
	{ "chroot", TCHROOT },
};

int
yylex(void)
{
	char buf[1024], *ebuf, *p, *str;
	int c, quotes = 0, escape = 0, qpos = -1, nonkw = 0;
	size_t i;

	p = buf;
	ebuf = buf + sizeof(buf);

repeat:
	/* skip whitespace first */
	for (c = getc(yyfp); c == ' ' || c == '\t'; c = getc(yyfp))
		yylval.colno++;

	/* check for special one-character constructions */
	switch (c) {
		case '\n':
			yylval.colno = 0;
			yylval.lineno++;
			/* FALLTHROUGH */
		case '{':
		case '}':
			return c;
		case '#':
			/* skip comments; NUL is allowed; no continuation */
			while ((c = getc(yyfp)) != '\n')
				if (c == EOF)
					goto eof;
			yylval.colno = 0;
			yylval.lineno++;
			return c;
		case EOF:
			goto eof;
	}

	/* parsing next word */
	for (;; c = getc(yyfp), yylval.colno++) {
		switch (c) {
		case '\0':
			yyerror("unallowed character NUL in column %d",
			    yylval.colno + 1);
			escape = 0;
			continue;
		case '\\':
			escape = !escape;
			if (escape)
				continue;
			break;
		case '\n':
			if (quotes)
				yyerror("unterminated quotes in column %d",
				    qpos + 1);
			if (escape) {
				nonkw = 1;
				escape = 0;
				yylval.colno = 0;
				yylval.lineno++;
				continue;
			}
			goto eow;
		case EOF:
			if (escape)
				yyerror("unterminated escape in column %d",
				    yylval.colno);
			if (quotes)
				yyerror("unterminated quotes in column %d",
				    qpos + 1);
			goto eow;
			/* FALLTHROUGH */
		case '{':
		case '}':
		case '#':
		case ' ':
		case '\t':
			if (!escape && !quotes)
				goto eow;
			break;
		case '"':
			if (!escape) {
				quotes = !quotes;
				if (quotes) {
					nonkw = 1;
					qpos = yylval.colno;
				}
				continue;
			}
		}
		*p++ = c;
		if (p == ebuf) {
			yyerror("too long line");
			p = buf;
		}
		escape = 0;
	}

eow:
	*p = 0;
	if (c != EOF)
		ungetc(c, yyfp);
	if (p == buf) {
		/*
		 * There could be a number of reasons for empty buffer,
		 * and we handle all of them here, to avoid cluttering
		 * the main loop.
		 */
		if (c == EOF)
			goto eof;
		else if (qpos == -1)
			goto repeat;
	}
	if (!nonkw) {
		for (i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
			if (strcmp(buf, keywords[i].word) == 0)
				return keywords[i].token;
		}
	}
	if ((str = strdup(buf)) == NULL)
		err(1, "%s", __func__);

	yylval.str = str;
	return TSTRING;

eof:
	if (ferror(yyfp)) {
		yyerror("input error reading config");
	}
	return 0;
}