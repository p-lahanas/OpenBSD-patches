PROG=pfexecd
SRCS=parse.y pfexecd.c
CFLAGS += -I${.CURDIR} -Wall -Werror

MAN=pfexecd.8 pfexecd.conf.5
LDADD = -levent

.include <bsd.prog.mk> #add bsd auto-generation of targets