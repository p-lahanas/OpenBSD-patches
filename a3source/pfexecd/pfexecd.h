struct rule {
	int action;
	int options;
	const char *ident;
	const char *target;
	const char *cmd;
	const char **cmdargs;
	const char **envlist;
	const char *group;
	const char **groupargs;
	const char *chroot;
};

extern struct rule **rules;
extern size_t nrules;
extern int parse_errors;

extern const char *formerpath;

struct passwd;

char **prepenv(const struct rule *, const struct passwd *,
    const struct passwd *);

#define PERMIT	1
#define DENY	2

#define NOPASS		0x1
#define KEEPENV		0x2
#define PERSIST		0x4
#define NOLOG		0x8
#define KEEPGROUPS	0x10
#define SETGROUPS	0x20
#define CHROOT		0x40

#define AUTH_FAILED	-1
#define AUTH_OK		0
#define AUTH_RETRIES	3