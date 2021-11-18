#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/un.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/task.h>
#include <sys/filedesc.h>

#include <sys/pfexec.h>
#include <sys/pfexecvar.h>

#include <sys/mount.h>
#include <sys/syscallargs.h>

int check_pfexec_resp_args(struct pfexec_resp *);
int pfexec_setresuid(struct proc *, uid_t);
int pfexec_setresgid(struct proc *, gid_t);
int pfexec_setresgroups(struct proc *, uint32_t, uint32_t *);
void pfexec_soconnect(void *);
static int change_dir(struct nameidata *, struct proc *);

/* Global error value for socket connection error */
int errorso = 0;

/* Arguments to pass to the soconnect call */
struct pfexec_soconnect_args {
	struct socket *so;
	struct mbuf *nam;
};

int
sys_pfexecve(struct proc *p, void *v, register_t *retval)
{
	errorso = 0;
	struct sys_execve_args /* {
	syscallarg(const char *) path;
	syscallarg(char *const *) argp;
	syscallarg(char *const *) envp;
	} */ *uaps;

	struct sys_pfexecve_args /* {
	// syscallarg(const struct pfexecve_opts *) opts;
	// syscallarg(const char *) path;
	// syscallarg(char *const *) argp;
	// syscallarg(char *const *) envp;
	// } */ *uap = v;

	uaps = v + sizeof(struct pfexecve_opts *);

	int error;
	const char *root = "root";

	if ((error = single_thread_set(p, SINGLE_UNWIND, 1)))
		return error;


	/* Begin filling out pfexec request data also allocate mem for resp. */
	struct pfexec_req *request = (struct pfexec_req *)
	    malloc(sizeof(*request), M_TEMP, M_WAITOK);
	memset(request, 0, sizeof(*request));

	struct pfexecve_opts *pfo = (struct pfexecve_opts *)
	    malloc(sizeof(*pfo), M_TEMP, M_WAITOK);
	memset(pfo, 0, sizeof(*pfo));

	struct pfexec_resp *resp = (struct pfexec_resp *)
	    malloc(sizeof(*resp), M_TEMP, M_WAITOK);
	memset(resp, 0, sizeof(*resp));

	error = copyin(SCARG(uap, opts), pfo, sizeof(*pfo));
	if (error != 0) {
		return error;
	}

	/* Check that only known flags are set */
	if (pfo->pfo_flags & ~PFEXECVE_ALL_FLAGS) {
		error = EINVAL;
		goto bad;
	}

	struct process *pr = p->p_p;
	request->pfr_pid = pr->ps_pid;

	/*
	 * Variables to store the original uids/guids in case
	 * anything goes wrong.
	 */
	uid_t orig_uid;
	gid_t orig_gid;
	short orig_ngroups;
	gid_t orig_groups[NGROUPS_MAX];


	request->pfr_uid = p->p_ucred->cr_uid;
	orig_uid = p->p_ucred->cr_uid;

	request->pfr_gid = p->p_ucred->cr_gid;
	orig_gid = p->p_ucred->cr_gid;

	request->pfr_ngroups = (uint32_t)p->p_ucred->cr_ngroups;
	orig_ngroups = p->p_ucred->cr_ngroups;

	/* Copy and type cast the groups across */
	for (int i = 0; i  < NGROUPS_MAX; i++) {
		request->pfr_groups[i] = (uint32_t)p->p_ucred->cr_groups[i];
		orig_groups[i] = p->p_ucred->cr_groups[i];
	}

	if (pfo->pfo_flags & PFEXECVE_USER) {
		strlcpy(request->pfr_req_user, pfo->pfo_user,
		    strnlen(pfo->pfo_user, LOGIN_NAME_MAX - 1) + 1);
	} else {
		strlcpy(request->pfr_req_user, root, LOGIN_NAME_MAX);
	}

	request->pfr_req_flags = pfo->pfo_flags;

	size_t pathlen;
	int err;

	if ((err = copyinstr(SCARG(uap, path), request->pfr_path,
	    PATH_MAX - 1, &pathlen)) != 0) {
		error = err;
		goto bad;
	}

	if (pathlen < 2) {
		error = EINVAL;
		goto bad;
	}

	/* Null terminate the path string */
	request->pfr_path[pathlen] = '\0';

	/* Check each element in argp array for null */
	char *argbuff = request->pfr_argarea;
	char * const *cpp, *sp, *dp;
	size_t len, off = 0;
	uint32_t argc;

	dp = argbuff;
	argc = 0;

	/* Now get argv & environment */
	if (!(cpp = SCARG(uap, argp))) {
		error = EFAULT;
		goto bad;
	}

	while (1) {
		len = argbuff + ARG_MAX - dp;
		if ((error = copyin(cpp, &sp, sizeof(sp))) != 0) {
			goto bad;
		}
		if (!sp)
			break;
		if ((error = copyinstr(sp, dp, len, &len)) != 0) {
			if (error == ENAMETOOLONG)
				error = E2BIG;
			goto bad;
		}

		request->pfr_argp[argc].pfa_len = len;
		request->pfr_argp[argc].pfa_offset = off;
		off += len;
		dp += len;
		cpp++;
		argc++;
	}


	request->pfr_argc = argc;

	/* Now do the same thing for the env stuff */
	char *argbuffenv = request->pfr_envarea;
	char * const *cppenv, *spenv, *dpenv;
	size_t lenenv, offenv = 0;
	uint32_t envc;

	dpenv = argbuffenv;
	envc = 0;

	/* Now get environment */
	if (!(cppenv = SCARG(uap, envp))) {
		error = EFAULT;
		goto bad;
	}

	while (1) {
		lenenv = argbuffenv + ARG_MAX - dpenv;
		if ((error = copyin(cppenv, &spenv, sizeof(spenv))) != 0) {
			goto bad;
		}
		if (!spenv)
			break;
		if ((error = copyinstr(spenv, dpenv, lenenv, &lenenv)) != 0) {
			if (error == ENAMETOOLONG)
				error = E2BIG;
			goto bad;
		}

		request->pfr_envp[envc].pfa_len = lenenv;
		request->pfr_envp[envc].pfa_offset = offenv;
		offenv += lenenv;
		dpenv += lenenv;
		cppenv++;
		envc++;
	}

	request->pfr_envc = envc;


	struct socket *so;
	struct mbuf *nam = NULL;

	if ((error = socreate(AF_UNIX, &so, SOCK_SEQPACKET, 0)))
		goto bad;


	struct sockaddr_un addr, *sa;

	bzero(&addr, sizeof(addr));
	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;

	strlcpy(addr.sun_path, PFEXECD_SOCK, sizeof(addr.sun_path));

	MGET(nam, M_WAIT, MT_SONAME);
	nam->m_len = addr.sun_len;
	sa = mtod(nam, struct sockaddr_un *);
	memcpy(sa, &addr, addr.sun_len);


	struct pfexec_soconnect_args args;
	args.so = so;
	args.nam = nam;
	struct task t = TASK_INITIALIZER(pfexec_soconnect, &args);

	task_add(systq, &t);

	while (task_pending(&t)) {
		tsleep(&t.t_flags, PWAIT, "soconnect", 10);
	}

	if (errorso != 0) {
		error = errorso;
		goto bad;
	}


	struct mbuf *m = NULL, *add = NULL;
	caddr_t data;

	size_t remaining = sizeof(*request);
	size_t cpyAmount = MAXMCLBYTES;
	off = 0;

	m = MCLGETL(m, M_WAIT, cpyAmount);
	m->m_len = cpyAmount;

	data = mtod(m, caddr_t);
	if ((error = kcopy(((void*) request) + off, data, cpyAmount)) != 0) {
		goto bad;
	}
	off += cpyAmount;
	remaining -= cpyAmount;

	while (remaining > 0) {
		if ((remaining) >= MAXMCLBYTES)
			cpyAmount = MAXMCLBYTES;
		else
			cpyAmount = remaining;

		add = MCLGETL(NULL, M_WAIT, cpyAmount);
		add->m_len = cpyAmount;
		data = mtod(add, caddr_t);

		if ((error = kcopy(((void*) request) + off, data, cpyAmount))
		    != 0) {
			goto bad;
		}

		off += cpyAmount;
		remaining -= cpyAmount;
		m_cat(m, add);
	}


	if ((error = sosend(so, NULL, NULL, m, NULL, MSG_EOR)) != 0) {
		soclose(so, MSG_DONTWAIT);
		goto bad;
	}

	/* Let's wait for the server to respond */
	struct uio uio;
	int rcvflg = MSG_EOR;
	struct mbuf *m0;

	MGET(m0, M_WAIT, MT_DATA);
	memset(&uio, 0, sizeof(uio));
	uio.uio_resid = sizeof(*resp);

	if ((error = soreceive(so, NULL, &uio, &m0, NULL, &rcvflg, 0))
	    != 0) {
		goto bad;
	}

	if (m0 == NULL) {
		error = EFAULT;
		goto bad;
	}

	m_copydata(m0, 0, sizeof(*resp), resp);

	/* Check the validity of resp arguments */
	if ((error = check_pfexec_resp_args(resp)) != 0)
		goto bad;


	if (resp->pfr_flags & PFRESP_UID) {
		pfexec_setresuid(p, resp->pfr_uid);
	}

	if (resp->pfr_flags & PFRESP_GID) {
		pfexec_setresgid(p, resp->pfr_gid);
	}

	if (resp->pfr_flags & PFRESP_GROUPS) {
		pfexec_setresgroups(p, resp->pfr_ngroups, resp->pfr_groups);
	}

	/*
	 * Try and call sys_execve. If anything goes wrong, reset the
	 * proc permissions.
	 */
	if ((error = sys_execve(p, uaps, retval)) != 0) {
		pfexec_setresuid(p, orig_uid);
		pfexec_setresgid(p, orig_gid);
		pfexec_setresgroups(p, orig_ngroups, orig_groups);
		goto bad;
	}

	if (resp->pfr_flags & PFRESP_CHROOT) {

		struct filedesc *fdp = p->p_fd;
		struct vnode *old_cdir, *old_rdir;
		int error;
		struct nameidata nd;

		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
		    resp->pfr_chroot, p);

		if ((error = change_dir(&nd, p)) != 0) {
			return (error);
		}

		if (fdp->fd_rdir != NULL) {
			vref(nd.ni_vp);
			old_rdir = fdp->fd_rdir;
			old_cdir = fdp->fd_cdir;
			fdp->fd_rdir = fdp->fd_cdir = nd.ni_vp;
			vrele(old_rdir);
			vrele(old_cdir);
		} else
			fdp->fd_rdir = nd.ni_vp;
	}

	soclose(so, MSG_DONTWAIT);

	free(request, M_TEMP, sizeof(*request));
	free(resp, M_TEMP, sizeof(*resp));
	free(pfo, M_TEMP, sizeof(*pfo));

	return (0);

	/* TODO: free the mbufs */

	/* Jump here if we need to free memory and exit with error */
bad:
	free(request, M_TEMP, sizeof(*request));
	free(resp, M_TEMP, sizeof(*resp));
	free(pfo, M_TEMP, sizeof(*pfo));

	return error;
}

int
check_pfexec_resp_args(struct pfexec_resp *resp)
{

	/* Check if pfexecd has responded with an error */
	if (resp->pfr_errno != 0)
		return resp->pfr_errno;

	/* Check the flags */
	uint32_t allflgs = PFRESP_UID | PFRESP_GID | PFRESP_GROUPS |
	    PFRESP_CHROOT | PFRESP_ENV;

	if (resp->pfr_flags & ~allflgs)
		return (EINVAL);

	if (resp->pfr_ngroups >= NGROUPS_MAX)
		return (EINVAL);


	if (resp->pfr_envc >= 1024)
		return (EINVAL);

	/* Return 0 if no invalid args */
	return (0);
}

int
pfexec_setresuid(struct proc *p, uid_t uid)
{

	struct process *pr = p->p_p;
	struct ucred *pruc, *newcred, *newcredproc;

	pruc = pr->ps_ucred;
	if (pruc->cr_uid == uid &&
	    pruc->cr_ruid == uid &&
	    pruc->cr_svuid == uid)
		return (0);

	/* Copy credentials so other references do not see our changes. */
	newcred = crget();
	newcredproc = crget();
	pruc = pr->ps_ucred;

	crset(newcred, pruc);
	crset(newcredproc, pruc);

	newcred->cr_ruid = uid;
	newcredproc->cr_ruid = uid;
	newcred->cr_uid = uid;
	newcredproc->cr_uid = uid;
	newcred->cr_svuid = uid;
	newcredproc->cr_svuid = uid;

	pr->ps_ucred = newcred;
	p->p_ucred = newcredproc;
	atomic_setbits_int(&p->p_p->ps_flags, PS_SUGID);

	/* now that we can sleep, transfer proc count to new user */
	if (uid != pruc->cr_ruid) {
		chgproccnt(pruc->cr_ruid, -1);
		chgproccnt(uid, 1);
	}
	/* TODO: need to do a hold here or something instead but yeah anyway */
	if (pruc != pr->ps_ucred && pruc != NULL)
		crfree(pruc);

	return (0);
}

int
pfexec_setresgid(struct proc *p, gid_t gid)
{

	struct process *pr = p->p_p;
	struct ucred *pruc, *newcred;

	pruc = pr->ps_ucred;

	/* Copy credentials so other references do not see our changes. */
	newcred = crget();
	pruc = pr->ps_ucred;

	crset(newcred, pruc);

	newcred->cr_rgid = gid;
	newcred->cr_gid = gid;
	newcred->cr_svgid = gid;

	pr->ps_ucred = newcred;
	p->p_ucred = newcred;
	crhold(newcred);

	atomic_setbits_int(&p->p_p->ps_flags, PS_SUGID);
	crfree(pruc);

	return (0);
}

int
pfexec_setresgroups(struct proc *p, uint32_t ngroups, uint32_t *groups)
{

	struct process *pr = p->p_p;
	struct ucred *pruc, *newcred;

	pruc = pr->ps_ucred;

	/* Copy credentials so other references do not see our changes. */
	newcred = crget();
	pruc = pr->ps_ucred;

	crset(newcred, pruc);

	newcred->cr_ngroups = ngroups;

	for (int i = 0; i < ngroups; i++) {
		newcred->cr_groups[i] = groups[i];
	}

	pr->ps_ucred = newcred;
	p->p_ucred = newcred;
	crhold(newcred);
	atomic_setbits_int(&p->p_p->ps_flags, PS_SUGID);
	crfree(pruc);

	return (0);
}

void
pfexec_soconnect(void *args)
{
	struct socket *so = ((struct pfexec_soconnect_args *)args)->so;
	struct mbuf *nam = ((struct pfexec_soconnect_args *)args)->nam;
	int s;

	s = solock(so);

	if ((soconnect(so, nam))) {
		errorso = ENOTCONN;
		sounlock(so, s);
		soclose(so, MSG_DONTWAIT);
		return;
	}

	/* Wait for connection */
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		sosleep_nsec(so, &so->so_timeo, PSOCK, "soconnect",
		    SEC_TO_NSEC(2));
	}

	if (so->so_error) {
		errorso = ENOTCONN;
		so->so_error = 0;
	}

	sounlock(so, s);
}

/*
 * Common routine for chroot and chdir.
 */
static int
change_dir(struct nameidata *ndp, struct proc *p)
{
	struct vnode *vp;
	int err;

	if ((err = namei(ndp)) != 0) {
		return (err);
	}
	vp = ndp->ni_vp;
	if (vp->v_type != VDIR) {
		err = ENOTDIR;
	} else {
		err = VOP_ACCESS(vp, VEXEC, p->p_ucred, p);
	}

	if (err) {
		vput(vp);
	} else {
		VOP_UNLOCK(vp);
	}

	return (err);
}