#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/resourcevar.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/poll.h>
#include <sys/tty.h>
#include <sys/errno.h>
#include <sys/namei.h>
#include <sys/filio.h>
#include <sys/syslog.h>
#include <sys/kernel.h>

#include <dev/acct.h>

/* Internal global for accounting message generation counter */
static unsigned int seqcount;

/* Set all features to be disabled by default */
static unsigned int enabledFeatures;
static unsigned int numTrackedFiles;

/* File opening state */
#define FALSE   0
#define TRUE    1
static unsigned int readOnly;

/* Waiting channel */
static unsigned int *wc;

/* Resource lock for the driver */
static struct rwlock acct_devlock;

/*
 * Msg Queue Data Structure - Needs to hold messages of varying lengths (void *)
 */
struct acct_message {
        
        void                      *msg;
        size_t                    msgLength;
        TAILQ_ENTRY(acct_message) entries;
};

/* Define Message Queue Head */
static TAILQ_HEAD(acct_msgq, acct_message) msg_queue;

/*
 * Queue to hold each tracked file
 */
struct file_entry {
        struct vnode            *acct_vp;
        uint32_t                acct_ena;  /* Enabled events for this file */
        uint32_t                acct_cond; /* Enabled conditions */
        char                    *path;
        TAILQ_ENTRY(file_entry) files;
};

static TAILQ_HEAD(tracked_filesq, file_entry) tfile_queue;


union acct_any {
        struct acct_common      common;
        struct acct_fork        fork;
        struct acct_exec        exec;
        struct acct_exit        exit;
        struct acct_open        open;
        struct acct_rename      rename;
        struct acct_unlink      unlink;
        struct acct_close       close;
};

/* Internal utility functions */
void acct_common_pop(struct acct_common *, struct process *);


/* Process accounting hooks */
void
acct_fork(struct process *pr) 
{
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_FORK)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);
        
        /* Allocate memory which does wait if unavailable */
        struct acct_fork *acct = (struct acct_fork *) 
            malloc(sizeof(struct acct_fork), M_DEVBUF, M_WAITOK);
        
        acct->ac_cpid = pr->ps_pid;
        
        /* Pass the parent process as pr is the child */
        acct_common_pop(&acct->ac_common, pr->ps_pptr);
        
        /* Set the acct len, type and seq */
        acct->ac_common.ac_len = sizeof(struct acct_fork);
        acct->ac_common.ac_type = ACCT_MSG_FORK;

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_fork);
        msg->msg = (void *) acct;

        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

void
acct_exec(struct process *pr)
{
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_EXEC)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);
        
        /* Allocate memory */
        struct acct_exec *acct = (struct acct_exec *) 
            malloc(sizeof(struct acct_exec), M_DEVBUF, M_WAITOK);
        
        acct_common_pop(&acct->ac_common, pr);
        
        /* Set the acct len, type and seq */
        acct->ac_common.ac_len = sizeof(struct acct_exec);
        acct->ac_common.ac_type = ACCT_MSG_EXEC;

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_exec);
        msg->msg = (void *) acct;
        
        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

void
acct_exit(struct process *pr)
{
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_EXIT)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);

        struct timespec ut, st;
        int t;

        /* The waiting version of malloc */
        struct acct_exit *acct = (struct acct_exit *) 
            malloc(sizeof(struct acct_exit), M_DEVBUF, M_WAITOK);
        
        acct_common_pop(&acct->ac_common, pr);
        
        /* Set the acct len, type and seq */
        acct->ac_common.ac_len = sizeof(struct acct_exit);
        acct->ac_common.ac_type = ACCT_MSG_EXIT;

        /* 
         * Calculate the user and system time usage. We are not interested in
         * the interrupt time usage (NULL).
         */
        calctsru(&pr->ps_tu, &ut, &st, NULL);
        acct->ac_utime = ut;
        acct->ac_stime = st;
        
        /* Average memory usage */
        struct proc *p = pr->ps_mainproc;
        struct rusage *r;
        struct timespec tmp;
        
        r = &p->p_ru;
        timespecadd(&ut, &st, &tmp);
        t = tmp.tv_sec * hz + tmp.tv_nsec / (1000 * tick);
        if (t) 
                acct->ac_mem = (r->ru_ixrss + r->ru_idrss + r->ru_isrss) / t;
        else 
                acct->ac_mem = 0;

        /* Count of IO blocks */
        acct->ac_io = r->ru_inblock + r->ru_oublock;

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_exit);
        msg->msg = (void *) acct;
        
        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

/* File accounting hooks */
void 
acct_open(struct process *pr, struct vnode *vfile, int errno, int mode, 
    const char *path)
{
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_OPEN)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);

        /* Allocate memory */
        struct acct_open *acct = (struct acct_open *) 
             malloc(sizeof(struct acct_open), M_DEVBUF, M_WAITOK);
        
        acct_common_pop(&acct->ac_common, pr);
        
        /* Set the acct len, type */
        acct->ac_common.ac_len = sizeof(struct acct_open);
        acct->ac_common.ac_type = ACCT_MSG_OPEN;

        size_t copyLen = min(strlen(path) + 1, PATH_MAX); 
        memcpy(acct->ac_path, path, copyLen);
        /* If all else fails, null terminate */
        acct->ac_path[PATH_MAX - 1] = '\0';

        acct->ac_mode = mode;
        acct->ac_errno = errno;

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_open);
        msg->msg = (void *) acct;
        
        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

void 
acct_rename(struct process *pr, struct vnode *vfile, 
    const char *from, const char *to, int errno)
{ 
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_RENAME)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);

        /* Allocate memory */
        struct acct_rename *acct = (struct acct_rename *) 
             malloc(sizeof(struct acct_open), M_DEVBUF, M_WAITOK);
        
        acct_common_pop(&acct->ac_common, pr);
        
        /* Set the acct len, type */
        acct->ac_common.ac_len = sizeof(struct acct_rename);
        acct->ac_common.ac_type = ACCT_MSG_RENAME;

        size_t copyLenFrom = min(strlen(from) + 1, PATH_MAX); 
        size_t copyLenTo = min(strlen(to) + 1, PATH_MAX); 
        memcpy(acct->ac_path, from, copyLenFrom);
        memcpy(acct->ac_new, to, copyLenTo);
        /* If all else fails, null terminate */
        //acct->ac_path[PATH_MAX - 1] = '\0';
        //acct->ac_new[PATH_MAX - 1] = '\0';
        acct->ac_errno = errno;

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_rename);
        msg->msg = (void *) acct;
        
        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

void 
acct_unlink(struct process *pr, struct vnode *vfile, int errno, 
    const char * path)
{   
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_UNLINK)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);

        /* Allocate memory */
        struct acct_unlink *acct = (struct acct_unlink *) 
             malloc(sizeof(struct acct_unlink), M_DEVBUF, M_WAITOK);
        
        acct_common_pop(&acct->ac_common, pr);
        
        /* Set the acct len, type */
        acct->ac_common.ac_len = sizeof(struct acct_unlink);
        acct->ac_common.ac_type = ACCT_MSG_UNLINK;
        
        size_t copyLen = min(strlen(path) + 1, PATH_MAX); 
        memcpy(acct->ac_path, path, copyLen);
       
        acct->ac_errno = errno;

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_unlink);
        msg->msg = (void *) acct;
        
        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

void 
acct_close(struct process *pr, struct vnode *vfile)
{ 
        rw_enter(&acct_devlock, RW_WRITE); 
        if (!(enabledFeatures & ACCT_ENA_CLOSE)) {
                rw_exit(&acct_devlock);
                return;
        }
        rw_exit(&acct_devlock);

        /* Allocate memory */
        struct acct_close *acct = (struct acct_close *) 
             malloc(sizeof(struct acct_open), M_DEVBUF, M_WAITOK);
        
        acct_common_pop(&acct->ac_common, pr);
        
        /* Set the acct len, type */
        acct->ac_common.ac_len = sizeof(struct acct_close);
        acct->ac_common.ac_type = ACCT_MSG_CLOSE;

        /* If all else fails, null terminate */
        acct->ac_path[0] = '\0';

        /* Convert this element into an acct_message and insert in msg_queue */
        struct acct_message *msg = (struct acct_message *) 
            malloc(sizeof(struct acct_message), M_DEVBUF, M_WAITOK);

        msg->msgLength = sizeof(struct acct_close);
        msg->msg = (void *) acct;
        
        rw_enter(&acct_devlock, RW_WRITE); 
        TAILQ_INSERT_TAIL(&msg_queue, msg, entries);
        wakeup(wc);
        rw_exit(&acct_devlock);
}

/* Userland Entry Points */

void
acctattach(int n) 
{
        KERNEL_LOCK();
        
        /* Initialise the queues */
        TAILQ_INIT(&msg_queue);
        TAILQ_INIT(&tfile_queue);

        /* Reset the enabled auditing features */
        enabledFeatures &= ~(ACCT_ENA_ALL);

        /* Initialise the message generation counter */
        seqcount = 0;
        numTrackedFiles = 0;
        rw_init(&acct_devlock, "acct_devlock");
        wc = &seqcount;
        
        KERNEL_UNLOCK();
}

int 
acctopen(dev_t dev, int flag, int mode, struct proc* p) 
{
        /* No non-zero minor device*/
        if (minor(dev) != 0) {
                return (ENXIO);
        }

        /* Check that not open for just writing and not reading */  
        if ((flag & (1 << O_WRONLY)) && !(flag & (1 << O_RDONLY))) {
                return (EACCES);
        }
       
        /* Check if opened for reading */  
        if ((flag & (1 << O_WRONLY))) {
                readOnly = FALSE;
        }
        
        /* Can only be opened in exclusive lock mode */ 
        if (!(flag & O_EXLOCK)) {
                return (EACCES); 
        }
        /* Reset sequence numbner for generated messages */
        rw_enter(&acct_devlock, RW_WRITE);
        seqcount = 0;
        rw_exit(&acct_devlock);

        return (0);
}

int 
acctclose(dev_t dev, int flag, int mode, struct proc *p) 
{
        // struct acct_message *msg;

        rw_enter(&acct_devlock, RW_WRITE);
        readOnly = TRUE;
        rw_exit(&acct_devlock);

        /* Free all the vnodes in the file tracking tree (ensure to vrele) */

        return (0);
}

int 
acctread(dev_t dev, struct uio *uio, int ioflags)
{
        /* Dequeue a single message and copy it to userland. 
         * If the message is not available, the function should block.
         */
        int error;
        struct acct_message *msg;
        size_t len;
        void *buff;

        rw_enter(&acct_devlock, RW_WRITE);
        
        while ((msg = TAILQ_FIRST(&msg_queue)) == NULL) {
                rwsleep(wc, &acct_devlock, PWAIT, "acctread", 1000000);
        }
        
        TAILQ_REMOVE(&msg_queue, msg, entries);
        
        /* Set the sequence number of the message */
        ((union acct_any *)(msg->msg))->common.ac_seq = seqcount++;
        rw_exit(&acct_devlock);


        if (uio->uio_offset < 0)
                return (EINVAL);
        
        len = msg->msgLength;
        buff = (void*) msg->msg; 
                
        if (len > uio->uio_resid)
                len = uio->uio_resid;
                
        error = uiomove(buff, len, uio);

        if (error)
                return (error);

        free(msg->msg, M_DEVBUF, msg->msgLength);
        free(msg, M_DEVBUF, sizeof(*msg));
        
        return (0);
}

int 
acctwrite(dev_t dev, struct uio *uio, int ioflags)
{ 
        return (EOPNOTSUPP); /* Does not support writing */
}

int
acctpoll(dev_t dev, int events, struct proc *p)
{
        return (POLLERR); /* Does not support polling */
}

int
acctkqfilter(dev_t dev, struct knote *kn)
{
        return (EOPNOTSUPP); /* Does not support use with kqueue */
}

int
acctioctl(int fd, u_long cmd, struct acct_ctl *acctctl) {

        struct nameidata nd;
        struct proc *p;
        struct file_entry *f;

        int error = 0;

        switch(cmd) {
        case FIONREAD:
                rw_enter(&acct_devlock, RW_WRITE);
                if (TAILQ_EMPTY(&msg_queue))
                        return (0);
                struct acct_message *msg = TAILQ_FIRST(&msg_queue);
                rw_exit(&acct_devlock);
                return (int)msg->msgLength;
        case FIONBIO:
                error = ENOTTY;
                break;
        case ACCT_IOC_STATUS:
                rw_enter(&acct_devlock, RW_WRITE);
                acctctl->acct_ena = enabledFeatures;
                acctctl->acct_fcount = numTrackedFiles;
                rw_exit(&acct_devlock);
                break; 
        case ACCT_IOC_FSTATUS:
                rw_enter(&acct_devlock, RW_WRITE);
                TAILQ_FOREACH(f, &tfile_queue, files) {
                        if (strcmp(f->path, acctctl->acct_path) == 0) {
                                acctctl->acct_ena = f->acct_ena;
                                acctctl->acct_cond = f->acct_cond;
                                acctctl->acct_fcount = numTrackedFiles;
                        }
                }
                rw_exit(&acct_devlock);
                break; 
        case ACCT_IOC_ENABLE:
                /* Enable auditing features globally */
                rw_enter(&acct_devlock, RW_WRITE);

                if (readOnly) {
                        rw_exit(&acct_devlock);
                        error = ENOTTY;
                        break;
                }
                enabledFeatures |= acctctl->acct_ena; 
                rw_exit(&acct_devlock);
                break;
        case ACCT_IOC_DISABLE:
                rw_enter(&acct_devlock, RW_WRITE);
                if (readOnly) {
                        rw_exit(&acct_devlock);
                        error = ENOTTY;
                        break;
                }
                enabledFeatures &= (~acctctl->acct_ena);
                rw_exit(&acct_devlock);
                break; 
        case ACCT_IOC_TRACK_FILE:
                /* Resolve file path to vnode and track the vnode */

                /* Get the current thread struct */
                p = curproc; 

                NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | SAVENAME,
                    UIO_SYSSPACE, acctctl->acct_path, p);

                /* Fall through and return the error val */
                if ((error = namei(&nd) != 0))
                        break;
                /* Add the new vnode file to the list of tracked files */ 
                struct file_entry *fe = malloc(sizeof(*fe), M_DEVBUF, M_WAITOK);
                /* Release lock from namei */
                if (nd.ni_vp)
                        VOP_UNLOCK(nd.ni_vp);
                
                /* DON'T DECREMENT THE v_usercount yet */
                fe->acct_vp = nd.ni_vp;
                fe->acct_ena = acctctl->acct_ena;
                fe->acct_cond = acctctl->acct_cond;
               
                size_t copyLen = min(strlen(acctctl->acct_path) + 1, PATH_MAX); 
                fe->path = (char*) malloc(sizeof(char) * copyLen, 
                    M_DEVBUF, M_WAITOK);
                memcpy(fe->path, acctctl->acct_path, copyLen);
                TAILQ_INSERT_TAIL(&tfile_queue, fe, files);
                numTrackedFiles++;
                break;
        case ACCT_IOC_UNTRACK_FILE:
                rw_enter(&acct_devlock, RW_WRITE);
                TAILQ_FOREACH(f, &tfile_queue, files) {
                        if (strcmp(f->path, acctctl->acct_path) == 0) {
                                TAILQ_REMOVE(&tfile_queue, f, files);
                                free(f->path, M_DEVBUF, sizeof(char) 
                                    * strlen(f->path));
                                free(f, M_DEVBUF, sizeof(struct file_entry));
                                break;
                        }
                }
                numTrackedFiles--;
                rw_exit(&acct_devlock);
                break;
        }

        return (error);
}

/* Internal utility functions */

/* 
 * Populates the given acct_common message
 */
void
acct_common_pop(struct acct_common *acct, struct process *pr) 
{
        
        struct timespec booted, elapsed, realstart, uptime;

        /* 1. Copy the process name */ 
        memcpy(acct->ac_comm, pr->ps_comm, sizeof(acct->ac_comm));

        /* 2. Copy the process id, user id and group id */ 
        acct->ac_pid = pr->ps_pid;
        acct->ac_uid = pr->ps_ucred->cr_ruid;
        acct->ac_gid = pr->ps_ucred->cr_rgid;

        /* 3. Calculate the elapsed time and starting time */
        nanouptime(&uptime);
        nanoboottime(&booted);
        timespecadd(&booted, &pr->ps_start, &realstart);
        acct->ac_btime = realstart;
        timespecsub(&uptime, &pr->ps_start, &elapsed);
        acct->ac_etime = elapsed;
        
        /* 4. The terminal which started this process */
        if ((pr->ps_flags & PS_CONTROLT) && pr->ps_pgrp->pg_session->s_ttyp)
                acct->ac_tty = pr->ps_pgrp->pg_session->s_ttyp->t_dev;
        else
                acct->ac_tty = NODEV;

        /* 5. Boolean flags on how the process terminated */
        acct->ac_flag = pr->ps_acflag;
}