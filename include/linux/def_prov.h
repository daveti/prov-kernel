/*
 * Default Instantiations of Provenance plug functions
 *
 * Authors:  Adam M. Bates <amb@cs.uoregon.edu>           
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * Copyright (c) 2013 MIT Lincoln Laboratory 
 */

#include<linux/provenance.h>

int def_prov_init(void)
{
		return 0;
}

int def_prov_ptrace_access_check(struct task_struct *child,
					     unsigned int mode)
{
		return 0;
}

int def_prov_ptrace_traceme(struct task_struct *parent)
{
		return 0;
}

void def_prov_init_mnt_opts(struct provenance_mnt_opts *opts)
{
}

void def_prov_free_mnt_opts(struct provenance_mnt_opts *opts)
{
}

int def_prov_bprm_set_creds(struct linux_binprm *bprm)
{
		return 0;
}

int def_prov_bprm_check_provenance(struct linux_binprm *bprm)
{
		return 0;
}

void def_prov_bprm_committing_creds(struct linux_binprm *bprm)
{
}

void def_prov_bprm_committed_creds(struct linux_binprm *bprm)
{
}

int def_prov_bprm_secureexec(struct linux_binprm *bprm)
{
		return 0;
}

int def_prov_sb_alloc_provenance(struct super_block *sb)
{
		return 0;
}

void def_prov_sb_free_provenance(struct super_block *sb)
{ 
}

int def_prov_sb_copy_data(char *orig, char *copy)
{
		return 0;
}

int def_prov_sb_remount(struct super_block *sb, void *data)
{
		return 0;
}

int def_prov_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
		return 0;
}

int def_prov_sb_show_options(struct seq_file *m,
					   struct super_block *sb)
{
		return 0;
}

int def_prov_sb_statfs(struct dentry *dentry)
{
		return 0;
}

int def_prov_sb_mount(char *dev_name, struct path *path,
				    char *type, unsigned long flags,
				    void *data)
{
		return 0;
}

int def_prov_sb_check_sb(struct vfsmount *mnt,
				       struct path *path)
{
		return 0;
}

int def_prov_sb_umount(struct vfsmount *mnt, int flags)
{
		return 0;
}

void def_prov_sb_umount_close(struct vfsmount *mnt)
{ 
}

void def_prov_sb_umount_busy(struct vfsmount *mnt)
{ 
}

void def_prov_sb_post_remount(struct vfsmount *mnt,
					     unsigned long flags, void *data)
{ 
}

void def_prov_sb_post_addmount(struct vfsmount *mnt,
					     struct path *mountpoint)
{ 
}

int def_prov_sb_pivotroot(struct path *old_path,
					struct path *new_path)
{
		return 0;
}

void def_prov_sb_post_pivotroot(struct path *old_path,
					      struct path *new_path)
{ 
}

int def_prov_sb_set_mnt_opts(struct super_block *sb,
					   struct provenance_mnt_opts *opts)
{
		return 0;
}

void def_prov_sb_clone_mnt_opts(const struct super_block *oldsb,
					      struct super_block *newsb)
{ 
}

int def_prov_sb_parse_opts_str(char *options, struct provenance_mnt_opts *opts)
{
		return 0;
}

int def_prov_inode_alloc_provenance(struct inode *inode)
{
        	return 0;
}

void def_prov_inode_free_provenance(struct inode *inode)
{ 
}

int def_prov_inode_init_provenance(struct inode *inode,
						struct inode *dir,
						char **name,
						void **value,
						size_t *len)
{
		return -EOPNOTSUPP;
}

int def_prov_inode_create(struct inode *dir,
					 struct dentry *dentry,
					 int mode)
{
		return 0;
}

int def_prov_inode_link(struct dentry *old_dentry,
				       struct inode *dir,
				       struct dentry *new_dentry)
{
		return 0;
}

int def_prov_inode_unlink(struct inode *dir,
					 struct dentry *dentry)
{
      		return 0;
}

int def_prov_inode_symlink(struct inode *dir,
					  struct dentry *dentry,
					  const char *old_name)
{
      		return 0;
}

int def_prov_inode_mkdir(struct inode *dir,
					struct dentry *dentry,
					int mode)
{
      		return 0;
}

int def_prov_inode_rmdir(struct inode *dir,
					struct dentry *dentry)
{
      		return 0;
}

int def_prov_inode_mknod(struct inode *dir,
					struct dentry *dentry,
					int mode, dev_t dev)
{
      		return 0;
}

int def_prov_inode_rename(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry)
{
		return 0;
}

int def_prov_inode_readlink(struct dentry *dentry)
{
		return 0;
}

int def_prov_inode_follow_link(struct dentry *dentry,
					      struct nameidata *nd)
{
		return 0;
}

int def_prov_inode_permission(struct inode *inode, int mask)
{
        	return 0;
}

int def_prov_inode_setattr(struct dentry *dentry,
					  struct iattr *attr)
{
		return 0;
}

int def_prov_inode_getattr(struct vfsmount *mnt,
					  struct dentry *dentry)
{
		return 0;
}

void def_prov_inode_delete(struct inode *inode)
{
}

int def_prov_inode_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{
		return cap_inode_setxattr(dentry, name, value, size, flags);
}

void def_prov_inode_post_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{
}

int def_prov_inode_getxattr(struct dentry *dentry,
			const char *name)
{
		return 0;
}

int def_prov_inode_listxattr(struct dentry *dentry)
{
		return 0;
}

int def_prov_inode_removexattr(struct dentry *dentry,
			const char *name)
{
	      	return 0;
}

int def_prov_inode_need_killpriv(struct dentry *dentry)
{
	      	return 0;
}

int def_prov_inode_killpriv(struct dentry *dentry)
{
	      	return 0;
}

int def_prov_inode_getprovenance(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
		return -EOPNOTSUPP;
}

int def_prov_inode_setprovenance(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
		return -EOPNOTSUPP;
}

int def_prov_inode_listprovenance(struct inode *inode, char *buffer, size_t buffer_size)
{
		return 0;
}

void def_prov_inode_getprovid(const struct inode *inode, u32 *provid)
{
	        //*provid = 0;
}

/*
int send_unix_msg(struct sock *peersk)
{
	return 0;
}

void recv_unix_msg(struct sock *sk)
{
}

int send_tcp_msg(struct socket *sock)
{
	return 0;
}

void recv_tcp_msg(struct socket *sock)
{
}

int send_udp_msg(struct sk_buff *skb)
{
	return 0;
}

int recv_udp_msg(struct sk_buff *skb)
{
	return 0;
}
*/

int def_prov_socket_sendmsg(struct socket *sock, struct msghdr *msg,
		int size)
{
        	return 0;
}

int def_prov_socket_dgram_append(struct sock *sk, struct sk_buff *head)
{
		return 0;
}

int def_prov_socket_create(int family, int type, int protocol, int kern)
{
		return 0;
}

int def_prov_socket_post_create(struct socket *sock, int family,
                                int type, int protocol, int kern)
{
		return 0;	
}

int def_prov_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
		return 0;
}

int def_prov_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
		return 0;
}

int def_prov_socket_listen(struct socket *sock, int backlog)
{
		return 0;
}

int def_prov_socket_accept(struct socket *sock, struct socket *newsock)
{
		return 0;
}

int def_prov_unix_stream_connect(struct socket *sock, struct socket *other,
                                 struct sock *newsk)
{
        	return 0;
}

int def_prov_unix_may_send(struct socket *sock,  struct socket *other)
{
		return 0;
}

int def_prov_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			   int size, int flags)
{
		return 0;
}

int def_prov_socket_getsockname(struct socket *sock)
{
		return 0;
}

int def_prov_socket_getpeername(struct socket *sock)
{
		return 0;
}

int def_prov_socket_getsockopt(struct socket *sock, int level, int optname)
{
		return 0;
}

int def_prov_socket_setsockopt(struct socket *sock, int level, int optname)
{
		return 0;
}

int def_prov_socket_shutdown(struct socket *sock, int how)
{
		return 0;
}


void def_prov_socket_post_recvmsg(struct socket *sock, struct msghdr *msg,
		int size, int flags)
{
}

void def_prov_socket_dgram_post_recv(struct sock *sk, struct sk_buff *skb)
{
	
}

int def_prov_socket_getpeersec_stream(struct socket *sock, char __user *optval,
                                      int __user *optlen, unsigned len)
{
		return 0;
}

int def_prov_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
		return 0;
}

int def_prov_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req)
{
		return 0;
}

void def_prov_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req)
{

}

 int def_prov_sk_alloc_provenance(struct sock *sk, int family, gfp_t priority)
{
		return 0;
}

void def_prov_sk_free_provenance(struct sock *sk)
{
}

void def_prov_sk_clone_provenance(const struct sock *sk, struct sock *newsk)
{
}

void def_prov_sk_getprovid(struct sock *sk, u32 *provid)
{
}

int def_prov_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
		return 0;
}

int def_prov_skb_shinfo_alloc_provenance(struct sk_buff *skb, int recycling,
		gfp_t gfp)
{
        	return 0;
}

void def_prov_skb_shinfo_free_provenance(struct sk_buff *skb, int recycling)
{
        }

int def_prov_skb_shinfo_copy(struct sk_buff *skb,
		struct skb_shared_info *shinfo, gfp_t gfp)
{
		return 0;
}


void def_prov_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	
}

void def_prov_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
	
}

void def_prov_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
        
}

int def_prov_tun_dev_create(void)
{
		return 0;
}

void def_prov_tun_dev_post_create(struct sock *sk)
{
	
}

int def_prov_tun_dev_attach(struct sock *sk)
{
		return 0;
}

int def_prov_file_permission(struct file *file, int mask)
{
              	return 0;
}

int def_prov_file_alloc_provenance(struct file *file)
{
		return 0;
}

void def_prov_file_free_provenance(struct file *file)
{
}

int def_prov_file_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
		return 0;
}

int def_prov_file_mmap(struct file *file, unsigned long reqprot,
				     unsigned long prot,
				     unsigned long flags,
				     unsigned long addr,
				     unsigned long addr_only)
{
		return cap_file_mmap(file, reqprot, prot, flags, addr, addr_only);
}

int def_prov_file_mprotect(struct vm_area_struct *vma,
					 unsigned long reqprot,
					 unsigned long prot)
{
		return 0;
}

int def_prov_file_lock(struct file *file, unsigned int cmd)
{
		return 0;
}

int def_prov_file_fcntl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
		return 0;
}

int def_prov_file_set_fowner(struct file *file)
{
		return 0;
}

int def_prov_file_send_sigiotask(struct task_struct *tsk,
					       struct fown_struct *fown,
					       int sig)
{
		return 0;
}

int def_prov_file_receive(struct file *file)
{
		return 0;
}

int def_prov_dentry_open(struct file *file,
				       const struct cred *cred)
{
		return 0;
}

int def_prov_task_create(unsigned long clone_flags)
{
		return 0;
}

int def_prov_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
		return 0;
}

void def_prov_cred_free(struct cred *cred)
{
}

int def_prov_cred_prepare(struct cred *new,
					 const struct cred *old,
					 gfp_t gfp)
{
		return 0;
}

void def_prov_cred_commit(struct cred *new,
					 const struct cred *old)
{
	
}

void def_prov_cred_transfer(struct cred *new,
					   const struct cred *old)
{
	
}

int def_prov_kernel_act_as(struct cred *cred, u32 provid)
{
		return 0;
}

int def_prov_kernel_create_files_as(struct cred *cred,
						  struct inode *inode)
{
		return 0;
}

int def_prov_kernel_module_request(char *kmod_name)
{
		return 0;
}

int def_prov_task_setuid(uid_t id0, uid_t id1, uid_t id2,
				       int flags)
{
		return 0;
}

int def_prov_task_fix_setuid(struct cred *new,
					   const struct cred *old,
					   int flags)
{
		return cap_task_fix_setuid(new, old, flags);
}

int def_prov_task_setgid(gid_t id0, gid_t id1, gid_t id2,
				       int flags)
{
		return 0;
}

int def_prov_task_setpgid(struct task_struct *p, pid_t pgid)
{
		return 0;
}

int def_prov_task_getpgid(struct task_struct *p)
{
		return 0;
}

int def_prov_task_getsid(struct task_struct *p)
{
		return 0;
}

void def_prov_task_getprovid(struct task_struct *p, u32 *provid)
{
  //*provid = 0;
}

int def_prov_task_setgroups(struct group_info *group_info)
{
		return 0;
}

int def_prov_task_setnice(struct task_struct *p, int nice)
{
	      	return 0;
}

int def_prov_task_setioprio(struct task_struct *p, int ioprio)
{
	      	return 0;
}

int def_prov_task_getioprio(struct task_struct *p)
{
		return 0;
}

int def_prov_task_setrlimit(struct task_struct *p,
					  unsigned int resource,
					  struct rlimit *new_rlim)
{
		return 0;
}

int def_prov_task_setscheduler(struct task_struct *p,
					     int policy,
					     struct sched_param *lp)
{
	      	return 0;
}

int def_prov_task_getscheduler(struct task_struct *p)
{
		return 0;
}

int def_prov_task_movememory(struct task_struct *p)
{
		return 0;
}

int def_prov_task_kill(struct task_struct *p,
				     struct siginfo *info, int sig,
				     u32 provid)
{
		return 0;
}

int def_prov_task_wait(struct task_struct *p)
{
		return 0;
}

int def_prov_task_prctl(int option, unsigned long arg2,
				      unsigned long arg3,
				      unsigned long arg4,
				      unsigned long arg5)
{
		return cap_task_prctl(option, arg2, arg3, arg3, arg5);
}

void def_prov_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

int def_prov_ipc_permission(struct kern_ipc_perm *ipcp,
					  short flag)
{
		return 0;
}

void def_prov_ipc_getprovid(struct kern_ipc_perm *ipcp, u32 *provid)
{
		//*provid = 0;
}

int def_prov_msg_msg_alloc_provenance(struct msg_msg *msg)
{
		return 0;
}

void def_prov_msg_msg_free_provenance(struct msg_msg *msg)
{
}

int def_prov_msg_queue_alloc_provenance(struct msg_queue *msq)
{
		return 0;
}

void def_prov_msg_queue_free_provenance(struct msg_queue *msq)
{
}

int def_prov_msg_queue_associate(struct msg_queue *msq,
					       int msqflg)
{
		return 0;
}

int def_prov_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
		return 0;
}

int def_prov_msg_queue_msgsnd(struct msg_queue *msq,
					    struct msg_msg *msg, int msqflg)
{
		return 0;
}

int def_prov_msg_queue_msgrcv(struct msg_queue *msq,
					    struct msg_msg *msg,
					    struct task_struct *target,
					    long type, int mode)
{
		return 0;
}

int def_prov_shm_alloc_provenance(struct shmid_kernel *shp)
{
		return 0;
}

void def_prov_shm_free_provenance(struct shmid_kernel *shp)
{
}

int def_prov_shm_associate(struct shmid_kernel *shp,
					 int shmflg)
{
		return 0;
}

int def_prov_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
		return 0;
}

int def_prov_shm_shmat(struct shmid_kernel *shp,
				     char __user *shmaddr, int shmflg)
{
		return 0;
}

int def_prov_sem_alloc_provenance(struct sem_array *sma)
{
		return 0;
}

void def_prov_sem_free_provenance(struct sem_array *sma)
{
}

int def_prov_sem_associate(struct sem_array *sma, int semflg)
{
		return 0;
}

int def_prov_sem_semctl(struct sem_array *sma, int cmd)
{
		return 0;
}

int def_prov_sem_semop(struct sem_array *sma,
				     struct sembuf *sops, unsigned nsops,
				     int alter)
{
		return 0;
}

void def_prov_d_instantiate(struct dentry *dentry, struct inode *inode)
{
        }

int def_prov_getprocattr(struct task_struct *p, char *name, char **value)
{
		return -EINVAL;
}

int def_prov_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
		return -EINVAL;
}

int def_prov_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	      	return 0;
}

int def_prov_netlink_recv(struct sk_buff *skb, int cap)
{
	      	return 0;
}

int def_prov_provid_to_provctx(u32 provid, char **provdata, u32 *seclen)
{
		return -EOPNOTSUPP;
}

int def_prov_provctx_to_provid(const char *provdata,
					   u32 seclen,
					   u32 *provid)
{
		return -EOPNOTSUPP;
}

void def_prov_release_provctx(char *provdata, u32 seclen)
{
	
}

int def_prov_inode_notifyprovctx(struct inode *inode, void *ctx, u32 ctxlen)
{
		return -EOPNOTSUPP;
}
int def_prov_inode_setprovctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
		return -EOPNOTSUPP;
}
int def_prov_inode_getprovctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
		return -EOPNOTSUPP;
}

int def_prov_path_truncate(struct path *path, loff_t length,
					 unsigned int time_attrs)
{
		return 0;
}

static struct provenance_operations default_provenance_ops = {
        .name	= "default",
};

#define set_to_def_prov_if_null(ops, function)				\
  do {									\
    if (!ops->function) {						\
      ops->function = def_prov_##function;				\
      pr_debug("Had to override the " #function				\
	       " provenance operation with the default.\n");		\
    }									\
  } while (0)

void provenance_fixup_ops(struct provenance_operations *ops)
{
	set_to_def_prov_if_null(ops, ptrace_access_check);
	set_to_def_prov_if_null(ops, ptrace_traceme);
	/*
	set_to_def_prov_if_null(ops, capget);
	set_to_def_prov_if_null(ops, capset);
	set_to_def_prov_if_null(ops, acct);
	set_to_def_prov_if_null(ops, capable);
	set_to_def_prov_if_null(ops, quotactl);
	set_to_def_prov_if_null(ops, quota_on);
	set_to_def_prov_if_null(ops, sysctl);
	set_to_def_prov_if_null(ops, syslog);
	set_to_def_prov_if_null(ops, settime);
	set_to_def_prov_if_null(ops, vm_enough_memory);
	*/

	set_to_def_prov_if_null(ops, bprm_set_creds);
	set_to_def_prov_if_null(ops, bprm_committing_creds);
	set_to_def_prov_if_null(ops, bprm_committed_creds);
	set_to_def_prov_if_null(ops, bprm_check_provenance);
	set_to_def_prov_if_null(ops, bprm_secureexec);
	set_to_def_prov_if_null(ops, sb_alloc_provenance);
	set_to_def_prov_if_null(ops, sb_free_provenance);
	set_to_def_prov_if_null(ops, sb_copy_data);
	set_to_def_prov_if_null(ops, sb_remount);
	set_to_def_prov_if_null(ops, sb_kern_mount);
	set_to_def_prov_if_null(ops, sb_show_options);
	set_to_def_prov_if_null(ops, sb_statfs);
	set_to_def_prov_if_null(ops, sb_mount);
	set_to_def_prov_if_null(ops, sb_check_sb);
	set_to_def_prov_if_null(ops, sb_umount);
	set_to_def_prov_if_null(ops, sb_umount_close);
	set_to_def_prov_if_null(ops, sb_umount_busy);
	set_to_def_prov_if_null(ops, sb_post_remount);
	set_to_def_prov_if_null(ops, sb_post_addmount);
	set_to_def_prov_if_null(ops, sb_pivotroot);
	set_to_def_prov_if_null(ops, sb_post_pivotroot);
	set_to_def_prov_if_null(ops, sb_set_mnt_opts);
	set_to_def_prov_if_null(ops, sb_clone_mnt_opts);
	set_to_def_prov_if_null(ops, sb_parse_opts_str);
	set_to_def_prov_if_null(ops, inode_alloc_provenance);
	set_to_def_prov_if_null(ops, inode_free_provenance);
	set_to_def_prov_if_null(ops, inode_init_provenance);
	set_to_def_prov_if_null(ops, inode_create);
	set_to_def_prov_if_null(ops, inode_link);
	set_to_def_prov_if_null(ops, inode_unlink);
	set_to_def_prov_if_null(ops, inode_symlink);
	set_to_def_prov_if_null(ops, inode_mkdir);
	set_to_def_prov_if_null(ops, inode_rmdir);
	set_to_def_prov_if_null(ops, inode_mknod);
	set_to_def_prov_if_null(ops, inode_rename);
	set_to_def_prov_if_null(ops, inode_readlink);
	set_to_def_prov_if_null(ops, inode_follow_link);
	set_to_def_prov_if_null(ops, inode_permission);
	set_to_def_prov_if_null(ops, inode_setattr);
	set_to_def_prov_if_null(ops, inode_getattr);
	set_to_def_prov_if_null(ops, inode_delete);
	set_to_def_prov_if_null(ops, inode_setxattr);
	set_to_def_prov_if_null(ops, inode_post_setxattr);
	set_to_def_prov_if_null(ops, inode_getxattr);
	set_to_def_prov_if_null(ops, inode_listxattr);
	set_to_def_prov_if_null(ops, inode_removexattr);
	set_to_def_prov_if_null(ops, inode_need_killpriv);
	set_to_def_prov_if_null(ops, inode_killpriv);
	set_to_def_prov_if_null(ops, inode_getprovenance);
	set_to_def_prov_if_null(ops, inode_setprovenance);
	set_to_def_prov_if_null(ops, inode_listprovenance);
	set_to_def_prov_if_null(ops, inode_getprovid);
#ifdef CONFIG_PROVENANCE_PATH
	set_to_def_prov_if_null(ops, path_mknod);
	set_to_def_prov_if_null(ops, path_mkdir);
	set_to_def_prov_if_null(ops, path_rmdir);
	set_to_def_prov_if_null(ops, path_unlink);
	set_to_def_prov_if_null(ops, path_symlink);
	set_to_def_prov_if_null(ops, path_link);
	set_to_def_prov_if_null(ops, path_rename);
#endif
	set_to_def_prov_if_null(ops, path_truncate);
	set_to_def_prov_if_null(ops, file_permission);
	set_to_def_prov_if_null(ops, file_alloc_provenance);
	set_to_def_prov_if_null(ops, file_free_provenance);
	set_to_def_prov_if_null(ops, file_ioctl);
	set_to_def_prov_if_null(ops, file_mmap);
	set_to_def_prov_if_null(ops, file_mprotect);
	set_to_def_prov_if_null(ops, file_lock);
	set_to_def_prov_if_null(ops, file_fcntl);
	set_to_def_prov_if_null(ops, file_set_fowner);
	set_to_def_prov_if_null(ops, file_send_sigiotask);
	set_to_def_prov_if_null(ops, file_receive);
	set_to_def_prov_if_null(ops, dentry_open);
	set_to_def_prov_if_null(ops, task_create);
	set_to_def_prov_if_null(ops, cred_alloc_blank);
	set_to_def_prov_if_null(ops, cred_free);
	set_to_def_prov_if_null(ops, cred_prepare);
	set_to_def_prov_if_null(ops, cred_commit);
	set_to_def_prov_if_null(ops, cred_transfer);
	set_to_def_prov_if_null(ops, kernel_act_as);
	set_to_def_prov_if_null(ops, kernel_create_files_as);
	set_to_def_prov_if_null(ops, kernel_module_request);
	set_to_def_prov_if_null(ops, task_setuid);
	set_to_def_prov_if_null(ops, task_fix_setuid);
	set_to_def_prov_if_null(ops, task_setgid);
	set_to_def_prov_if_null(ops, task_setpgid);
	set_to_def_prov_if_null(ops, task_getpgid);
	set_to_def_prov_if_null(ops, task_getsid);
	set_to_def_prov_if_null(ops, task_getprovid);
	set_to_def_prov_if_null(ops, task_setgroups);
	set_to_def_prov_if_null(ops, task_setnice);
	set_to_def_prov_if_null(ops, task_setioprio);
	set_to_def_prov_if_null(ops, task_getioprio);
	set_to_def_prov_if_null(ops, task_setrlimit);
	set_to_def_prov_if_null(ops, task_setscheduler);
	set_to_def_prov_if_null(ops, task_getscheduler);
	set_to_def_prov_if_null(ops, task_movememory);
	set_to_def_prov_if_null(ops, task_wait);
	set_to_def_prov_if_null(ops, task_kill);
	set_to_def_prov_if_null(ops, task_prctl);
	set_to_def_prov_if_null(ops, task_to_inode);
	set_to_def_prov_if_null(ops, ipc_permission);
	set_to_def_prov_if_null(ops, ipc_getprovid);
	set_to_def_prov_if_null(ops, msg_msg_alloc_provenance);
	set_to_def_prov_if_null(ops, msg_msg_free_provenance);
	set_to_def_prov_if_null(ops, msg_queue_alloc_provenance);
	set_to_def_prov_if_null(ops, msg_queue_free_provenance);
	set_to_def_prov_if_null(ops, msg_queue_associate);
	set_to_def_prov_if_null(ops, msg_queue_msgctl);
	set_to_def_prov_if_null(ops, msg_queue_msgsnd);
	set_to_def_prov_if_null(ops, msg_queue_msgrcv);
	set_to_def_prov_if_null(ops, shm_alloc_provenance);
	set_to_def_prov_if_null(ops, shm_free_provenance);
	set_to_def_prov_if_null(ops, shm_associate);
	set_to_def_prov_if_null(ops, shm_shmctl);
	set_to_def_prov_if_null(ops, shm_shmat);
	set_to_def_prov_if_null(ops, sem_alloc_provenance);
	set_to_def_prov_if_null(ops, sem_free_provenance);
	set_to_def_prov_if_null(ops, sem_associate);
	set_to_def_prov_if_null(ops, sem_semctl);
	set_to_def_prov_if_null(ops, sem_semop);
	set_to_def_prov_if_null(ops, netlink_send);
	set_to_def_prov_if_null(ops, netlink_recv);
	set_to_def_prov_if_null(ops, d_instantiate);
	set_to_def_prov_if_null(ops, getprocattr);
	set_to_def_prov_if_null(ops, setprocattr);
	/*
	set_to_def_prov_if_null(ops, secid_to_secctx);
	set_to_def_prov_if_null(ops, secctx_to_secid);
	set_to_def_prov_if_null(ops, release_secctx);
	set_to_def_prov_if_null(ops, inode_notifysecctx);
	set_to_def_prov_if_null(ops, inode_setsecctx);
	set_to_def_prov_if_null(ops, inode_getsecctx);
	*/
	set_to_def_prov_if_null(ops, unix_stream_connect);
	set_to_def_prov_if_null(ops, unix_may_send);
	set_to_def_prov_if_null(ops, socket_create);
	set_to_def_prov_if_null(ops, socket_post_create);
	set_to_def_prov_if_null(ops, socket_bind);
	set_to_def_prov_if_null(ops, socket_connect);
	set_to_def_prov_if_null(ops, socket_listen);
	set_to_def_prov_if_null(ops, socket_accept);
	set_to_def_prov_if_null(ops, socket_sendmsg);
	set_to_def_prov_if_null(ops, socket_recvmsg);
        set_to_def_prov_if_null(ops, socket_post_recvmsg);
	set_to_def_prov_if_null(ops, socket_getsockname);
	set_to_def_prov_if_null(ops, socket_getpeername);
	set_to_def_prov_if_null(ops, socket_setsockopt);
	set_to_def_prov_if_null(ops, socket_getsockopt);
	set_to_def_prov_if_null(ops, socket_shutdown);
	set_to_def_prov_if_null(ops, socket_sock_rcv_skb);
        set_to_def_prov_if_null(ops, skb_shinfo_alloc_provenance);
	set_to_def_prov_if_null(ops, skb_shinfo_free_provenance);
        set_to_def_prov_if_null(ops, skb_shinfo_copy);
        set_to_def_prov_if_null(ops, socket_dgram_append);
        set_to_def_prov_if_null(ops, socket_dgram_post_recv);
	set_to_def_prov_if_null(ops, socket_getpeersec_stream);
	set_to_def_prov_if_null(ops, socket_getpeersec_dgram);
	set_to_def_prov_if_null(ops, sk_alloc_provenance);
	set_to_def_prov_if_null(ops, sk_free_provenance);
	set_to_def_prov_if_null(ops, sk_clone_provenance);
	set_to_def_prov_if_null(ops, sk_classify_flow);

	set_to_def_prov_if_null(ops, sk_getprovid);
	/*
	set_to_def_prov_if_null(ops, sock_graft);
	*/
	set_to_def_prov_if_null(ops, inet_conn_request);
	set_to_def_prov_if_null(ops, inet_csk_clone);
	set_to_def_prov_if_null(ops, inet_conn_established);
	set_to_def_prov_if_null(ops, req_classify_flow);
	set_to_def_prov_if_null(ops, tun_dev_create);
	set_to_def_prov_if_null(ops, tun_dev_post_create);
	set_to_def_prov_if_null(ops, tun_dev_attach);
}
