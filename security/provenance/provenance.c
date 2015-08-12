/*
 * Provenance plug functions
 *
 * Derived from security.c 
 *
 * Authors:  Adam M. Bates <amb@cs.uoregon.edu>           
 *
 * Copyright (C) 2001 WireX Communications, Inc <chris@wirex.com>
 * Copyright (C) 2001-2002 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2001 Networks Associates Technology, Inc <ssmalley@nai.com>
 * Copyright (C) 2013 MIT Lincoln Laboratory 
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/provenance.h>
#include <linux/security.h>
#include <linux/def_prov.h>
#include <linux/ima.h>

/* Boot-time LSM user choice */
static __initdata char chosen_lpm[PROVENANCE_NAME_MAX + 1];

/* things that live in def_prov.h */
//comment these to get it working again
extern struct provenance_operations default_provenance_ops;
extern void provenance_fixup_ops(struct provenance_operations *ops);

/*
struct provenance_operations default_provenance_ops = {
	.name	= "default",
};
*/

struct provenance_operations *provenance_ops;	/* Initialized to NULL */

static inline int verify(struct provenance_operations *ops)
{
	/* verify the provenance_operations structure exists */
	if (!ops)
		return -EINVAL;
	//Not sure if we need this (it is in capability.c)
	provenance_fixup_ops(ops);
	return 0;
}

static void __init do_provenance_initcalls(void)
{
	initcall_t *call;
	call = __provenance_initcall_start;
	while (call < __provenance_initcall_end) {
		(*call) ();
		call++;
	}
}

/**
 * provenance_init - initializes the provenance framework
 *
 * This should be called early in the kernel initialization sequence.
 */
int __init provenance_init(void)
{
	printk(KERN_INFO "Provenance Framework initialized\n");

	provenance_fixup_ops(&default_provenance_ops);
	provenance_ops = &default_provenance_ops;
	do_provenance_initcalls();

	return 0;
}

/* Save user chosen LSM */
static int __init choose_lpm(char *str)
{
	strncpy(chosen_lpm, str, PROVENANCE_NAME_MAX);
	return 1;
}
__setup("provenance=", choose_lpm);

/**
 * provenance_module_enable - Load given provenance module on boot ?
 * @ops: a pointer to the struct provenance_operations that is to be checked.
 *
 * Each LSM must pass this method before registering its own operations
 * to avoid provenance registration races. This method may also be used
 * to check if your LSM is currently loaded during kernel initialization.
 *
 * Return true if:
 *	-The passed LSM is the one chosen by user at boot time,
 *	-or user didn't specify a specific LSM and we're the first to ask
 *	 for registration permission,
 *	-or the passed LSM is currently loaded.
 * Otherwise, return false.
 */
int __init provenance_module_enable(struct provenance_operations *ops)
{
	if (!*chosen_lpm)
		strncpy(chosen_lpm, ops->name, PROVENANCE_NAME_MAX);
	else if (strncmp(ops->name, chosen_lpm, PROVENANCE_NAME_MAX))
		return 0;

	return 1;
}

asmlinkage unsigned long sys_current_provenance_id(void){

  const struct cred_provenance * curprov = current_provenance();

  printk("Provenance Monitor: Relaying provenance ID %lu to user space\n",(unsigned long)curprov->cpid);

  return  curprov->cpid;
}

asmlinkage unsigned long sys_process_id_to_provenance_id(int pid){

  struct cred_provenance * prov;

  struct task_struct * target;
  target = find_task_by_vpid(pid);
  prov = (struct cred_provenance *)target->real_cred->provenance;

  printk("Provenance Monitor: Process %lu resolve to provenance id %lu\n",
	 (unsigned long)pid,
	 (unsigned long)prov->cpid);

  return  prov->cpid;
}


/**
 * register_provenance - registers a provenance framework with the kernel
 * @ops: a pointer to the struct provenance_options that is to be registered
 *
 * This function allows a provenance module to register itself with the
 * kernel provenance subsystem.  Some rudimentary checking is done on the @ops
 * value passed to this function. You'll need to check first if your LSM
 * is allowed to register its @ops by calling provenance_module_enable(@ops).
 *
 * If there is already a provenance module registered with the kernel,
 * an error will be returned.  Otherwise %0 is returned on success.
 */
int register_provenance(struct provenance_operations *ops)
{
	if (verify(ops)) {
		printk(KERN_DEBUG "%s could not verify "
		       "provenance_operations structure.\n", __func__);
		return -EINVAL;
	}

	if (provenance_ops != &default_provenance_ops)
		return -EAGAIN;

	provenance_ops = ops;

	return 0;
}

/* Provenance operations */

int provenance_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
	return provenance_ops->ptrace_access_check(child, mode);
}

int provenance_ptrace_traceme(struct task_struct *parent)
{
	return provenance_ops->ptrace_traceme(parent);
}

int provenance_acct(struct file *file)
{
	return provenance_ops->acct(file);
}

int provenance_sysctl(struct ctl_table *table, int op)
{
	return provenance_ops->sysctl(table, op);
}

int provenance_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return provenance_ops->quotactl(cmds, type, id, sb);
}

int provenance_quota_on(struct dentry *dentry)
{
	return provenance_ops->quota_on(dentry);
}

int provenance_syslog(int type)
{
	return provenance_ops->syslog(type);
}

int provenance_settime(const struct timespec *ts, const struct timezone *tz)
{
	return provenance_ops->settime(ts, tz);
}

int provenance_vm_enough_memory(long pages)
{
	WARN_ON(current->mm == NULL);
	return provenance_ops->vm_enough_memory(current->mm, pages);
}

int provenance_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
	WARN_ON(mm == NULL);
	return provenance_ops->vm_enough_memory(mm, pages);
}

int provenance_vm_enough_memory_kern(long pages)
{
	/* If current->mm is a kernel thread then we will pass NULL,
	   for this specific case that is fine */
	return provenance_ops->vm_enough_memory(current->mm, pages);
}

int provenance_bprm_set_creds(struct linux_binprm *bprm)
{
	return provenance_ops->bprm_set_creds(bprm);
}

int provenance_bprm_check(struct linux_binprm *bprm)
{
	int ret;

	ret = provenance_ops->bprm_check_provenance(bprm);
	if (ret)
		return ret;
	return ima_bprm_check(bprm);
}

void provenance_bprm_committing_creds(struct linux_binprm *bprm)
{
	provenance_ops->bprm_committing_creds(bprm);
}

void provenance_bprm_committed_creds(struct linux_binprm *bprm)
{
	provenance_ops->bprm_committed_creds(bprm);
}

int provenance_bprm_secureexec(struct linux_binprm *bprm)
{
	return provenance_ops->bprm_secureexec(bprm);
}

int provenance_sb_alloc(struct super_block *sb)
{
	return provenance_ops->sb_alloc_provenance(sb);
}

void provenance_sb_free(struct super_block *sb)
{
	provenance_ops->sb_free_provenance(sb);
}

int provenance_sb_copy_data(char *orig, char *copy)
{
	return provenance_ops->sb_copy_data(orig, copy);
}
EXPORT_SYMBOL(provenance_sb_copy_data);

int provenance_sb_remount(struct super_block *sb, void *data)
{
	return provenance_ops->sb_remount(sb, data);
}

int provenance_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return provenance_ops->sb_kern_mount(sb, flags, data);
}

int provenance_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return provenance_ops->sb_show_options(m, sb);
}

int provenance_sb_statfs(struct dentry *dentry)
{
	return provenance_ops->sb_statfs(dentry);
}

int provenance_sb_mount(char *dev_name, struct path *path,
                       char *type, unsigned long flags, void *data)
{
	return provenance_ops->sb_mount(dev_name, path, type, flags, data);
}

int provenance_sb_check_sb(struct vfsmount *mnt, struct path *path)
{
	return provenance_ops->sb_check_sb(mnt, path);
}

int provenance_sb_umount(struct vfsmount *mnt, int flags)
{
	return provenance_ops->sb_umount(mnt, flags);
}

void provenance_sb_umount_close(struct vfsmount *mnt)
{
	provenance_ops->sb_umount_close(mnt);
}

void provenance_sb_umount_busy(struct vfsmount *mnt)
{
	provenance_ops->sb_umount_busy(mnt);
}

void provenance_sb_post_remount(struct vfsmount *mnt, unsigned long flags, void *data)
{
	provenance_ops->sb_post_remount(mnt, flags, data);
}

void provenance_sb_post_addmount(struct vfsmount *mnt, struct path *mountpoint)
{
	provenance_ops->sb_post_addmount(mnt, mountpoint);
}

int provenance_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	return provenance_ops->sb_pivotroot(old_path, new_path);
}

void provenance_sb_post_pivotroot(struct path *old_path, struct path *new_path)
{
	provenance_ops->sb_post_pivotroot(old_path, new_path);
}

int provenance_sb_set_mnt_opts(struct super_block *sb,
				struct provenance_mnt_opts *opts)
{
	return provenance_ops->sb_set_mnt_opts(sb, opts);
}
EXPORT_SYMBOL(provenance_sb_set_mnt_opts);

void provenance_sb_clone_mnt_opts(const struct super_block *oldsb,
				struct super_block *newsb)
{
	provenance_ops->sb_clone_mnt_opts(oldsb, newsb);
}
EXPORT_SYMBOL(provenance_sb_clone_mnt_opts);

int provenance_sb_parse_opts_str(char *options, struct provenance_mnt_opts *opts)
{
	return provenance_ops->sb_parse_opts_str(options, opts);
}
EXPORT_SYMBOL(provenance_sb_parse_opts_str);

int provenance_inode_alloc(struct inode *inode)
{
	int ret;

	inode->i_provenance = NULL;
	ret =  provenance_ops->inode_alloc_provenance(inode);
	if (ret)
		return ret;
	ret = ima_inode_alloc(inode);
	if (ret)
		provenance_inode_free(inode);
	return ret;
}

void provenance_inode_free(struct inode *inode)
{
	ima_inode_free(inode);
	provenance_ops->inode_free_provenance(inode);
}

int provenance_inode_init_provenance(struct inode *inode, struct inode *dir,
				  char **name, void **value, size_t *len)
{
	if (unlikely(IS_PRIVATE(inode)))
		return -EOPNOTSUPP;
	return provenance_ops->inode_init_provenance(inode, dir, name, value, len);
}
EXPORT_SYMBOL(provenance_inode_init_provenance);

int provenance_path_truncate(struct path *path, loff_t length,
			   unsigned int time_attrs)
{
	if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
		return 0;
	return provenance_ops->path_truncate(path, length, time_attrs);
}

int provenance_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return provenance_ops->inode_create(dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(provenance_inode_create);

int provenance_inode_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
		return 0;
	return provenance_ops->inode_link(old_dentry, dir, new_dentry);
}

int provenance_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_unlink(dir, dentry);
}

int provenance_inode_symlink(struct inode *dir, struct dentry *dentry,
			    const char *old_name)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return provenance_ops->inode_symlink(dir, dentry, old_name);
}

int provenance_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return provenance_ops->inode_mkdir(dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(provenance_inode_mkdir);

int provenance_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_rmdir(dir, dentry);
}

int provenance_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	if (unlikely(IS_PRIVATE(dir)))
		return 0;
	return provenance_ops->inode_mknod(dir, dentry, mode, dev);
}

int provenance_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
        if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
            (new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
		return 0;
	return provenance_ops->inode_rename(old_dir, old_dentry,
					   new_dir, new_dentry);
}

int provenance_inode_readlink(struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_readlink(dentry);
}

int provenance_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_follow_link(dentry, nd);
}

int provenance_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return provenance_ops->inode_permission(inode, mask);
}

int provenance_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_setattr(dentry, attr);
}
EXPORT_SYMBOL_GPL(provenance_inode_setattr);

int provenance_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_getattr(mnt, dentry);
}

void provenance_inode_delete(struct inode *inode)
{
	if (unlikely(IS_PRIVATE(inode)))
		return;
	provenance_ops->inode_delete(inode);
}

int provenance_inode_setxattr(struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_setxattr(dentry, name, value, size, flags);
}

void provenance_inode_post_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return;
	provenance_ops->inode_post_setxattr(dentry, name, value, size, flags);
}

int provenance_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_getxattr(dentry, name);
}

int provenance_inode_listxattr(struct dentry *dentry)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_listxattr(dentry);
}

int provenance_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (unlikely(IS_PRIVATE(dentry->d_inode)))
		return 0;
	return provenance_ops->inode_removexattr(dentry, name);
}

int provenance_inode_need_killpriv(struct dentry *dentry)
{
	return provenance_ops->inode_need_killpriv(dentry);
}

int provenance_inode_killpriv(struct dentry *dentry)
{
	return provenance_ops->inode_killpriv(dentry);
}

int provenance_inode_getprovenance(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return provenance_ops->inode_getprovenance(inode, name, buffer, alloc);
}

int provenance_inode_setprovenance(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return provenance_ops->inode_setprovenance(inode, name, value, size, flags);
}

int provenance_inode_listprovenance(struct inode *inode, char *buffer, size_t buffer_size)
{
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	return provenance_ops->inode_listprovenance(inode, buffer, buffer_size);
}

void provenance_inode_getprovid(const struct inode *inode, u32 *provid)
{
	provenance_ops->inode_getprovid(inode, provid);
}

int provenance_file_permission(struct file *file, int mask)
{
	return provenance_ops->file_permission(file, mask);
}

int provenance_file_alloc(struct file *file)
{
	return provenance_ops->file_alloc_provenance(file);
}

void provenance_file_free(struct file *file)
{
	provenance_ops->file_free_provenance(file);
}

int provenance_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return provenance_ops->file_ioctl(file, cmd, arg);
}

int provenance_file_mmap(struct file *file, unsigned long reqprot,
			unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only)
{
	int ret;

	ret = provenance_ops->file_mmap(file, reqprot, prot, flags, addr, addr_only);
	if (ret)
		return ret;
	return ima_file_mmap(file, prot);
}

int provenance_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			    unsigned long prot)
{
	return provenance_ops->file_mprotect(vma, reqprot, prot);
}

int provenance_file_lock(struct file *file, unsigned int cmd)
{
	return provenance_ops->file_lock(file, cmd);
}

int provenance_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return provenance_ops->file_fcntl(file, cmd, arg);
}

int provenance_file_set_fowner(struct file *file)
{
	return provenance_ops->file_set_fowner(file);
}

int provenance_file_send_sigiotask(struct task_struct *tsk,
				  struct fown_struct *fown, int sig)
{
	return provenance_ops->file_send_sigiotask(tsk, fown, sig);
}

int provenance_file_receive(struct file *file)
{
	return provenance_ops->file_receive(file);
}

int provenance_dentry_open(struct file *file, const struct cred *cred)
{
	return provenance_ops->dentry_open(file, cred);
}

int provenance_task_create(unsigned long clone_flags)
{
	return provenance_ops->task_create(clone_flags);
}

int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return provenance_ops->cred_alloc_blank(cred, gfp);
}

void provenance_cred_free(struct cred *cred)
{
	provenance_ops->cred_free(cred);
}

int provenance_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
	return provenance_ops->cred_prepare(new, old, gfp);
}

void provenance_commit_creds(struct cred *new, const struct cred *old)
{
	provenance_ops->cred_commit(new, old);
}

void provenance_transfer_creds(struct cred *new, const struct cred *old)
{
	provenance_ops->cred_transfer(new, old);
}

int provenance_kernel_act_as(struct cred *new, u32 provid)
{
	return provenance_ops->kernel_act_as(new, provid);
}

int provenance_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return provenance_ops->kernel_create_files_as(new, inode);
}

int provenance_kernel_module_request(char *kmod_name)
{
	return provenance_ops->kernel_module_request(kmod_name);
}

int provenance_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return provenance_ops->task_setuid(id0, id1, id2, flags);
}

int provenance_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags)
{
	return provenance_ops->task_fix_setuid(new, old, flags);
}

int provenance_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	return provenance_ops->task_setgid(id0, id1, id2, flags);
}

int provenance_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return provenance_ops->task_setpgid(p, pgid);
}

int provenance_task_getpgid(struct task_struct *p)
{
	return provenance_ops->task_getpgid(p);
}

int provenance_task_getsid(struct task_struct *p)
{
	return provenance_ops->task_getsid(p);
}

void provenance_task_getprovid(struct task_struct *p, u32 *provid)
{
	provenance_ops->task_getprovid(p, provid);
}
EXPORT_SYMBOL(provenance_task_getprovid);

int provenance_task_setgroups(struct group_info *group_info)
{
	return provenance_ops->task_setgroups(group_info);
}

int provenance_task_setnice(struct task_struct *p, int nice)
{
	return provenance_ops->task_setnice(p, nice);
}

int provenance_task_setioprio(struct task_struct *p, int ioprio)
{
	return provenance_ops->task_setioprio(p, ioprio);
}

int provenance_task_getioprio(struct task_struct *p)
{
	return provenance_ops->task_getioprio(p);
}

int provenance_task_setrlimit(struct task_struct *p, unsigned int resource,
		struct rlimit *new_rlim)
{
	return provenance_ops->task_setrlimit(p, resource, new_rlim);
}

int provenance_task_setscheduler(struct task_struct *p,
				int policy, struct sched_param *lp)
{
	return provenance_ops->task_setscheduler(p, policy, lp);
}

int provenance_task_getscheduler(struct task_struct *p)
{
	return provenance_ops->task_getscheduler(p);
}

int provenance_task_movememory(struct task_struct *p)
{
	return provenance_ops->task_movememory(p);
}

int provenance_task_kill(struct task_struct *p, struct siginfo *info,
			int sig, u32 provid)
{
	return provenance_ops->task_kill(p, info, sig, provid);
}

int provenance_task_wait(struct task_struct *p)
{
	return provenance_ops->task_wait(p);
}

int provenance_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			 unsigned long arg4, unsigned long arg5)
{
	return provenance_ops->task_prctl(option, arg2, arg3, arg4, arg5);
}

void provenance_task_to_inode(struct task_struct *p, struct inode *inode)
{
	provenance_ops->task_to_inode(p, inode);
}

int provenance_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return provenance_ops->ipc_permission(ipcp, flag);
}

void provenance_ipc_getprovid(struct kern_ipc_perm *ipcp, u32 *provid)
{
	provenance_ops->ipc_getprovid(ipcp, provid);
}

int provenance_msg_msg_alloc(struct msg_msg *msg)
{
	return provenance_ops->msg_msg_alloc_provenance(msg);
}

void provenance_msg_msg_free(struct msg_msg *msg)
{
	provenance_ops->msg_msg_free_provenance(msg);
}

int provenance_msg_queue_alloc(struct msg_queue *msq)
{
	return provenance_ops->msg_queue_alloc_provenance(msq);
}

void provenance_msg_queue_free(struct msg_queue *msq)
{
	provenance_ops->msg_queue_free_provenance(msq);
}

int provenance_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return provenance_ops->msg_queue_associate(msq, msqflg);
}

int provenance_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return provenance_ops->msg_queue_msgctl(msq, cmd);
}

int provenance_msg_queue_msgsnd(struct msg_queue *msq,
			       struct msg_msg *msg, int msqflg)
{
	return provenance_ops->msg_queue_msgsnd(msq, msg, msqflg);
}

int provenance_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
			       struct task_struct *target, long type, int mode)
{
	return provenance_ops->msg_queue_msgrcv(msq, msg, target, type, mode);
}

int provenance_shm_alloc(struct shmid_kernel *shp)
{
	return provenance_ops->shm_alloc_provenance(shp);
}

void provenance_shm_free(struct shmid_kernel *shp)
{
	provenance_ops->shm_free_provenance(shp);
}

int provenance_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return provenance_ops->shm_associate(shp, shmflg);
}

int provenance_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return provenance_ops->shm_shmctl(shp, cmd);
}

int provenance_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr, int shmflg)
{
	return provenance_ops->shm_shmat(shp, shmaddr, shmflg);
}

int provenance_sem_alloc(struct sem_array *sma)
{
	return provenance_ops->sem_alloc_provenance(sma);
}

void provenance_sem_free(struct sem_array *sma)
{
	provenance_ops->sem_free_provenance(sma);
}

int provenance_sem_associate(struct sem_array *sma, int semflg)
{
	return provenance_ops->sem_associate(sma, semflg);
}

int provenance_sem_semctl(struct sem_array *sma, int cmd)
{
	return provenance_ops->sem_semctl(sma, cmd);
}

int provenance_sem_semop(struct sem_array *sma, struct sembuf *sops,
			unsigned nsops, int alter)
{
	return provenance_ops->sem_semop(sma, sops, nsops, alter);
}

void provenance_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (unlikely(inode && IS_PRIVATE(inode)))
		return;
	provenance_ops->d_instantiate(dentry, inode);
}
EXPORT_SYMBOL(provenance_d_instantiate);

int provenance_getprocattr(struct task_struct *p, char *name, char **value)
{
	return provenance_ops->getprocattr(p, name, value);
}

int provenance_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	return provenance_ops->setprocattr(p, name, value, size);
}

int provenance_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return provenance_ops->netlink_send(sk, skb);
}

int provenance_netlink_recv(struct sk_buff *skb, int cap)
{
	return provenance_ops->netlink_recv(skb, cap);
}
EXPORT_SYMBOL(provenance_netlink_recv);

int provenance_provid_to_provctx(u32 provid, char **provdata, u32 *provlen)
{
	return provenance_ops->provid_to_provctx(provid, provdata, provlen);
}
EXPORT_SYMBOL(provenance_provid_to_provctx);

int provenance_provctx_to_provid(const char *provdata, u32 provlen, u32 *provid)
{
	return provenance_ops->provctx_to_provid(provdata, provlen, provid);
}
EXPORT_SYMBOL(provenance_provctx_to_provid);

void provenance_release_provctx(char *provdata, u32 provlen)
{
	provenance_ops->release_provctx(provdata, provlen);
}
EXPORT_SYMBOL(provenance_release_provctx);

int provenance_inode_notifyprovctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return provenance_ops->inode_notifyprovctx(inode, ctx, ctxlen);
}
EXPORT_SYMBOL(provenance_inode_notifyprovctx);

int provenance_inode_setprovctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return provenance_ops->inode_setprovctx(dentry, ctx, ctxlen);
}
EXPORT_SYMBOL(provenance_inode_setprovctx);

int provenance_inode_getprovctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return provenance_ops->inode_getprovctx(inode, ctx, ctxlen);
}
EXPORT_SYMBOL(provenance_inode_getprovctx);

int provenance_unix_stream_connect(struct socket *sock, struct socket *other,
				 struct sock *newsk)
{
	return provenance_ops->unix_stream_connect(sock, other, newsk);
}
EXPORT_SYMBOL(provenance_unix_stream_connect);

int provenance_unix_may_send(struct socket *sock,  struct socket *other)
{
	return provenance_ops->unix_may_send(sock, other);
}
EXPORT_SYMBOL(provenance_unix_may_send);

int provenance_socket_create(int family, int type, int protocol, int kern)
{
	return provenance_ops->socket_create(family, type, protocol, kern);
}

int provenance_socket_post_create(struct socket *sock, int family,
				int type, int protocol, int kern)
{
	return provenance_ops->socket_post_create(sock, family, type,
						protocol, kern);
}

int provenance_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return provenance_ops->socket_bind(sock, address, addrlen);
}

int provenance_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return provenance_ops->socket_connect(sock, address, addrlen);
}

int provenance_socket_listen(struct socket *sock, int backlog)
{
	return provenance_ops->socket_listen(sock, backlog);
}

int provenance_socket_accept(struct socket *sock, struct socket *newsock)
{
	return provenance_ops->socket_accept(sock, newsock);
}

int provenance_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return provenance_ops->socket_sendmsg(sock, msg, size);
}

int provenance_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			    int size, int flags)
{
	return provenance_ops->socket_recvmsg(sock, msg, size, flags);
}

void provenance_socket_post_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags)
{
        provenance_ops->socket_post_recvmsg(sock, msg, size, flags);
}


int provenance_socket_getsockname(struct socket *sock)
{
	return provenance_ops->socket_getsockname(sock);
}

int provenance_socket_getpeername(struct socket *sock)
{
	return provenance_ops->socket_getpeername(sock);
}

int provenance_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return provenance_ops->socket_getsockopt(sock, level, optname);
}

int provenance_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return provenance_ops->socket_setsockopt(sock, level, optname);
}

int provenance_socket_shutdown(struct socket *sock, int how)
{
	return provenance_ops->socket_shutdown(sock, how);
}

int provenance_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return provenance_ops->socket_sock_rcv_skb(sk, skb);
}
EXPORT_SYMBOL(provenance_sock_rcv_skb);

int provenance_skb_shinfo_alloc(struct sk_buff *skb, int recycling, gfp_t gfp)
{
  return provenance_ops->skb_shinfo_alloc_provenance(skb, recycling, gfp);
}

void provenance_skb_shinfo_free(struct sk_buff *skb, int recycling)
{
  provenance_ops->skb_shinfo_free_provenance(skb, recycling);
}

int provenance_skb_shinfo_copy(struct sk_buff *skb,
			     struct skb_shared_info *shinfo, gfp_t gfp)
{
  return provenance_ops->skb_shinfo_copy(skb, shinfo, gfp);
}

int provenance_socket_dgram_append(struct sock *sk, struct sk_buff *head)
{
  return provenance_ops->socket_dgram_append(sk, head);
}
EXPORT_SYMBOL(provenance_socket_dgram_append);

void provenance_socket_dgram_post_recv(struct sock *sk, struct sk_buff *skb)
{
  provenance_ops->socket_dgram_post_recv(sk, skb);
}
EXPORT_SYMBOL(provenance_socket_dgram_post_recv);

int provenance_socket_getpeersec_stream(struct socket *sock, char __user *optval,
				      int __user *optlen, unsigned len)
{
	return provenance_ops->socket_getpeersec_stream(sock, optval, optlen, len);
}

int provenance_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *provid)
{
	return provenance_ops->socket_getpeersec_dgram(sock, skb, provid);
}
EXPORT_SYMBOL(provenance_socket_getpeersec_dgram);

int provenance_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
	return provenance_ops->sk_alloc_provenance(sk, family, priority);
}

void provenance_sk_free(struct sock *sk)
{
	provenance_ops->sk_free_provenance(sk);
}

void provenance_sk_clone(const struct sock *sk, struct sock *newsk)
{
	provenance_ops->sk_clone_provenance(sk, newsk);
}

void provenance_sk_getprovid(struct sock *sk, u32 *provid)
{

}
EXPORT_SYMBOL(provenance_sk_getprovid);

void provenance_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
	provenance_ops->sk_getprovid(sk, &fl->provid);
}
EXPORT_SYMBOL(provenance_sk_classify_flow);

void provenance_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
	provenance_ops->req_classify_flow(req, fl);
}
EXPORT_SYMBOL(provenance_req_classify_flow);

void provenance_sock_graft(struct sock *sk, struct socket *parent)
{
	provenance_ops->sock_graft(sk, parent);
}
EXPORT_SYMBOL(provenance_sock_graft);

int provenance_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req)
{
	return provenance_ops->inet_conn_request(sk, skb, req);
}
EXPORT_SYMBOL(provenance_inet_conn_request);

void provenance_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req)
{
	provenance_ops->inet_csk_clone(newsk, req);
}

void provenance_inet_conn_established(struct sock *sk,
			struct sk_buff *skb)
{
	provenance_ops->inet_conn_established(sk, skb);
}

int provenance_tun_dev_create(void)
{
	return provenance_ops->tun_dev_create();
}
EXPORT_SYMBOL(provenance_tun_dev_create);

void provenance_tun_dev_post_create(struct sock *sk)
{
	return provenance_ops->tun_dev_post_create(sk);
}
EXPORT_SYMBOL(provenance_tun_dev_post_create);

int provenance_tun_dev_attach(struct sock *sk)
{
	return provenance_ops->tun_dev_attach(sk);
}
EXPORT_SYMBOL(provenance_tun_dev_attach);

