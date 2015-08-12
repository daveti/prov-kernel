/*
 * Linux provenance plug
 *
 * Copyright (c) 2013 MIT Lincoln Laboratory, Adam M. Bates <amb@cs.uoregon.edu>
 *
 * Adapted from security.h, written by:
 * Copyright (C) 2001 WireX Communications, Inc <chris@wirex.com>
 * Copyright (C) 2001 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2001 Networks Associates Technology, Inc <ssmalley@nai.com>
 * Copyright (C) 2001 James Morris <jmorris@intercode.com.au>
 * Copyright (C) 2001 Silicon Graphics, Inc. (Trust Technology Group)
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Due to this file being licensed under the GPL there is controversy over
 *	whether this permits you to write a module that #includes this file
 *	without placing your module under the GPL.  Please consult a lawyer for
 *	advice before doing this.
 *
 */

#ifndef __LINUX_PROVENANCE_H
#define __LINUX_PROVENANCE_H

#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/signal.h>
#include <linux/resource.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/mm.h> /* PAGE_ALIGN */
#include <linux/msg.h>
#include <linux/sched.h>
#include <linux/key.h>
#include <linux/xfrm.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/xattr.h>
#include <net/flow.h>

/* daveti: for DSA */
#include <crypto/hash.h>
#include <linux/dsa.h>
#include <linux/time.h>


/* Maximum number of letters for an LPM name string */
#define PROVENANCE_NAME_MAX	10

/* If capable should audit the provenance request */
#define PROVENANCE_CAP_NOAUDIT 0
#define PROVENANCE_CAP_AUDIT 1

/* IP options number */
#define IPOPT_PROVENANCE_CONTROL_COPY 0x9e
#define IPOPT_PROVENANCE_CONTROL_NOCOPY 0x1e
#define IPOPT_PROVENANCE_MEASURE_COPY 0xde
#define IPOPT_PROVENANCE_MEASURE_NOCOPY 0x5e
#define IPOPT_PROVENANCE IPOPT_PROVENANCE_CONTROL_COPY

/* Key names for xattrs */
#define XATTR_PROVENANCE_SUFFIX "provenance"
#define XATTR_NAME_PROVENANCE XATTR_SECURITY_PREFIX XATTR_PROVENANCE_SUFFIX

/* forward declares to avoid warnings */
struct msghdr;
struct sk_buff;
struct sock;
struct sockaddr;
struct socket;
struct flowi;
struct dst_entry;
struct seq_file;

struct sched_param;
struct request_sock;

//Bates: Consildating dsa and hifi ids into 'struct pktid'
struct pktid;
struct host_sockid;
struct sockid;

/* Structures referring to a receive queue on a specific system */
struct sockid {
	uint32_t low;
	uint16_t high;
} __attribute__((packed));

/* Old Hi-Fi sockid (len==22) */
struct host_sockid {
  struct sockid sock;
  uuid_be host;
} __attribute__((packed));

struct pktid{
  u8 signature[DSA_SIGNATURE_RAW_SIZE];
} __attribute__((packed));

/*
 * Values used in the task_provenance_ops calls
 */
/* setuid or setgid, id0 == uid or gid */
#define LPM_SETID_ID	1

/* setreuid or setregid, id0 == real, id1 == eff */
#define LPM_SETID_RE	2

/* setresuid or setresgid, id0 == real, id1 == eff, uid2 == saved */
#define LPM_SETID_RES	4

/* setfsuid or setfsgid, id0 == fsuid or fsgid */
#define LPM_SETID_FS	8


#ifdef CONFIG_PROVENANCE

struct provenance_mnt_opts {
	char **mnt_opts;
	int *mnt_opts_flags;
	int num_mnt_opts;
};

/*
 * Provenance label for struct cred.  "Opaque" processes are such that credentials
 * they fork are considered part of the original process, so we use a reference
 * counter to make sure these are freed at the appropriate time and no earlier.
 */
struct cred_provenance {
	struct kref refcount;
        u32 cpid;  /* The provenance id */
	int flags;
#define CPROV_INITED (1 << 0)
#define CPROV_OPAQUE (1 << 1)	
        u8 track;            /* Module-specific: whether or not to track this object */
        /* char * context;*/     /* Module-specific: variable-length string */
};

/*
 * Provenance label for filesystems via struct super_block.  This UUID is stored
 * in the xattr of the root inode for persistence.  If we encounter a filesystem
 * with no such label, we create one and store it ourselves.
 */
struct sb_provenance {
	uuid_be uuid;
        u8 track;            /* Module-specific: whether or not to track this object */
        /* char * context;*/     /* Module-specific: variable-length string */
};

/* Provenance structures for XSI IPC */
struct msg_provenance {
	u32 msgid;
        u8 track;            /* Module-specific: whether or not to track this object */
  /*char * context;*/     /* Module-specific: variable-length string */
};

struct shm_provenance {
	u32 shmid;
        u8 track;            /* Module-specific: whether or not to track this object */
  /*char * context;*/     /* Module-specific: variable-length string */
};

/* Provenance structures for sockets */
struct sock_provenance {
	struct host_sockid full_id;
	struct sockid short_id;
	u8 full_set;
	u8 short_set;
        u8 track;            /* Module-specific: whether or not to track this object */
  /* char * context; *//* Module-specific: variable-length string */
};

struct skb_provenance {
        struct host_sockid id;
	u8 set;
	struct pktid sig;
        u8 track;            /* Module-specific: whether or not to track this object */
  /* char * context; *//* Module-specific: variable-length string */
};

/* Provenance structure for inodes,files. */
struct inode_provenance {
        int is_new;
        u64 version;      /* Increment on each file write */
        u8 track;            /* Module-specific: whether or not to track this object */
  /*char * context;*/     /* Module-specific: variable-length string */
};

struct file_provenance {
        u8 track;            /* Module-specific: whether or not to track this object */
  /*char * context;*/     /* Module-specific: variable-length string */
};


static inline void provenance_init_mnt_opts(struct provenance_mnt_opts *opts)
{
	opts->mnt_opts = NULL;
	opts->mnt_opts_flags = NULL;
	opts->num_mnt_opts = 0;
}

static inline void provenance_free_mnt_opts(struct provenance_mnt_opts *opts)
{
	int i;
	if (opts->mnt_opts)
		for (i = 0; i < opts->num_mnt_opts; i++)
			kfree(opts->mnt_opts[i]);
	kfree(opts->mnt_opts);
	opts->mnt_opts = NULL;
	kfree(opts->mnt_opts_flags);
	opts->mnt_opts_flags = NULL;
	opts->num_mnt_opts = 0;
}

/**
 * struct provenance_operations - main provenance structure
 *
 * provenance module identifier.
 *
 * @name:
 *	A string that acts as a unique identifeir for the LPM with max number
 *	of characters = PROVENANCE_NAME_MAX.
 *
 * provenance hooks for program execution operations.
 *
 * @bprm_set_creds:
 *	Save provenance information in the bprm->provenance field, typically based
 *	on information about the bprm->file, for later use by the apply_creds
 *	hook.  This hook may also optionally check permissions (e.g. for
 *	transitions between provenance domains).
 *	This hook may be called multiple times during a single execve, e.g. for
 *	interpreters.  The hook can tell whether it has already been called by
 *	checking to see if @bprm->provenance is non-NULL.  If so, then the hook
 *	may decide either to retain the provenance information saved earlier or
 *	to replace it.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 * @bprm_check_provenance:
 *	This hook mediates the point when a search for a binary handler will
 *	begin.  It allows a check the @bprm->provenance value which is set in the
 *	preceding set_creds call.  The primary difference from set_creds is
 *	that the argv list and envp list are reliably available in @bprm.  This
 *	hook may be called multiple times during a single execve; and in each
 *	pass set_creds is called first.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 * @bprm_committing_creds:
 *	Prepare to install the new provenance attributes of a process being
 *	transformed by an execve operation, based on the old credentials
 *	pointed to by @current->cred and the information set in @bprm->cred by
 *	the bprm_set_creds hook.  @bprm points to the linux_binprm structure.
 *	This hook is a good place to perform state changes on the process such
 *	as closing open file descriptors to which access will no longer be
 *	granted when the attributes are changed.  This is called immediately
 *	before commit_creds().
 * @bprm_committed_creds:
 *	Tidy up after the installation of the new provenance attributes of a
 *	process being transformed by an execve operation.  The new credentials
 *	have, by this point, been set to @current->cred.  @bprm points to the
 *	linux_binprm structure.  This hook is a good place to perform state
 *	changes on the process such as clearing out non-inheritable signal
 *	state.  This is called immediately after commit_creds().
 * @bprm_secureexec:
 *	Return a boolean value (0 or 1) indicating whether a "secure exec"
 *	is required.  The flag is passed in the auxiliary table
 *	on the initial stack to the ELF interpreter to indicate whether libc
 *	should enable secure mode.
 *	@bprm contains the linux_binprm structure.
 *
 * provenance hooks for filesystem operations.
 *
 * @sb_alloc_provenance:
 *	Allocate and attach a provenance structure to the sb->s_provenance field.
 *	The s_provenance field is initialized to NULL when the structure is
 *	allocated.
 *	@sb contains the super_block structure to be modified.
 *	Return 0 if operation was successful.
 * @sb_free_provenance:
 *	Deallocate and clear the sb->s_provenance field.
 *	@sb contains the super_block structure to be modified.
 * @sb_show_options:
 *      Description unavialable.  See security.h.
 * @sb_statfs:
 *	Check permission before obtaining filesystem statistics for the @mnt
 *	mountpoint.
 *	@dentry is a handle on the superblock for the filesystem.
 *	Return 0 if permission is granted.
 * @sb_kern_mount:
 *      Description unavailable.  See security.h.
 * @sb_mount:
 *	Check permission before an object specified by @dev_name is mounted on
 *	the mount point named by @nd.  For an ordinary mount, @dev_name
 *	identifies a device if the file system type requires a device.  For a
 *	remount (@flags & MS_REMOUNT), @dev_name is irrelevant.  For a
 *	loopback/bind mount (@flags & MS_BIND), @dev_name identifies the
 *	pathname of the object being mounted.
 *	@dev_name contains the name for object being mounted.
 *	@path contains the path for mount point object.
 *	@type contains the filesystem type.
 *	@flags contains the mount flags.
 *	@data contains the filesystem-specific data.
 *	Return 0 if permission is granted.
 * @sb_copy_data:
 *	Allow mount option data to be copied prior to parsing by the filesystem,
 *	so that the provenance module can extract provenance-specific mount
 *	options cleanly (a filesystem may modify the data e.g. with strsep()).
 *	This also allows the original mount data to be stripped of provenance-
 *	specific options to avoid having to make filesystems aware of them.
 *	@type the type of filesystem being mounted.
 *	@orig the original mount data copied from userspace.
 *	@copy copied data which will be passed to the provenance module.
 *	Returns 0 if the copy was successful.
 * @sb_check_sb:
 *	Check permission before the device with superblock @mnt->sb is mounted
 *	on the mount point named by @nd.
 *	@mnt contains the vfsmount for device being mounted.
 *	@path contains the path for the mount point.
 *	Return 0 if permission is granted.
 * @sb_remount:
 *	Extracts provenance system specifc mount options and verifys no changes
 *	are being made to those options.
 *	@sb superblock being remounted
 *	@data contains the filesystem-specific data.
 *	Return 0 if permission is granted.
 * @sb_umount:
 *	Check permission before the @mnt file system is unmounted.
 *	@mnt contains the mounted file system.
 *	@flags contains the unmount flags, e.g. MNT_FORCE.
 *	Return 0 if permission is granted.
 * @sb_umount_close:
 *	Close any files in the @mnt mounted filesystem that are held open by
 *	the provenance module.  This hook is called during an umount operation
 *	prior to checking whether the filesystem is still busy.
 *	@mnt contains the mounted filesystem.
 * @sb_umount_busy:
 *	Handle a failed umount of the @mnt mounted filesystem, e.g.  re-opening
 *	any files that were closed by umount_close.  This hook is called during
 *	an umount operation if the umount fails after a call to the
 *	umount_close hook.
 *	@mnt contains the mounted filesystem.
 * @sb_post_remount:
 *	Update the provenance module's state when a filesystem is remounted.
 *	This hook is only called if the remount was successful.
 *	@mnt contains the mounted file system.
 *	@flags contains the new filesystem flags.
 *	@data contains the filesystem-specific data.
 * @sb_post_addmount:
 *	Update the provenance module's state when a filesystem is mounted.
 *	This hook is called any time a mount is successfully grafetd to
 *	the tree.
 *	@mnt contains the mounted filesystem.
 *	@mountpoint contains the path for the mount point.
 * @sb_pivotroot:
 *	Check permission before pivoting the root filesystem.
 *	@old_path contains the path for the new location of the current root (put_old).
 *	@new_path contains the path for the new root (new_root).
 *	Return 0 if permission is granted.
 * @sb_post_pivotroot:
 *	Update module state after a successful pivot.
 *	@old_path contains the path for the old root.
 *	@new_path contains the path for the new root.
 * @sb_set_mnt_opts:
 *	Set the provenance relevant mount options used for a superblock
 *	@sb the superblock to set provenance mount options for
 *	@opts binary data structure containing all lsm mount data
 * @sb_clone_mnt_opts:
 *	Copy all provenance options from a given superblock to another
 *	@oldsb old superblock which contain information to clone
 *	@newsb new superblock which needs filled in
 * @sb_parse_opts_str:
 *	Parse a string of provenance data filling in the opts structure
 *	@options string containing all mount options known by the LPM
 *	@opts binary data structure usable by the LPM
 *
 * provenance hooks for inode operations.
 *
 * @inode_alloc_provenance:
 *	Allocate and attach a provenance structure to @inode->i_provenance.  The
 *	i_provenance field is initialized to NULL when the inode structure is
 *	allocated.
 *	@inode contains the inode structure.
 *	Return 0 if operation was successful.
 * @inode_free_provenance:
 *	@inode contains the inode structure.
 *	Deallocate the inode provenance structure and set @inode->i_provenance to
 *	NULL.
 * @inode_init_provenance:
 *	Obtain the provenance attribute name suffix and value to set on a newly
 *	created inode and set up the incore provenance field for the new inode.
 *	This hook is called by the fs code as part of the inode creation
 *	transaction and provides for atomic labeling of the inode, unlike
 *	the post_create/mkdir/... hooks called by the VFS.  The hook function
 *	is expected to allocate the name and value via kmalloc, with the caller
 *	being responsible for calling kfree after using them.
 *	If the provenance module does not use provenance attributes or does
 *	not wish to put a provenance attribute on this particular inode,
 *	then it should return -EOPNOTSUPP to skip this processing.
 *	@inode contains the inode structure of the newly created inode.
 *	@dir contains the inode structure of the parent directory.
 *	@name will be set to the allocated name suffix (e.g. selinux).
 *	@value will be set to the allocated attribute value.
 *	@len will be set to the length of the value.
 *	Returns 0 if @name and @value have been successfully set,
 *		-EOPNOTSUPP if no provenance attribute is needed, or
 *		-ENOMEM on memory allocation failure.
 * @inode_create:
 *	Check permission to create a regular file.
 *	@dir contains inode structure of the parent of the new file.
 *	@dentry contains the dentry structure for the file to be created.
 *	@mode contains the file mode of the file to be created.
 *	Return 0 if permission is granted.
 * @inode_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing link to the file.
 *	@dir contains the inode structure of the parent directory of the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 * @path_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing link
 *	to the file.
 *	@new_dir contains the path structure of the parent directory of
 *	the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 * @inode_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the inode structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 * @path_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the path structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 * @inode_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the inode structure of parent directory of the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 * @path_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the path structure of parent directory of
 *	the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 * @inode_mkdir:
 *	Check permissions to create a new directory in the existing directory
 *	associated with inode strcture @dir.
 *	@dir containst the inode structure of parent of the directory to be created.
 *	@dentry contains the dentry structure of new directory.
 *	@mode contains the mode of new directory.
 *	Return 0 if permission is granted.
 * @path_mkdir:
 *	Check permissions to create a new directory in the existing directory
 *	associated with path strcture @path.
 *	@dir containst the path structure of parent of the directory
 *	to be created.
 *	@dentry contains the dentry structure of new directory.
 *	@mode contains the mode of new directory.
 *	Return 0 if permission is granted.
 * @inode_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the inode structure of parent of the directory to be removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 * @path_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the path structure of parent of the directory to be
 *	removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 * @inode_mknod:
 *	Check permissions when creating a special file (or a socket or a fifo
 *	file created via the mknod system call).  Note that if mknod operation
 *	is being done for a regular file, then the create hook will be called
 *	and not this hook.
 *	@dir contains the inode structure of parent of the new file.
 *	@dentry contains the dentry structure of the new file.
 *	@mode contains the mode of the new file.
 *	@dev contains the device number.
 *	Return 0 if permission is granted.
 * @path_mknod:
 *	Check permissions when creating a file. Note that this hook is called
 *	even if mknod operation is being done for a regular file.
 *	@dir contains the path structure of parent of the new file.
 *	@dentry contains the dentry structure of the new file.
 *	@mode contains the mode of the new file.
 *	@dev contains the undecoded device number. Use new_decode_dev() to get
 *	the decoded device number.
 *	Return 0 if permission is granted.
 * @inode_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the inode structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the inode structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 * @path_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the path structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the path structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 * @inode_readlink:
 *	Check the permission to read the symbolic link.
 *	@dentry contains the dentry structure for the file link.
 *	Return 0 if permission is granted.
 * @inode_follow_link:
 *	Check permission to follow a symbolic link when looking up a pathname.
 *	@dentry contains the dentry structure for the link.
 *	@nd contains the nameidata structure for the parent directory.
 *	Return 0 if permission is granted.
 * @inode_permission:
 *	Check permission before accessing an inode.  This hook is called by the
 *	existing Linux permission function, so a provenance module can use it to
 *	provide additional checking for existing Linux permission checks.
 *	Notice that this hook is called when a file is opened (as well as many
 *	other operations), whereas the file_provenance_ops permission hook is
 *	called when the actual read/write operations are performed.
 *	@inode contains the inode structure to check.
 *	@mask contains the permission mask.
 *	@nd contains the nameidata (may be NULL).
 *	Return 0 if permission is granted.
 * @inode_setattr:
 *	Check permission before setting file attributes.  Note that the kernel
 *	call to notify_change is performed from several locations, whenever
 *	file attributes change (such as when a file is truncated, chown/chmod
 *	operations, transferring disk quotas, etc).
 *	@dentry contains the dentry structure for the file.
 *	@attr is the iattr structure containing the new file attributes.
 *	Return 0 if permission is granted.
 * @path_truncate:
 *	Check permission before truncating a file.
 *	@path contains the path structure for the file.
 *	@length is the new length of the file.
 *	@time_attrs is the flags passed to do_truncate().
 *	Return 0 if permission is granted.
 * @inode_getattr:
 *	Check permission before obtaining file attributes.
 *	@mnt is the vfsmount where the dentry was looked up
 *	@dentry contains the dentry structure for the file.
 *	Return 0 if permission is granted.
 * @inode_delete:
 *	@inode contains the inode structure for deleted inode.
 *	This hook is called when a deleted inode is released (i.e. an inode
 *	with no hard links has its use count drop to zero).  A provenance module
 *	can use this hook to release any persistent label associated with the
 *	inode.
 * @inode_setxattr:
 *	Check permission before setting the extended attributes
 *	@value identified by @name for @dentry.
 *	Return 0 if permission is granted.
 * @inode_post_setxattr:
 *	Update inode provenance field after successful setxattr operation.
 *	@value identified by @name for @dentry.
 * @inode_getxattr:
 *	Check permission before obtaining the extended attributes
 *	identified by @name for @dentry.
 *	Return 0 if permission is granted.
 * @inode_listxattr:
 *	Check permission before obtaining the list of extended attribute
 *	names for @dentry.
 *	Return 0 if permission is granted.
 * @inode_removexattr:
 *	Check permission before removing the extended attribute
 *	identified by @name for @dentry.
 *	Return 0 if permission is granted.
 * @inode_getprovenance:
 *	Retrieve a copy of the extended attribute representation of the
 *	provenance label associated with @name for @inode via @buffer.  Note that
 *	@name is the remainder of the attribute name after the provenance prefix
 *	has been removed. @alloc is used to specify of the call should return a
 *	value via the buffer or just the value length Return size of buffer on
 *	success.
 * @inode_setprovenance:
 *	Set the provenance label associated with @name for @inode from the
 *	extended attribute value @value.  @size indicates the size of the
 *	@value in bytes.  @flags may be XATTR_CREATE, XATTR_REPLACE, or 0.
 *	Note that @name is the remainder of the attribute name after the
 *	provenance. prefix has been removed.
 *	Return 0 on success.
 * @inode_listprovenance:
 *	Copy the extended attribute names for the provenance labels
 *	associated with @inode into @buffer.  The maximum size of @buffer
 *	is specified by @buffer_size.  @buffer may be NULL to request
 *	the size of the buffer required.
 *	Returns number of bytes used/required on success.
 * @inode_need_killpriv:
 *	Called when an inode has been changed.
 *	@dentry is the dentry being changed.
 *	Return <0 on error to abort the inode change operation.
 *	Return 0 if inode_killpriv does not need to be called.
 *	Return >0 if inode_killpriv does need to be called.
 * @inode_killpriv:
 *	The setuid bit is being removed.  Remove similar provenance labels.
 *	Called with the dentry->d_inode->i_mutex held.
 *	@dentry is the dentry being changed.
 *	Return 0 on success.  If error is returned, then the operation
 *	causing setuid bit removal is failed.
 * @inode_getprovid:
 *	Get the provid associated with the node.
 *	@inode contains a pointer to the inode.
 *	@provid contains a pointer to the location where result will be saved.
 *	In case of failure, @provid will be set to zero.
 *
 * provenance hooks for file operations
 *
 * @file_permission:
 *	Check file permissions before accessing an open file.  This hook is
 *	called by various operations that read or write files.  A provenance
 *	module can use this hook to perform additional checking on these
 *	operations, e.g.  to revalidate permissions on use to support privilege
 *	bracketing or policy changes.  Notice that this hook is used when the
 *	actual read/write operations are performed, whereas the
 *	inode_provenance_ops hook is called when a file is opened (as well as
 *	many other operations).
 *	Caveat:  Although this hook can be used to revalidate permissions for
 *	various system call operations that read or write files, it does not
 *	address the revalidation of permissions for memory-mapped files.
 *	Provenance modules must handle this separately if they need such
 *	revalidation.
 *	@file contains the file structure being accessed.
 *	@mask contains the requested permissions.
 *	Return 0 if permission is granted.
 * @file_alloc_provenance:
 *	Allocate and attach a provenance structure to the file->f_provenance field.
 *	The provenance field is initialized to NULL when the structure is first
 *	created.
 *	@file contains the file structure to secure.
 *	Return 0 if the hook is successful and permission is granted.
 * @file_free_provenance:
 *	Deallocate and free any provenance structures stored in file->f_provenance.
 *	@file contains the file structure being modified.
 * @file_ioctl:
 *	@file contains the file structure.
 *	@cmd contains the operation to perform.
 *	@arg contains the operational arguments.
 *	Check permission for an ioctl operation on @file.  Note that @arg can
 *	sometimes represents a user space pointer; in other cases, it may be a
 *	simple integer value.  When @arg represents a user space pointer, it
 *	should never be used by the provenance module.
 *	Return 0 if permission is granted.
 * @file_mmap :
 *	Check permissions for a mmap operation.  The @file may be NULL, e.g.
 *	if mapping anonymous memory.
 *	@file contains the file structure for file to map (may be NULL).
 *	@reqprot contains the protection requested by the application.
 *	@prot contains the protection that will be applied by the kernel.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 * @file_mprotect:
 *	Check permissions before changing memory access permissions.
 *	@vma contains the memory region to modify.
 *	@reqprot contains the protection requested by the application.
 *	@prot contains the protection that will be applied by the kernel.
 *	Return 0 if permission is granted.
 * @file_lock:
 *	Check permission before performing file locking operations.
 *	Note: this hook mediates both flock and fcntl style locks.
 *	@file contains the file structure.
 *	@cmd contains the posix-translated lock operation to perform
 *	(e.g. F_RDLCK, F_WRLCK).
 *	Return 0 if permission is granted.
 * @file_fcntl:
 *	Check permission before allowing the file operation specified by @cmd
 *	from being performed on the file @file.  Note that @arg can sometimes
 *	represents a user space pointer; in other cases, it may be a simple
 *	integer value.  When @arg represents a user space pointer, it should
 *	never be used by the provenance module.
 *	@file contains the file structure.
 *	@cmd contains the operation to be performed.
 *	@arg contains the operational arguments.
 *	Return 0 if permission is granted.
 * @file_set_fowner:
 *	Save owner provenance information (typically from current->provenance) in
 *	file->f_provenance for later use by the send_sigiotask hook.
 *	@file contains the file structure to update.
 *	Return 0 on success.
 * @file_send_sigiotask:
 *	Check permission for the file owner @fown to send SIGIO or SIGURG to the
 *	process @tsk.  Note that this hook is sometimes called from interrupt.
 *	Note that the fown_struct, @fown, is never outside the context of a
 *	struct file, so the file structure (and associated provenance information)
 *	can always be obtained:
 *		container_of(fown, struct file, f_owner)
 *	@tsk contains the structure of task receiving signal.
 *	@fown contains the file owner information.
 *	@sig is the signal that will be sent.  When 0, kernel sends SIGIO.
 *	Return 0 if permission is granted.
 * @file_receive:
 *	This hook allows provenance modules to control the ability of a process
 *	to receive an open file descriptor via socket IPC.
 *	@file contains the file structure being received.
 *	Return 0 if permission is granted.
 *
 * provenance hook for dentry
 *
 * @dentry_open
 *	Save open-time permission checking state for later use upon
 *	file_permission, and recheck access if anything has changed
 *	since inode_permission.
 *
 * provenance hooks for task operations.
 *
 * @task_create:
 *	Check permission before creating a child process.  See the clone(2)
 *	manual page for definitions of the @clone_flags.
 *	@clone_flags contains the flags indicating what should be shared.
 *	Return 0 if permission is granted.
 * @cred_alloc_blank:
 *	@cred points to the credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Only allocate sufficient memory and attach to @cred such that
 *	cred_transfer() will not get ENOMEM.
 * @cred_free:
 *	@cred points to the credentials.
 *	Deallocate and clear the cred->provenance field in a set of credentials.
 * @prepare_creds:
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Prepare a new set of credentials by copying the data from the old set.
 * @commit_creds:
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	Install a new set of credentials.
 * @transfer_Creds:
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	Transfer data from original creds to new creds
 * @kernel_act_as:
 *	Set the credentials for a kernel service to act as (subjective context).
 *	@new points to the credentials to be modified.
 *	@provid specifies the provenance ID to be set
 *	The current task must be the one that nominated @provid.
 *	Return 0 if successful.
 * @kernel_create_files_as:
 *	Set the file creation context in a set of credentials to be the same as
 *	the objective context of the specified inode.
 *	@new points to the credentials to be modified.
 *	@inode points to the inode to use as a reference.
 *	The current task must be the one that nominated @inode.
 *	Return 0 if successful.
 * @kernel_module_request:
 *	Ability to trigger the kernel to automatically upcall to userspace for
 *	userspace to load a kernel module with the given name.
 *	@kmod_name name of the module requested by the kernel
 *	Return 0 if successful.
 * @task_setuid:
 *	Check permission before setting one or more of the user identity
 *	attributes of the current process.  The @flags parameter indicates
 *	which of the set*uid system calls invoked this hook and how to
 *	interpret the @id0, @id1, and @id2 parameters.  See the LPM_SETID
 *	definitions at the beginning of this file for the @flags values and
 *	their meanings.
 *	@id0 contains a uid.
 *	@id1 contains a uid.
 *	@id2 contains a uid.
 *	@flags contains one of the LPM_SETID_* values.
 *	Return 0 if permission is granted.
 * @task_fix_setuid:
 *	Update the module's state after setting one or more of the user
 *	identity attributes of the current process.  The @flags parameter
 *	indicates which of the set*uid system calls invoked this hook.  If
 *	@new is the set of credentials that will be installed.  Modifications
 *	should be made to this rather than to @current->cred.
 *	@old is the set of credentials that are being replaces
 *	@flags contains one of the LPM_SETID_* values.
 *	Return 0 on success.
 * @task_setgid:
 *	Check permission before setting one or more of the group identity
 *	attributes of the current process.  The @flags parameter indicates
 *	which of the set*gid system calls invoked this hook and how to
 *	interpret the @id0, @id1, and @id2 parameters.  See the LPM_SETID
 *	definitions at the beginning of this file for the @flags values and
 *	their meanings.
 *	@id0 contains a gid.
 *	@id1 contains a gid.
 *	@id2 contains a gid.
 *	@flags contains one of the LPM_SETID_* values.
 *	Return 0 if permission is granted.
 * @task_setpgid:
 *	Check permission before setting the process group identifier of the
 *	process @p to @pgid.
 *	@p contains the task_struct for process being modified.
 *	@pgid contains the new pgid.
 *	Return 0 if permission is granted.
 * @task_getpgid:
 *	Check permission before getting the process group identifier of the
 *	process @p.
 *	@p contains the task_struct for the process.
 *	Return 0 if permission is granted.
 * @task_getsid:
 *	Check permission before getting the session identifier of the process
 *	@p.
 *	@p contains the task_struct for the process.
 *	Return 0 if permission is granted.
 * @task_getprovid:
 *	Retrieve the provenance identifier of the process @p.
 *	@p contains the task_struct for the process and place is into @provid.
 *	In case of failure, @provid will be set to zero.
 *
 * @task_setgroups:
 *	Check permission before setting the supplementary group set of the
 *	current process.
 *	@group_info contains the new group information.
 *	Return 0 if permission is granted.
 * @task_setnice:
 *	Check permission before setting the nice value of @p to @nice.
 *	@p contains the task_struct of process.
 *	@nice contains the new nice value.
 *	Return 0 if permission is granted.
 * @task_setioprio
 *	Check permission before setting the ioprio value of @p to @ioprio.
 *	@p contains the task_struct of process.
 *	@ioprio contains the new ioprio value
 *	Return 0 if permission is granted.
 * @task_getioprio
 *	Check permission before getting the ioprio value of @p.
 *	@p contains the task_struct of process.
 *	Return 0 if permission is granted.
 * @task_setrlimit:
 *	Check permission before setting the resource limits of the current
 *	process for @resource to @new_rlim.  The old resource limit values can
 *	be examined by dereferencing (current->signal->rlim + resource).
 *	@resource contains the resource whose limit is being set.
 *	@new_rlim contains the new limits for @resource.
 *	Return 0 if permission is granted.
 * @task_setscheduler:
 *	Check permission before setting scheduling policy and/or parameters of
 *	process @p based on @policy and @lp.
 *	@p contains the task_struct for process.
 *	@policy contains the scheduling policy.
 *	@lp contains the scheduling parameters.
 *	Return 0 if permission is granted.
 * @task_getscheduler:
 *	Check permission before obtaining scheduling information for process
 *	@p.
 *	@p contains the task_struct for process.
 *	Return 0 if permission is granted.
 * @task_movememory
 *	Check permission before moving memory owned by process @p.
 *	@p contains the task_struct for process.
 *	Return 0 if permission is granted.
 * @task_kill:
 *	Check permission before sending signal @sig to @p.  @info can be NULL,
 *	the constant 1, or a pointer to a siginfo structure.  If @info is 1 or
 *	SI_FROMKERNEL(info) is true, then the signal should be viewed as coming
 *	from the kernel and should typically be permitted.
 *	SIGIO signals are handled separately by the send_sigiotask hook in
 *	file_provenance_ops.
 *	@p contains the task_struct for process.
 *	@info contains the signal information.
 *	@sig contains the signal value.
 *	@provid contains the sid of the process where the signal originated
 *	Return 0 if permission is granted.
 * @task_wait:
 *	Check permission before allowing a process to reap a child process @p
 *	and collect its status information.
 *	@p contains the task_struct for process.
 *	Return 0 if permission is granted.
 * @task_prctl:
 *	Check permission before performing a process control operation on the
 *	current process.
 *	@option contains the operation.
 *	@arg2 contains a argument.
 *	@arg3 contains a argument.
 *	@arg4 contains a argument.
 *	@arg5 contains a argument.
 *	Return -ENOSYS if no-one wanted to handle this op, any other value to
 *	cause prctl() to return immediately with that value.
 * @task_to_inode:
 *	Set the provenance attributes for an inode based on an associated task's
 *	provenance attributes, e.g. for /proc/pid inodes.
 *	@p contains the task_struct for the task.
 *	@inode contains the inode structure for the inode.
 *
 * provenance hooks for Netlink messaging.
 *
 * @netlink_send:
 *	Save provenance information for a netlink message so that permission
 *	checking can be performed when the message is processed.  The provenance
 *	information can be saved using the eff_cap field of the
 *	netlink_skb_parms structure.  Also may be used to provide fine
 *	grained control over message transmission.
 *	@sk associated sock of task sending the message.,
 *	@skb contains the sk_buff structure for the netlink message.
 *	Return 0 if the information was successfully saved and message
 *	is allowed to be transmitted.
 * @netlink_recv:
 *	Check permission before processing the received netlink message in
 *	@skb.
 *	@skb contains the sk_buff structure for the netlink message.
 *	@cap indicates the capability required
 *	Return 0 if permission is granted.
 *
 * provenance hooks for Unix domain networking.
 *
 * @unix_stream_connect:
 *	Check permissions before establishing a Unix domain stream connection
 *	between @sock and @other.
 *	@sock contains the socket structure.
 *	@other contains the peer socket structure.
 *	Return 0 if permission is granted.
 * @unix_may_send:
 *	Check permissions before connecting or sending datagrams from @sock to
 *	@other.
 *	@sock contains the socket structure.
 *	@sock contains the peer socket structure.
 *	Return 0 if permission is granted.
 *
 * The @unix_stream_connect and @unix_may_send hooks were necessary because
 * Linux provides an alternative to the conventional file name space for Unix
 * domain sockets.  Whereas binding and connecting to sockets in the file name
 * space is mediated by the typical file permissions (and caught by the mknod
 * and permission hooks in inode_provenance_ops), binding and connecting to
 * sockets in the abstract name space is completely unmediated.  Sufficient
 * control of Unix domain sockets in the abstract name space isn't possible
 * using only the socket layer hooks, since we need to know the actual target
 * socket, which is not looked up until we are inside the af_unix code.
 *
 * provenance hooks for socket operations.
 *
 * @socket_create:
 *	Check permissions prior to creating a new socket.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 *	Return 0 if permission is granted.
 * @socket_post_create:
 *	This hook allows a module to update or allocate a per-socket provenance
 *	structure. Note that the provenance field was not added directly to the
 *	socket structure, but rather, the socket provenance information is stored
 *	in the associated inode.  Typically, the inode alloc_provenance hook will
 *	allocate and and attach provenance information to
 *	sock->inode->i_provenance.  This hook may be used to update the
 *	sock->inode->i_provenance field with additional information that wasn't
 *	available when the inode was allocated.
 *	@sock contains the newly created socket structure.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 * @socket_bind:
 *	Check permission before socket protocol layer bind operation is
 *	performed and the socket @sock is bound to the address specified in the
 *	@address parameter.
 *	@sock contains the socket structure.
 *	@address contains the address to bind to.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 * @socket_connect:
 *	Check permission before socket protocol layer connect operation
 *	attempts to connect socket @sock to a remote address, @address.
 *	@sock contains the socket structure.
 *	@address contains the address of remote endpoint.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 * @socket_listen:
 *	Check permission before socket protocol layer listen operation.
 *	@sock contains the socket structure.
 *	@backlog contains the maximum length for the pending connection queue.
 *	Return 0 if permission is granted.
 * @socket_accept:
 *	Check permission before accepting a new connection.  Note that the new
 *	socket, @newsock, has been created and some information copied to it,
 *	but the accept operation has not actually been performed.
 *	@sock contains the listening socket structure.
 *	@newsock contains the newly created server socket for connection.
 *	Return 0 if permission is granted.
 * @socket_sendmsg:
 *	Check permission before transmitting a message to another socket.
 *	@sock contains the socket structure.
 *	@msg contains the message to be transmitted.
 *	@size contains the size of message.
 *	Return 0 if permission is granted.
 * @socket_recvmsg:
 *	Check permission before receiving a message from a socket.
 *	@sock contains the socket structure.
 *	@msg contains the message structure.
 *	@size contains the size of message structure.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 * @socket_post_recvmsg:                                             
 *      Notify the provenance module that a process is about to receive a message
 *      from a socket.  The message itself is available at this point.
 *      @sock contains the socket structure.
 *      @msg contains the message structure.
 *      @size contains the size of message structure.
 *      @flags contains the operational flags.
 * @socket_getsockname:
 *	Check permission before the local address (name) of the socket object
 *	@sock is retrieved.
 *	@sock contains the socket structure.
 *	Return 0 if permission is granted.
 * @socket_getpeername:
 *	Check permission before the remote address (name) of a socket object
 *	@sock is retrieved.
 *	@sock contains the socket structure.
 *	Return 0 if permission is granted.
 * @socket_getsockopt:
 *	Check permissions before retrieving the options associated with socket
 *	@sock.
 *	@sock contains the socket structure.
 *	@level contains the protocol level to retrieve option from.
 *	@optname contains the name of option to retrieve.
 *	Return 0 if permission is granted.
 * @socket_setsockopt:
 *	Check permissions before setting the options associated with socket
 *	@sock.
 *	@sock contains the socket structure.
 *	@level contains the protocol level to set options for.
 *	@optname contains the name of the option to set.
 *	Return 0 if permission is granted.
 * @socket_shutdown:
 *	Checks permission before all or part of a connection on the socket
 *	@sock is shut down.
 *	@sock contains the socket structure.
 *	@how contains the flag indicating how future sends and receives are handled.
 *	Return 0 if permission is granted.
 * @socket_sock_rcv_skb:
 *	Check permissions on incoming network packets.  This hook is distinct
 *	from Netfilter's IP input hooks since it is the first time that the
 *	incoming sk_buff @skb has been associated with a particular socket, @sk.
 *	@sk contains the sock (not socket) associated with the incoming sk_buff.
 *	@skb contains the incoming network data.
 * @skb_shinfo_alloc_provenance:
 *      Allocate and attach a provenance structure to the skb_shared_info
 *      structure associated with a socket buffer.
 *      @skb contains the socket buffer structure.
 *      @recycling is 1 if the buffer is being recycled (i.e. not freed and
 *      re-allocated).  If possible, the structure should be initialized without
 *      allocating memory in this case.  This will always follow a corresponding
 *      free_provenance call with recycling set to 1.
 *      @gfp indicates the atomicity of any memory allocations.
 * @skb_shinfo_free_provenance:
 *      Deallocate the provenance structure attached to the skb_shared_info
 *      associated with a socket buffer.  Note that this may be called more than
 *      once if the shinfo allocate hook fails, so be sure to check the pointer
 *      before freeing, and set it to NULL afterward.
 *      @skb contains the socket buffer structure.
 *      @recycling is 1 if the buffer is being recycled.  If possible, the
 *      structure should be deinitialized without freeing memory in this case.
 *      This will always be followed by a corresponding alloc_provenance call with
 *      recycling set to 1.
 * @skb_shinfo_copy:
 *      Notifies the provenance module that a copy (not a clone) of the buffer and
 *      shared info structure is being made.  By default, the copy will have the
 *      same provenance pointer as the original, but there are now two references
 *      to it which can be legally passed to the shinfo free hook.
 *      @skb contains the original socket buffer structure.
 *      @shinfo contains the new shared info structure.
 *      @gfp indicates the atomicity of any memory allocations.
 * @socket_dgram_append:
 *      Check permissions before allowing a process to append data to the end of
 *      a potentially corked packet.  This is the point where a process can be
 *      associated with the packet which will eventually be sent.  This is
 *      called for UDP, ICMP, and RAW, as well as self-contained TCP packets
 *      such as ACKs or RSTs.
 *      @sk contains the sock (not socket) on which the packet will be sent.
 *      @head contains the first socket buffer in the queue, from which the
 *      combined buffer will be built.
 *      Return 0 if permission is granted.
 * @socket_dgram_post_recv:
 *      Notifies the provenance module before delivering a datagram to a process.
 *      @sk contains the sock (not socket) on which the packet is being
 *      received.
 *      @skb contains the datagram.
 * @socket_getpeersec_stream:
 *	This hook allows the provenance module to provide peer socket provenance
 *	state for unix or connected tcp sockets to userspace via getsockopt
 *	SO_GETPEERSEC.  For tcp sockets this can be meaningful if the
 *	socket is associated with an ipsec SA.
 *	@sock is the local socket.
 *	@optval userspace memory where the provenance state is to be copied.
 *	@optlen userspace int where the module should copy the actual length
 *	of the provenance state.
 *	@len as input is the maximum length to copy to userspace provided
 *	by the caller.
 *	Return 0 if all is well, otherwise, typical getsockopt return
 *	values.
 * @socket_getpeersec_dgram:
 *	This hook allows the provenance module to provide peer socket provenance
 *	state for udp sockets on a per-packet basis to userspace via
 *	getsockopt SO_GETPEERSEC.  The application must first have indicated
 *	the IP_PASSSEC option via getsockopt.  It can then retrieve the
 *	provenance state returned by this hook for a packet via the SCM_PROVENANCE
 *	ancillary message type.
 *	@skb is the skbuff for the packet being queried
 *	@provdata is a pointer to a buffer in which to copy the provenance data
 *	@seclen is the maximum length for @provdata
 *	Return 0 on success, error on failure.
 * @sk_alloc_provenance:
 *	Allocate and attach a provenance structure to the sk->sk_provenance field,
 *	which is used to copy provenance attributes between local stream sockets.
 * @sk_free_provenance:
 *	Deallocate provenance structure.
 * @sk_clone_provenance:
 *	Clone/copy provenance structure.
 * @sk_getprovid:
 *	Retrieve the LPM-specific provid for the sock to enable caching of network
 *	authorizations.
 * @sock_graft:
 *	Sets the socket's iprov sid to the sock's sid.
 * @inet_conn_request:
 *	Sets the openreq's sid to socket's sid with MLS portion taken from peer sid.
 * @inet_csk_clone:
 *	Sets the new child socket's sid to the openreq sid.
 * @inet_conn_established:
 *	Sets the connection's peersid to the secmark on skb.
 * @req_classify_flow:
 *	Sets the flow's sid to the openreq sid.
 * @tun_dev_create:
 *	Check permissions prior to creating a new TUN device.
 * @tun_dev_post_create:
 *	This hook allows a module to update or allocate a per-socket provenance
 *	structure.
 *	@sk contains the newly created sock structure.
 * @tun_dev_attach:
 *	Check permissions prior to attaching to a persistent TUN device.  This
 *	hook can also be used by the module to update any provenance state
 *	associated with the TUN device's sock structure.
 *	@sk contains the existing sock structure.
 *
 * provenance hooks affecting all System V IPC operations.
 *
 * @ipc_permission:
 *	Check permissions for access to IPC
 *	@ipcp contains the kernel IPC permission structure
 *	@flag contains the desired (requested) permission set
 *	Return 0 if permission is granted.
 * @ipc_getprovid:
 *	Get the provid associated with the ipc object.
 *	@ipcp contains the kernel IPC permission structure.
 *	@provid contains a pointer to the location where result will be saved.
 *	In case of failure, @provid will be set to zero.
 *
 * provenance hooks for individual messages held in System V IPC message queues
 * @msg_msg_alloc_provenance:
 *	Allocate and attach a provenance structure to the msg->provenance field.
 *	The provenance field is initialized to NULL when the structure is first
 *	created.
 *	@msg contains the message structure to be modified.
 *	Return 0 if operation was successful and permission is granted.
 * @msg_msg_free_provenance:
 *	Deallocate the provenance structure for this message.
 *	@msg contains the message structure to be modified.
 *
 * provenance hooks for System V IPC Message Queues
 *
 * @msg_queue_alloc_provenance:
 *	Allocate and attach a provenance structure to the
 *	msq->q_perm.provenance field. The provenance field is initialized to
 *	NULL when the structure is first created.
 *	@msq contains the message queue structure to be modified.
 *	Return 0 if operation was successful and permission is granted.
 * @msg_queue_free_provenance:
 *	Deallocate provenance structure for this message queue.
 *	@msq contains the message queue structure to be modified.
 * @msg_queue_associate:
 *	Check permission when a message queue is requested through the
 *	msgget system call.  This hook is only called when returning the
 *	message queue identifier for an existing message queue, not when a
 *	new message queue is created.
 *	@msq contains the message queue to act upon.
 *	@msqflg contains the operation control flags.
 *	Return 0 if permission is granted.
 * @msg_queue_msgctl:
 *	Check permission when a message control operation specified by @cmd
 *	is to be performed on the message queue @msq.
 *	The @msq may be NULL, e.g. for IPC_INFO or MSG_INFO.
 *	@msq contains the message queue to act upon.  May be NULL.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 * @msg_queue_msgsnd:
 *	Check permission before a message, @msg, is enqueued on the message
 *	queue, @msq.
 *	@msq contains the message queue to send message to.
 *	@msg contains the message to be enqueued.
 *	@msqflg contains operational flags.
 *	Return 0 if permission is granted.
 * @msg_queue_msgrcv:
 *	Check permission before a message, @msg, is removed from the message
 *	queue, @msq.  The @target task structure contains a pointer to the
 *	process that will be receiving the message (not equal to the current
 *	process when inline receives are being performed).
 *	@msq contains the message queue to retrieve message from.
 *	@msg contains the message destination.
 *	@target contains the task structure for recipient process.
 *	@type contains the type of message requested.
 *	@mode contains the operational flags.
 *	Return 0 if permission is granted.
 *
 * provenance hooks for System V Shared Memory Segments
 *
 * @shm_alloc_provenance:
 *	Allocate and attach a provenance structure to the shp->shm_perm.provenance
 *	field.  The provenance field is initialized to NULL when the structure is
 *	first created.
 *	@shp contains the shared memory structure to be modified.
 *	Return 0 if operation was successful and permission is granted.
 * @shm_free_provenance:
 *	Deallocate the provenance struct for this memory segment.
 *	@shp contains the shared memory structure to be modified.
 * @shm_associate:
 *	Check permission when a shared memory region is requested through the
 *	shmget system call.  This hook is only called when returning the shared
 *	memory region identifier for an existing region, not when a new shared
 *	memory region is created.
 *	@shp contains the shared memory structure to be modified.
 *	@shmflg contains the operation control flags.
 *	Return 0 if permission is granted.
 * @shm_shmctl:
 *	Check permission when a shared memory control operation specified by
 *	@cmd is to be performed on the shared memory region @shp.
 *	The @shp may be NULL, e.g. for IPC_INFO or SHM_INFO.
 *	@shp contains shared memory structure to be modified.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 * @shm_shmat:
 *	Check permissions prior to allowing the shmat system call to attach the
 *	shared memory segment @shp to the data segment of the calling process.
 *	The attaching address is specified by @shmaddr.
 *	@shp contains the shared memory structure to be modified.
 *	@shmaddr contains the address to attach memory region to.
 *	@shmflg contains the operational flags.
 *	Return 0 if permission is granted.
 *
 * provenance hooks for System V Semaphores
 *
 * @sem_alloc_provenance:
 *	Allocate and attach a provenance structure to the sma->sem_perm.provenance
 *	field.  The provenance field is initialized to NULL when the structure is
 *	first created.
 *	@sma contains the semaphore structure
 *	Return 0 if operation was successful and permission is granted.
 * @sem_free_provenance:
 *	deallocate provenance struct for this semaphore
 *	@sma contains the semaphore structure.
 * @sem_associate:
 *	Check permission when a semaphore is requested through the semget
 *	system call.  This hook is only called when returning the semaphore
 *	identifier for an existing semaphore, not when a new one must be
 *	created.
 *	@sma contains the semaphore structure.
 *	@semflg contains the operation control flags.
 *	Return 0 if permission is granted.
 * @sem_semctl:
 *	Check permission when a semaphore operation specified by @cmd is to be
 *	performed on the semaphore @sma.  The @sma may be NULL, e.g. for
 *	IPC_INFO or SEM_INFO.
 *	@sma contains the semaphore structure.  May be NULL.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 * @sem_semop
 *	Check permissions before performing operations on members of the
 *	semaphore set @sma.  If the @alter flag is nonzero, the semaphore set
 *	may be modified.
 *	@sma contains the semaphore structure.
 *	@sops contains the operations to perform.
 *	@nsops contains the number of operations to perform.
 *	@alter contains the flag indicating whether changes are to be made.
 *	Return 0 if permission is granted.
 * @ptrace_access_check:
 *	Check permission before allowing the current process to trace the
 *	@child process.
 *	Provenance modules may also want to perform a process tracing check
 *	during an execve in the set_provenance or apply_creds hooks of
 *	tracing check during an execve in the bprm_set_creds hook of
 *	binprm_provenance_ops if the process is being traced and its provenance
 *	attributes would be changed by the execve.
 *	@child contains the task_struct structure for the target process.
 *	@mode contains the PTRACE_MODE flags indicating the form of access.
 *	Return 0 if permission is granted.
 * @ptrace_traceme:
 *	Check that the @parent process has sufficient permission to trace the
 *	current process before allowing the current process to present itself
 *	to the @parent process for tracing.
 *	The parent process will still have to undergo the ptrace_access_check
 *	checks before it is allowed to trace this one.
 *	@parent contains the task_struct structure for debugger process.
 *	Return 0 if permission is granted.
 * @acct:
 *	Check permission before enabling or disabling process accounting.  If
 *	accounting is being enabled, then @file refers to the open file used to
 *	store accounting records.  If accounting is being disabled, then @file
 *	is NULL.
 *	@file contains the file structure for the accounting file (may be NULL).
 *	Return 0 if permission is granted.
 * @sysctl:
 *	Check permission before accessing the @table sysctl variable in the
 *	manner specified by @op.
 *	@table contains the ctl_table structure for the sysctl variable.
 *	@op contains the operation (001 = search, 002 = write, 004 = read).
 *	Return 0 if permission is granted.
 * @syslog:
 *	Check permission before accessing the kernel message ring or changing
 *	logging to the console.
 *	See the syslog(2) manual page for an explanation of the @type values.
 *	@type contains the type of action.
 *	Return 0 if permission is granted.
 * @settime:
 *	Check permission to change the system time.
 *	struct timespec and timezone are defined in include/linux/time.h
 *	@ts contains new time
 *	@tz contains new timezone
 *	Return 0 if permission is granted.
 * @vm_enough_memory:
 * @vm_enough_memory_mm:
 * @vm_enough_memory_kern:
 *	Check permissions for allocating a new virtual mapping.
 *	@mm contains the mm struct it is being added to.
 *	@pages contains the number of pages.
 *	Return 0 if permission is granted.
 *
 * @provid_to_provctx:
 *	Convert provid to provenance context.
 *	@provid contains the provenance ID.
 *	@provdata contains the pointer that stores the converted provenance context.
 * @provctx_to_provid:
 *	Convert provenance context to provid.
 *	@provid contains the pointer to the generated provenance ID.
 *	@provdata contains the provenance context.
 *
 * @release_provctx:
 *	Release the provenance context.
 *	@provdata contains the provenance context.
 *	@seclen contains the length of the provenance context.
 *
 * provenance hooks for Audit
 *
 * @inode_notifyprovctx:
 *	Notify the provenance module of what the provenance context of an inode
 *	should be.  Initializes the incore provenance context managed by the
 *	provenance module for this inode.  Example usage:  NFS client invokes
 *	this hook to initialize the provenance context in its incore inode to the
 *	value provided by the server for the file when the server returned the
 *	file's attributes to the client.
 *
 * 	Must be called with inode->i_mutex locked.
 *
 * 	@inode we wish to set the provenance context of.
 * 	@ctx contains the string which we wish to set in the inode.
 * 	@ctxlen contains the length of @ctx.
 *
 * @inode_setprovctx:
 * 	Change the provenance context of an inode.  Updates the
 * 	incore provenance context managed by the provenance module and invokes the
 * 	fs code as needed (via __vfs_setxattr_noperm) to update any backing
 * 	xattrs that represent the context.  Example usage:  NFS server invokes
 * 	this hook to change the provenance context in its incore inode and on the
 * 	backing filesystem to a value provided by the client on a SETATTR
 * 	operation.
 *
 * 	Must be called with inode->i_mutex locked.
 *
 * 	@dentry contains the inode we wish to set the provenance context of.
 * 	@ctx contains the string which we wish to set in the inode.
 * 	@ctxlen contains the length of @ctx.
 *
 * @inode_getprovctx:
 * 	Returns a string containing all relavent provenance context information
 *
 * 	@inode we wish to set the provenance context of.
 *	@ctx is a pointer in which to place the allocated provenance context.
 *	@ctxlen points to the place to put the length of @ctx.
 * This is the main provenance structure.
 */
struct provenance_operations {
	char name[PROVENANCE_NAME_MAX + 1];

	int (*ptrace_access_check) (struct task_struct *child, unsigned int mode);
	int (*ptrace_traceme) (struct task_struct *parent);
	int (*acct) (struct file *file);
	int (*sysctl) (struct ctl_table *table, int op);
	int (*quotactl) (int cmds, int type, int id, struct super_block *sb);
	int (*quota_on) (struct dentry *dentry);
	int (*syslog) (int type);
	int (*settime) (const struct timespec *ts, const struct timezone *tz);
	int (*vm_enough_memory) (struct mm_struct *mm, long pages);

	int (*bprm_set_creds) (struct linux_binprm *bprm);
        int (*bprm_check_provenance) (struct linux_binprm *bprm);
        int (*bprm_secureexec) (struct linux_binprm *bprm);
	void (*bprm_committing_creds) (struct linux_binprm *bprm);
	void (*bprm_committed_creds) (struct linux_binprm *bprm);

	int (*sb_alloc_provenance) (struct super_block *sb);
	void (*sb_free_provenance) (struct super_block *sb);
	int (*sb_copy_data) (char *orig, char *copy);
	int (*sb_remount) (struct super_block *sb, void *data);
	int (*sb_kern_mount) (struct super_block *sb, int flags, void *data);
	int (*sb_show_options) (struct seq_file *m, struct super_block *sb);
	int (*sb_statfs) (struct dentry *dentry);
	int (*sb_mount) (char *dev_name, struct path *path,
			 char *type, unsigned long flags, void *data);
	int (*sb_check_sb) (struct vfsmount *mnt, struct path *path);
	int (*sb_umount) (struct vfsmount *mnt, int flags);
	void (*sb_umount_close) (struct vfsmount *mnt);
	void (*sb_umount_busy) (struct vfsmount *mnt);
	void (*sb_post_remount) (struct vfsmount *mnt,
				 unsigned long flags, void *data);
	void (*sb_post_addmount) (struct vfsmount *mnt,
				  struct path *mountpoint);
	int (*sb_pivotroot) (struct path *old_path,
			     struct path *new_path);
	void (*sb_post_pivotroot) (struct path *old_path,
				   struct path *new_path);
	int (*sb_set_mnt_opts) (struct super_block *sb,
				struct provenance_mnt_opts *opts);
	void (*sb_clone_mnt_opts) (const struct super_block *oldsb,
				   struct super_block *newsb);
	int (*sb_parse_opts_str) (char *options, struct provenance_mnt_opts *opts);

	int (*path_truncate) (struct path *path, loff_t length,
			      unsigned int time_attrs);

	int (*inode_alloc_provenance) (struct inode *inode);
	void (*inode_free_provenance) (struct inode *inode);
	int (*inode_init_provenance) (struct inode *inode, struct inode *dir,
				    char **name, void **value, size_t *len);
	int (*inode_create) (struct inode *dir,
			     struct dentry *dentry, int mode);
	int (*inode_link) (struct dentry *old_dentry,
			   struct inode *dir, struct dentry *new_dentry);
	int (*inode_unlink) (struct inode *dir, struct dentry *dentry);
	int (*inode_symlink) (struct inode *dir,
			      struct dentry *dentry, const char *old_name);
	int (*inode_mkdir) (struct inode *dir, struct dentry *dentry, int mode);
	int (*inode_rmdir) (struct inode *dir, struct dentry *dentry);
	int (*inode_mknod) (struct inode *dir, struct dentry *dentry,
			    int mode, dev_t dev);
	int (*inode_rename) (struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry);
	int (*inode_readlink) (struct dentry *dentry);
	int (*inode_follow_link) (struct dentry *dentry, struct nameidata *nd);
	int (*inode_permission) (struct inode *inode, int mask);
	int (*inode_setattr)	(struct dentry *dentry, struct iattr *attr);
	int (*inode_getattr) (struct vfsmount *mnt, struct dentry *dentry);
	void (*inode_delete) (struct inode *inode);
	int (*inode_setxattr) (struct dentry *dentry, const char *name,
			       const void *value, size_t size, int flags);
	void (*inode_post_setxattr) (struct dentry *dentry, const char *name,
				     const void *value, size_t size, int flags);
	int (*inode_getxattr) (struct dentry *dentry, const char *name);
	int (*inode_listxattr) (struct dentry *dentry);
	int (*inode_removexattr) (struct dentry *dentry, const char *name);
	int (*inode_need_killpriv) (struct dentry *dentry);
	int (*inode_killpriv) (struct dentry *dentry);
	int (*inode_getprovenance) (const struct inode *inode, const char *name, void **buffer, bool alloc);
	int (*inode_setprovenance) (struct inode *inode, const char *name, const void *value, size_t size, int flags);
	int (*inode_listprovenance) (struct inode *inode, char *buffer, size_t buffer_size);
	void (*inode_getprovid) (const struct inode *inode, u32 *provid);

	int (*file_permission) (struct file *file, int mask);
	int (*file_alloc_provenance) (struct file *file);
	void (*file_free_provenance) (struct file *file);
	int (*file_ioctl) (struct file *file, unsigned int cmd,
			   unsigned long arg);
	int (*file_mmap) (struct file *file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags, unsigned long addr,
			  unsigned long addr_only);
	int (*file_mprotect) (struct vm_area_struct *vma,
			      unsigned long reqprot,
			      unsigned long prot);
	int (*file_lock) (struct file *file, unsigned int cmd);
	int (*file_fcntl) (struct file *file, unsigned int cmd,
			   unsigned long arg);
	int (*file_set_fowner) (struct file *file);
	int (*file_send_sigiotask) (struct task_struct *tsk,
				    struct fown_struct *fown, int sig);
	int (*file_receive) (struct file *file);
	int (*dentry_open) (struct file *file, const struct cred *cred);

	int (*task_create) (unsigned long clone_flags);
  //Hooked
	int (*cred_alloc_blank) (struct cred *cred, gfp_t gfp);
	void (*cred_free) (struct cred *cred);
	int (*cred_prepare)(struct cred *new, const struct cred *old,
			    gfp_t gfp);
	void (*cred_commit)(struct cred *new, const struct cred *old);
	void (*cred_transfer)(struct cred *new, const struct cred *old);
  //End Hooked
	int (*kernel_act_as)(struct cred *new, u32 provid);
	int (*kernel_create_files_as)(struct cred *new, struct inode *inode);
	int (*kernel_module_request)(char *kmod_name);
	int (*task_setuid) (uid_t id0, uid_t id1, uid_t id2, int flags);
	int (*task_fix_setuid) (struct cred *new, const struct cred *old,
				int flags);
	int (*task_setgid) (gid_t id0, gid_t id1, gid_t id2, int flags);
	int (*task_setpgid) (struct task_struct *p, pid_t pgid);
	int (*task_getpgid) (struct task_struct *p);
	int (*task_getsid) (struct task_struct *p);
	void (*task_getprovid) (struct task_struct *p, u32 *provid);
	int (*task_setgroups) (struct group_info *group_info);
	int (*task_setnice) (struct task_struct *p, int nice);
	int (*task_setioprio) (struct task_struct *p, int ioprio);
	int (*task_getioprio) (struct task_struct *p);
	int (*task_setrlimit) (struct task_struct *p, unsigned int resource,
			struct rlimit *new_rlim);
	int (*task_setscheduler) (struct task_struct *p, int policy,
				  struct sched_param *lp);
	int (*task_getscheduler) (struct task_struct *p);
	int (*task_movememory) (struct task_struct *p);
	int (*task_kill) (struct task_struct *p,
			  struct siginfo *info, int sig, u32 provid);
	int (*task_wait) (struct task_struct *p);
	int (*task_prctl) (int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5);
	void (*task_to_inode) (struct task_struct *p, struct inode *inode);

	int (*ipc_permission) (struct kern_ipc_perm *ipcp, short flag);
	void (*ipc_getprovid) (struct kern_ipc_perm *ipcp, u32 *provid);

	int (*msg_msg_alloc_provenance) (struct msg_msg *msg);
	void (*msg_msg_free_provenance) (struct msg_msg *msg);

	int (*msg_queue_alloc_provenance) (struct msg_queue *msq);
	void (*msg_queue_free_provenance) (struct msg_queue *msq);
	int (*msg_queue_associate) (struct msg_queue *msq, int msqflg);
	int (*msg_queue_msgctl) (struct msg_queue *msq, int cmd);
	int (*msg_queue_msgsnd) (struct msg_queue *msq,
				 struct msg_msg *msg, int msqflg);
	int (*msg_queue_msgrcv) (struct msg_queue *msq,
				 struct msg_msg *msg,
				 struct task_struct *target,
				 long type, int mode);

	int (*shm_alloc_provenance) (struct shmid_kernel *shp);
	void (*shm_free_provenance) (struct shmid_kernel *shp);
	int (*shm_associate) (struct shmid_kernel *shp, int shmflg);
	int (*shm_shmctl) (struct shmid_kernel *shp, int cmd);
	int (*shm_shmat) (struct shmid_kernel *shp,
			  char __user *shmaddr, int shmflg);

	int (*sem_alloc_provenance) (struct sem_array *sma);
	void (*sem_free_provenance) (struct sem_array *sma);
	int (*sem_associate) (struct sem_array *sma, int semflg);
	int (*sem_semctl) (struct sem_array *sma, int cmd);
	int (*sem_semop) (struct sem_array *sma,
			  struct sembuf *sops, unsigned nsops, int alter);

	int (*netlink_send) (struct sock *sk, struct sk_buff *skb);
	int (*netlink_recv) (struct sk_buff *skb, int cap);

	void (*d_instantiate) (struct dentry *dentry, struct inode *inode);

	int (*getprocattr) (struct task_struct *p, char *name, char **value);
	int (*setprocattr) (struct task_struct *p, char *name, void *value, size_t size);
	int (*provid_to_provctx) (u32 provid, char **provdata, u32 *seclen);
	int (*provctx_to_provid) (const char *provdata, u32 seclen, u32 *provid);
	void (*release_provctx) (char *provdata, u32 seclen);

	int (*inode_notifyprovctx)(struct inode *inode, void *ctx, u32 ctxlen);
	int (*inode_setprovctx)(struct dentry *dentry, void *ctx, u32 ctxlen);
	int (*inode_getprovctx)(struct inode *inode, void **ctx, u32 *ctxlen);

	int (*unix_stream_connect) (struct socket *sock,
				    struct socket *other, struct sock *newsk);
	int (*unix_may_send) (struct socket *sock, struct socket *other);

	int (*socket_create) (int family, int type, int protocol, int kern);
	int (*socket_post_create) (struct socket *sock, int family,
				   int type, int protocol, int kern);
	int (*socket_bind) (struct socket *sock,
			    struct sockaddr *address, int addrlen);
	int (*socket_connect) (struct socket *sock,
			       struct sockaddr *address, int addrlen);
	int (*socket_listen) (struct socket *sock, int backlog);
	int (*socket_accept) (struct socket *sock, struct socket *newsock);
	int (*socket_sendmsg) (struct socket *sock,
			       struct msghdr *msg, int size);
	int (*socket_recvmsg) (struct socket *sock,
			       struct msghdr *msg, int size, int flags);
        void (*socket_post_recvmsg) (struct socket *sock,
                               struct msghdr *msg, int size, int flags);
	int (*socket_getsockname) (struct socket *sock);
	int (*socket_getpeername) (struct socket *sock);
	int (*socket_getsockopt) (struct socket *sock, int level, int optname);
	int (*socket_setsockopt) (struct socket *sock, int level, int optname);
	int (*socket_shutdown) (struct socket *sock, int how);
	int (*socket_sock_rcv_skb) (struct sock *sk, struct sk_buff *skb);
        int (*skb_shinfo_alloc_provenance) (struct sk_buff *skb, int recycling,
					  gfp_t gfp);
        void (*skb_shinfo_free_provenance) (struct sk_buff *skb, int recycling);
        int (*skb_shinfo_copy) (struct sk_buff *skb,
				struct skb_shared_info *shinfo, gfp_t gfp);
        int (*socket_dgram_append) (struct sock *sk, struct sk_buff *head);
        void (*socket_dgram_post_recv) (struct sock *sk, struct sk_buff *skb);
	int (*socket_getpeersec_stream) (struct socket *sock, char __user *optval, int __user *optlen, unsigned len);
	int (*socket_getpeersec_dgram) (struct socket *sock, struct sk_buff *skb, u32 *provid);
	int (*sk_alloc_provenance) (struct sock *sk, int family, gfp_t priority);
	void (*sk_free_provenance) (struct sock *sk);
	void (*sk_clone_provenance) (const struct sock *sk, struct sock *newsk);
        void (*sk_classify_flow) (struct sock *sk, struct flowi *fl);
	void (*sk_getprovid) (struct sock *sk, u32 *provid);
	void (*sock_graft) (struct sock *sk, struct socket *parent);
	int (*inet_conn_request) (struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req);
	void (*inet_csk_clone) (struct sock *newsk, const struct request_sock *req);
	void (*inet_conn_established) (struct sock *sk, struct sk_buff *skb);
	void (*req_classify_flow) (const struct request_sock *req, struct flowi *fl);
	int (*tun_dev_create)(void);
	void (*tun_dev_post_create)(struct sock *sk);
	int (*tun_dev_attach)(struct sock *sk);

};

/* prototypes */
extern int provenance_init(void);
extern int provenance_module_enable(struct provenance_operations *ops);
extern int register_provenance(struct provenance_operations *ops);

/* provenance operations */
int provenance_ptrace_access_check(struct task_struct *child, unsigned int mode);
int provenance_ptrace_traceme(struct task_struct *parent);
int provenance_acct(struct file *file);
int provenance_sysctl(struct ctl_table *table, int op);
int provenance_quotactl(int cmds, int type, int id, struct super_block *sb);
int provenance_quota_on(struct dentry *dentry);
int provenance_syslog(int type);
int provenance_settime(const struct timespec *ts, const struct timezone *tz);
int provenance_vm_enough_memory(long pages);
int provenance_vm_enough_memory_mm(struct mm_struct *mm, long pages);
int provenance_vm_enough_memory_kern(long pages);

int provenance_bprm_set_creds(struct linux_binprm *bprm);
int provenance_bprm_check(struct linux_binprm *bprm);
void provenance_bprm_committing_creds(struct linux_binprm *bprm);
void provenance_bprm_committed_creds(struct linux_binprm *bprm);
int provenance_bprm_secureexec(struct linux_binprm *bprm);
int provenance_sb_alloc(struct super_block *sb);
void provenance_sb_free(struct super_block *sb);
int provenance_sb_copy_data(char *orig, char *copy);
int provenance_sb_remount(struct super_block *sb, void *data);
int provenance_sb_kern_mount(struct super_block *sb, int flags, void *data);
int provenance_sb_show_options(struct seq_file *m, struct super_block *sb);
int provenance_sb_statfs(struct dentry *dentry);
int provenance_sb_mount(char *dev_name, struct path *path,
		      char *type, unsigned long flags, void *data);
int provenance_sb_check_sb(struct vfsmount *mnt, struct path *path);
int provenance_sb_umount(struct vfsmount *mnt, int flags);
void provenance_sb_umount_close(struct vfsmount *mnt);
void provenance_sb_umount_busy(struct vfsmount *mnt);
void provenance_sb_post_remount(struct vfsmount *mnt, unsigned long flags, void *data);
void provenance_sb_post_addmount(struct vfsmount *mnt, struct path *mountpoint);
int provenance_sb_pivotroot(struct path *old_path, struct path *new_path);
void provenance_sb_post_pivotroot(struct path *old_path, struct path *new_path);
int provenance_sb_set_mnt_opts(struct super_block *sb, struct provenance_mnt_opts *opts);
void provenance_sb_clone_mnt_opts(const struct super_block *oldsb,
				struct super_block *newsb);
int provenance_sb_parse_opts_str(char *options, struct provenance_mnt_opts *opts);

int provenance_inode_alloc(struct inode *inode);
void provenance_inode_free(struct inode *inode);
int provenance_inode_init_provenance(struct inode *inode, struct inode *dir,
				  char **name, void **value, size_t *len);
int provenance_inode_create(struct inode *dir, struct dentry *dentry, int mode);
int provenance_inode_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry);
int provenance_inode_unlink(struct inode *dir, struct dentry *dentry);
int provenance_inode_symlink(struct inode *dir, struct dentry *dentry,
			   const char *old_name);
int provenance_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode);
int provenance_inode_rmdir(struct inode *dir, struct dentry *dentry);
int provenance_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
int provenance_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			  struct inode *new_dir, struct dentry *new_dentry);
int provenance_inode_readlink(struct dentry *dentry);
int provenance_inode_follow_link(struct dentry *dentry, struct nameidata *nd);
int provenance_inode_permission(struct inode *inode, int mask);
int provenance_inode_setattr(struct dentry *dentry, struct iattr *attr);
int provenance_inode_getattr(struct vfsmount *mnt, struct dentry *dentry);
void provenance_inode_delete(struct inode *inode);
int provenance_inode_setxattr(struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags);
void provenance_inode_post_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags);
int provenance_inode_getxattr(struct dentry *dentry, const char *name);
int provenance_inode_listxattr(struct dentry *dentry);
int provenance_inode_removexattr(struct dentry *dentry, const char *name);
int provenance_inode_need_killpriv(struct dentry *dentry);
int provenance_inode_killpriv(struct dentry *dentry);
int provenance_inode_getprovenance(const struct inode *inode, const char *name, void **buffer, bool alloc);
int provenance_inode_setprovenance(struct inode *inode, const char *name, const void *value, size_t size, int flags);
int provenance_inode_listprovenance(struct inode *inode, char *buffer, size_t buffer_size);
void provenance_inode_getprovid(const struct inode *inode, u32 *provid);
int provenance_file_permission(struct file *file, int mask);
int provenance_file_alloc(struct file *file);
void provenance_file_free(struct file *file);
int provenance_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int provenance_file_mmap(struct file *file, unsigned long reqprot,
			unsigned long prot, unsigned long flags,
			unsigned long addr, unsigned long addr_only);
int provenance_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			   unsigned long prot);
int provenance_file_lock(struct file *file, unsigned int cmd);
int provenance_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
int provenance_file_set_fowner(struct file *file);
int provenance_file_send_sigiotask(struct task_struct *tsk,
				 struct fown_struct *fown, int sig);
int provenance_file_receive(struct file *file);
int provenance_dentry_open(struct file *file, const struct cred *cred);
int provenance_task_create(unsigned long clone_flags);
int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp);
void provenance_cred_free(struct cred *cred);
int provenance_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp);
void provenance_commit_creds(struct cred *new, const struct cred *old);
void provenance_transfer_creds(struct cred *new, const struct cred *old);
int provenance_kernel_act_as(struct cred *new, u32 provid);
int provenance_kernel_create_files_as(struct cred *new, struct inode *inode);
int provenance_kernel_module_request(char *kmod_name);
int provenance_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags);
int provenance_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags);
int provenance_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags);
int provenance_task_setpgid(struct task_struct *p, pid_t pgid);
int provenance_task_getpgid(struct task_struct *p);
int provenance_task_getsid(struct task_struct *p);
void provenance_task_getprovid(struct task_struct *p, u32 *provid);
int provenance_task_setgroups(struct group_info *group_info);
int provenance_task_setnice(struct task_struct *p, int nice);
int provenance_task_setioprio(struct task_struct *p, int ioprio);
int provenance_task_getioprio(struct task_struct *p);
int provenance_task_setrlimit(struct task_struct *p, unsigned int resource,
		struct rlimit *new_rlim);
int provenance_task_setscheduler(struct task_struct *p,
				int policy, struct sched_param *lp);
int provenance_task_getscheduler(struct task_struct *p);
int provenance_task_movememory(struct task_struct *p);
int provenance_task_kill(struct task_struct *p, struct siginfo *info,
			int sig, u32 provid);
int provenance_task_wait(struct task_struct *p);
int provenance_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			unsigned long arg4, unsigned long arg5);
void provenance_task_to_inode(struct task_struct *p, struct inode *inode);
int provenance_ipc_permission(struct kern_ipc_perm *ipcp, short flag);
void provenance_ipc_getprovid(struct kern_ipc_perm *ipcp, u32 *provid);
int provenance_msg_msg_alloc(struct msg_msg *msg);
void provenance_msg_msg_free(struct msg_msg *msg);
int provenance_msg_queue_alloc(struct msg_queue *msq);
void provenance_msg_queue_free(struct msg_queue *msq);
int provenance_msg_queue_associate(struct msg_queue *msq, int msqflg);
int provenance_msg_queue_msgctl(struct msg_queue *msq, int cmd);
int provenance_msg_queue_msgsnd(struct msg_queue *msq,
			      struct msg_msg *msg, int msqflg);
int provenance_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
			      struct task_struct *target, long type, int mode);
int provenance_shm_alloc(struct shmid_kernel *shp);
void provenance_shm_free(struct shmid_kernel *shp);
int provenance_shm_associate(struct shmid_kernel *shp, int shmflg);
int provenance_shm_shmctl(struct shmid_kernel *shp, int cmd);
int provenance_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr, int shmflg);
int provenance_sem_alloc(struct sem_array *sma);
void provenance_sem_free(struct sem_array *sma);
int provenance_sem_associate(struct sem_array *sma, int semflg);
int provenance_sem_semctl(struct sem_array *sma, int cmd);
int provenance_sem_semop(struct sem_array *sma, struct sembuf *sops,
			unsigned nsops, int alter);
void provenance_d_instantiate(struct dentry *dentry, struct inode *inode);
int provenance_getprocattr(struct task_struct *p, char *name, char **value);
int provenance_setprocattr(struct task_struct *p, char *name, void *value, size_t size);
int provenance_netlink_send(struct sock *sk, struct sk_buff *skb);
int provenance_netlink_recv(struct sk_buff *skb, int cap);
int provenance_provid_to_provctx(u32 provid, char **provdata, u32 *seclen);
int provenance_provctx_to_provid(const char *provdata, u32 seclen, u32 *provid);
void provenance_release_provctx(char *provdata, u32 seclen);

int provenance_inode_notifyprovctx(struct inode *inode, void *ctx, u32 ctxlen);
int provenance_inode_setprovctx(struct dentry *dentry, void *ctx, u32 ctxlen);
int provenance_inode_getprovctx(struct inode *inode, void **ctx, u32 *ctxlen);

int provenance_path_truncate(struct path *path, loff_t length,
			   unsigned int time_attrs);
#else /* CONFIG_PROVENANCE */
struct provenance_mnt_opts {
};

static inline int provenance_init(void)
{
	return 0;
}

static inline int provenance_ptrace_access_check(struct task_struct *child,
					     unsigned int mode)
{
        return 0;
}

static inline int provenance_ptrace_traceme(struct task_struct *parent)
{
        return 0;
}

static inline void provenance_init_mnt_opts(struct provenance_mnt_opts *opts)
{
}

static inline void provenance_free_mnt_opts(struct provenance_mnt_opts *opts)
{
}

static inline int provenance_bprm_set_creds(struct linux_binprm *bprm)
{
        return 0;
}

static inline int provenance_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static inline void provenance_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static inline void provenance_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static inline int provenance_bprm_secureexec(struct linux_binprm *bprm)
{
        return 0;
}

static inline int provenance_sb_alloc(struct super_block *sb)
{
	return 0;
}

static inline void provenance_sb_free(struct super_block *sb)
{ }

static inline int provenance_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static inline int provenance_sb_remount(struct super_block *sb, void *data)
{
	return 0;
}

static inline int provenance_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static inline int provenance_sb_show_options(struct seq_file *m,
					   struct super_block *sb)
{
	return 0;
}

static inline int provenance_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static inline int provenance_sb_mount(char *dev_name, struct path *path,
				    char *type, unsigned long flags,
				    void *data)
{
	return 0;
}

static inline int provenance_sb_check_sb(struct vfsmount *mnt,
				       struct path *path)
{
	return 0;
}

static inline int provenance_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static inline void provenance_sb_umount_close(struct vfsmount *mnt)
{ }

static inline void provenance_sb_umount_busy(struct vfsmount *mnt)
{ }

static inline void provenance_sb_post_remount(struct vfsmount *mnt,
					     unsigned long flags, void *data)
{ }

static inline void provenance_sb_post_addmount(struct vfsmount *mnt,
					     struct path *mountpoint)
{ }

static inline int provenance_sb_pivotroot(struct path *old_path,
					struct path *new_path)
{
	return 0;
}

static inline void provenance_sb_post_pivotroot(struct path *old_path,
					      struct path *new_path)
{ }

static inline int provenance_sb_set_mnt_opts(struct super_block *sb,
					   struct provenance_mnt_opts *opts)
{
	return 0;
}

static inline void provenance_sb_clone_mnt_opts(const struct super_block *oldsb,
					      struct super_block *newsb)
{ }

static inline int provenance_sb_parse_opts_str(char *options, struct provenance_mnt_opts *opts)
{
	return 0;
}

static inline int provenance_inode_alloc(struct inode *inode)
{
	return 0;
}

static inline void provenance_inode_free(struct inode *inode)
{ }

static inline int provenance_inode_init_provenance(struct inode *inode,
						struct inode *dir,
						char **name,
						void **value,
						size_t *len)
{
	return -EOPNOTSUPP;
}

static inline int provenance_inode_create(struct inode *dir,
					 struct dentry *dentry,
					 int mode)
{
	return 0;
}

static inline int provenance_inode_link(struct dentry *old_dentry,
				       struct inode *dir,
				       struct dentry *new_dentry)
{
	return 0;
}

static inline int provenance_inode_unlink(struct inode *dir,
					 struct dentry *dentry)
{
	return 0;
}

static inline int provenance_inode_symlink(struct inode *dir,
					  struct dentry *dentry,
					  const char *old_name)
{
	return 0;
}

static inline int provenance_inode_mkdir(struct inode *dir,
					struct dentry *dentry,
					int mode)
{
	return 0;
}

static inline int provenance_inode_rmdir(struct inode *dir,
					struct dentry *dentry)
{
	return 0;
}

static inline int provenance_inode_mknod(struct inode *dir,
					struct dentry *dentry,
					int mode, dev_t dev)
{
	return 0;
}

static inline int provenance_inode_rename(struct inode *old_dir,
					 struct dentry *old_dentry,
					 struct inode *new_dir,
					 struct dentry *new_dentry)
{
	return 0;
}

static inline int provenance_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static inline int provenance_inode_follow_link(struct dentry *dentry,
					      struct nameidata *nd)
{
	return 0;
}

static inline int provenance_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static inline int provenance_inode_setattr(struct dentry *dentry,
					  struct iattr *attr)
{
	return 0;
}

static inline int provenance_inode_getattr(struct vfsmount *mnt,
					  struct dentry *dentry)
{
	return 0;
}

static inline void provenance_inode_delete(struct inode *inode)
{ }

static inline int provenance_inode_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{
  return 0;
}

static inline void provenance_inode_post_setxattr(struct dentry *dentry,
		const char *name, const void *value, size_t size, int flags)
{ }

static inline int provenance_inode_getxattr(struct dentry *dentry,
			const char *name)
{
	return 0;
}

static inline int provenance_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static inline int provenance_inode_removexattr(struct dentry *dentry,
			const char *name)
{
  return 0;
}

static inline int provenance_inode_need_killpriv(struct dentry *dentry)
{
  return 0;
}

static inline int provenance_inode_killpriv(struct dentry *dentry)
{
  return 0;
}

static inline int provenance_inode_getprovenance(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static inline int provenance_inode_setprovenance(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static inline int provenance_inode_listprovenance(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

static inline void provenance_inode_getprovid(const struct inode *inode, u32 *provid)
{
	*provid = 0;
}

static inline int provenance_file_permission(struct file *file, int mask)
{
	return 0;
}

static inline int provenance_file_alloc(struct file *file)
{
	return 0;
}

static inline void provenance_file_free(struct file *file)
{ }

static inline int provenance_file_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return 0;
}

static inline int provenance_file_mmap(struct file *file, unsigned long reqprot,
				     unsigned long prot,
				     unsigned long flags,
				     unsigned long addr,
				     unsigned long addr_only)
{
  return 0;
}

static inline int provenance_file_mprotect(struct vm_area_struct *vma,
					 unsigned long reqprot,
					 unsigned long prot)
{
	return 0;
}

static inline int provenance_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static inline int provenance_file_fcntl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return 0;
}

static inline int provenance_file_set_fowner(struct file *file)
{
	return 0;
}

static inline int provenance_file_send_sigiotask(struct task_struct *tsk,
					       struct fown_struct *fown,
					       int sig)
{
	return 0;
}

static inline int provenance_file_receive(struct file *file)
{
	return 0;
}

static inline int provenance_dentry_open(struct file *file,
				       const struct cred *cred)
{
	return 0;
}

static inline int provenance_task_create(unsigned long clone_flags)
{
	return 0;
}

static inline int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static inline void provenance_cred_free(struct cred *cred)
{ }

static inline int provenance_prepare_creds(struct cred *new,
					 const struct cred *old,
					 gfp_t gfp)
{
	return 0;
}

static inline void provenance_commit_creds(struct cred *new,
					 const struct cred *old)
{
}

static inline void provenance_transfer_creds(struct cred *new,
					   const struct cred *old)
{
}

static inline int provenance_kernel_act_as(struct cred *cred, u32 provid)
{
	return 0;
}

static inline int provenance_kernel_create_files_as(struct cred *cred,
						  struct inode *inode)
{
	return 0;
}

static inline int provenance_kernel_module_request(char *kmod_name)
{
	return 0;
}

static inline int provenance_task_setuid(uid_t id0, uid_t id1, uid_t id2,
				       int flags)
{
	return 0;
}

static inline int provenance_task_fix_setuid(struct cred *new,
					   const struct cred *old,
					   int flags)
{
  return 0;
}

static inline int provenance_task_setgid(gid_t id0, gid_t id1, gid_t id2,
				       int flags)
{
	return 0;
}

static inline int provenance_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static inline int provenance_task_getpgid(struct task_struct *p)
{
	return 0;
}

static inline int provenance_task_getsid(struct task_struct *p)
{
	return 0;
}

static inline void provenance_task_getprovid(struct task_struct *p, u32 *provid)
{
	*provid = 0;
}

static inline int provenance_task_setgroups(struct group_info *group_info)
{
	return 0;
}

static inline int provenance_task_setnice(struct task_struct *p, int nice)
{
  return 0;
}

static inline int provenance_task_setioprio(struct task_struct *p, int ioprio)
{
  return 0;
}

static inline int provenance_task_getioprio(struct task_struct *p)
{
	return 0;
}

static inline int provenance_task_setrlimit(struct task_struct *p,
					  unsigned int resource,
					  struct rlimit *new_rlim)
{
	return 0;
}

static inline int provenance_task_setscheduler(struct task_struct *p,
					     int policy,
					     struct sched_param *lp)
{
  return 0;
}

static inline int provenance_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static inline int provenance_task_movememory(struct task_struct *p)
{
	return 0;
}

static inline int provenance_task_kill(struct task_struct *p,
				     struct siginfo *info, int sig,
				     u32 provid)
{
	return 0;
}

static inline int provenance_task_wait(struct task_struct *p)
{
	return 0;
}

static inline int provenance_task_prctl(int option, unsigned long arg2,
				      unsigned long arg3,
				      unsigned long arg4,
				      unsigned long arg5)
{
  return 0;
}

static inline void provenance_task_to_inode(struct task_struct *p, struct inode *inode)
{ }

static inline int provenance_ipc_permission(struct kern_ipc_perm *ipcp,
					  short flag)
{
	return 0;
}

static inline void provenance_ipc_getprovid(struct kern_ipc_perm *ipcp, u32 *provid)
{
	*provid = 0;
}

static inline int provenance_msg_msg_alloc(struct msg_msg *msg)
{
	return 0;
}

static inline void provenance_msg_msg_free(struct msg_msg *msg)
{ }

static inline int provenance_msg_queue_alloc(struct msg_queue *msq)
{
	return 0;
}

static inline void provenance_msg_queue_free(struct msg_queue *msq)
{ }

static inline int provenance_msg_queue_associate(struct msg_queue *msq,
					       int msqflg)
{
	return 0;
}

static inline int provenance_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static inline int provenance_msg_queue_msgsnd(struct msg_queue *msq,
					    struct msg_msg *msg, int msqflg)
{
	return 0;
}

static inline int provenance_msg_queue_msgrcv(struct msg_queue *msq,
					    struct msg_msg *msg,
					    struct task_struct *target,
					    long type, int mode)
{
	return 0;
}

static inline int provenance_shm_alloc(struct shmid_kernel *shp)
{
	return 0;
}

static inline void provenance_shm_free(struct shmid_kernel *shp)
{ }

static inline int provenance_shm_associate(struct shmid_kernel *shp,
					 int shmflg)
{
	return 0;
}

static inline int provenance_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static inline int provenance_shm_shmat(struct shmid_kernel *shp,
				     char __user *shmaddr, int shmflg)
{
	return 0;
}

static inline int provenance_sem_alloc(struct sem_array *sma)
{
	return 0;
}

static inline void provenance_sem_free(struct sem_array *sma)
{ }

static inline int provenance_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static inline int provenance_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static inline int provenance_sem_semop(struct sem_array *sma,
				     struct sembuf *sops, unsigned nsops,
				     int alter)
{
	return 0;
}

static inline void provenance_d_instantiate(struct dentry *dentry, struct inode *inode)
{ }

static inline int provenance_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static inline int provenance_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	return -EINVAL;
}

static inline int provenance_netlink_send(struct sock *sk, struct sk_buff *skb)
{
  return 0;
}

static inline int provenance_netlink_recv(struct sk_buff *skb, int cap)
{
  return 0;
}

static inline int provenance_provid_to_provctx(u32 provid, char **provdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static inline int provenance_provctx_to_provid(const char *provdata,
					   u32 seclen,
					   u32 *provid)
{
	return -EOPNOTSUPP;
}

static inline void provenance_release_provctx(char *provdata, u32 seclen)
{
}

static inline int provenance_inode_notifyprovctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}
static inline int provenance_inode_setprovctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}
static inline int provenance_inode_getprovctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return -EOPNOTSUPP;
}

static inline int provenance_path_truncate(struct path *path, loff_t length,
					 unsigned int time_attrs)
{
	return 0;
}
#endif	/* CONFIG_PROVENANCE */


int provenance_unix_stream_connect(struct socket *sock, struct socket *other,
				 struct sock *newsk);
int provenance_unix_may_send(struct socket *sock,  struct socket *other);
int provenance_socket_create(int family, int type, int protocol, int kern);
int provenance_socket_post_create(struct socket *sock, int family,
				int type, int protocol, int kern);
int provenance_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
int provenance_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
int provenance_socket_listen(struct socket *sock, int backlog);
int provenance_socket_accept(struct socket *sock, struct socket *newsock);
int provenance_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);
int provenance_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			    int size, int flags);
void provenance_socket_post_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags);
int provenance_socket_getsockname(struct socket *sock);
int provenance_socket_getpeername(struct socket *sock);
int provenance_socket_getsockopt(struct socket *sock, int level, int optname);
int provenance_socket_setsockopt(struct socket *sock, int level, int optname);
int provenance_socket_shutdown(struct socket *sock, int how);
int provenance_sock_rcv_skb(struct sock *sk, struct sk_buff *skb);
int provenance_skb_shinfo_alloc(struct sk_buff *skb, int recycling, gfp_t gfp);
void provenance_skb_shinfo_free(struct sk_buff *skb, int recycling);
int provenance_skb_shinfo_copy(struct sk_buff *skb, struct skb_shared_info *shinfo,
			     gfp_t gfp);
int provenance_socket_dgram_append(struct sock *sk, struct sk_buff *head);
void provenance_socket_dgram_post_recv(struct sock *sk, struct sk_buff *skb);
int provenance_socket_getpeersec_stream(struct socket *sock, char __user *optval,
				      int __user *optlen, unsigned len);
int provenance_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *provid);
int provenance_sk_alloc(struct sock *sk, int family, gfp_t priority);
void provenance_sk_free(struct sock *sk);
void provenance_sk_clone(const struct sock *sk, struct sock *newsk);
void provenance_sk_classify_flow(struct sock *sk, struct flowi *fl);
void provenance_req_classify_flow(const struct request_sock *req, struct flowi *fl);
void provenance_sock_graft(struct sock*sk, struct socket *parent);
int provenance_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req);
void provenance_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req);
void provenance_inet_conn_established(struct sock *sk,
			struct sk_buff *skb);
int provenance_tun_dev_create(void);
void provenance_tun_dev_post_create(struct sock *sk);
int provenance_tun_dev_attach(struct sock *sk);

/*
static inline int provenance_unix_stream_connect(struct socket *sock,
					       struct socket *other,
					       struct sock *newsk)
{
	return 0;
}

static inline int provenance_unix_may_send(struct socket *sock,
					 struct socket *other)
{
	return 0;
}

static inline int provenance_socket_create(int family, int type,
					 int protocol, int kern)
{
	return 0;
}

static inline int provenance_socket_post_create(struct socket *sock,
					      int family,
					      int type,
					      int protocol, int kern)
{
	return 0;
}

static inline int provenance_socket_bind(struct socket *sock,
				       struct sockaddr *address,
				       int addrlen)
{
	return 0;
}

static inline int provenance_socket_connect(struct socket *sock,
					  struct sockaddr *address,
					  int addrlen)
{
	return 0;
}

static inline int provenance_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static inline int provenance_socket_accept(struct socket *sock,
					 struct socket *newsock)
{
	return 0;
}

static inline int provenance_socket_sendmsg(struct socket *sock,
					  struct msghdr *msg, int size)
{
	return 0;
}

static inline int provenance_socket_recvmsg(struct socket *sock,
					  struct msghdr *msg, int size,
					  int flags)
{
	return 0;
}

static inline void provenance_socket_post_recvmsg(struct socket *sock,
						struct msghdr *msg, int size,
						int flags)
{
} 

static inline int provenance_socket_getsockname(struct socket *sock)
{
	return 0;
}

static inline int provenance_socket_getpeername(struct socket *sock)
{
	return 0;
}

static inline int provenance_socket_getsockopt(struct socket *sock,
					     int level, int optname)
{
	return 0;
}

static inline int provenance_socket_setsockopt(struct socket *sock,
					     int level, int optname)
{
	return 0;
}

static inline int provenance_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}
static inline int provenance_sock_rcv_skb(struct sock *sk,
					struct sk_buff *skb)
{
	return 0;
}

static inline int provenance_skb_shinfo_alloc(struct sk_buff *skb, int recycling,
					    gfp_t gfp)
{
        return 0;
}

static inline void provenance_skb_shinfo_free(struct sk_buff *skb, int recycling)
{
}

static inline int provenance_skb_shinfo_copy(struct sk_buff *skb,
					   struct skb_shared_info *shinfo, gfp_t gfp)
{
        return 0;
}

static inline int provenance_socket_dgram_append(struct sock *sk,
					       struct sk_buff *head)
{
        return 0;
}

static inline void provenance_socket_dgram_post_recv(struct sock *sk,
						   struct sk_buff *skb)
{
}

static inline int provenance_socket_getpeersec_stream(struct socket *sock, char __user *optval,
						    int __user *optlen, unsigned len)
{
	return -ENOPROTOOPT;
}

static inline int provenance_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *provid)
{
	return -ENOPROTOOPT;
}

static inline int provenance_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static inline void provenance_sk_free(struct sock *sk)
{
}

static inline void provenance_sk_clone(const struct sock *sk, struct sock *newsk)
{
}

static inline void provenance_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
}

static inline void provenance_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
}

static inline void provenance_sock_graft(struct sock *sk, struct socket *parent)
{
}

static inline int provenance_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req)
{
	return 0;
}

static inline void provenance_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req)
{
}

static inline void provenance_inet_conn_established(struct sock *sk,
			struct sk_buff *skb)
{
}

static inline int provenance_tun_dev_create(void)
{
	return 0;
}

static inline void provenance_tun_dev_post_create(struct sock *sk)
{
}

static inline int provenance_tun_dev_attach(struct sock *sk)
{
	return 0;
}
*/


#ifdef CONFIG_PROVENANCE_PATH
int provenance_path_unlink(struct path *dir, struct dentry *dentry);
int provenance_path_mkdir(struct path *dir, struct dentry *dentry, int mode);
int provenance_path_rmdir(struct path *dir, struct dentry *dentry);
int provenance_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			unsigned int dev);
int provenance_path_symlink(struct path *dir, struct dentry *dentry,
			  const char *old_name);
int provenance_path_link(struct dentry *old_dentry, struct path *new_dir,
		       struct dentry *new_dentry);
int provenance_path_rename(struct path *old_dir, struct dentry *old_dentry,
			 struct path *new_dir, struct dentry *new_dentry);
#else	/* CONFIG_PROVENANCE_PATH */
static inline int provenance_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static inline int provenance_path_mkdir(struct path *dir, struct dentry *dentry,
				      int mode)
{
	return 0;
}

static inline int provenance_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static inline int provenance_path_mknod(struct path *dir, struct dentry *dentry,
				      int mode, unsigned int dev)
{
	return 0;
}

static inline int provenance_path_symlink(struct path *dir, struct dentry *dentry,
					const char *old_name)
{
	return 0;
}

static inline int provenance_path_link(struct dentry *old_dentry,
				     struct path *new_dir,
				     struct dentry *new_dentry)
{
	return 0;
}

static inline int provenance_path_rename(struct path *old_dir,
				       struct dentry *old_dentry,
				       struct path *new_dir,
				       struct dentry *new_dentry)
{
	return 0;
}
#endif
#ifdef CONFIG_PROVENANCE

static inline char *alloc_provdata(void)
{
	return (char *)get_zeroed_page(GFP_KERNEL);
}

static inline void free_provdata(void *provdata)
{
	free_page((unsigned long)provdata);
}

#else

static inline char *alloc_provdata(void)
{
        return (char *)1;
}

static inline void free_provdata(void *provdata)
{ }
#endif /* CONFIG_PROVENANCE */

#endif /* ! __LINUX_PROVENANCE_H */

