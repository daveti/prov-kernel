/*
 * Provenance Monitor: a high-fidelity, whole-system provenance monitor
 *
 * Authors:  Devin J. Pohly <djpohly@cse.psu.edu>
 *           Adam M. Bates <amb@cs.uoregon.edu>           
 *
 * Copyright (C) 2013 The Pennsylvania State University
 * Systems and Internet Infrastructure Security Laboratory
 *
 * Copyright (C) 2013 MIT Lincoln Laboratory 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/kmod.h>

#include <linux/highmem.h>
#include <linux/uaccess.h>

#include <linux/stddef.h>
#include <linux/limits.h>
#include <linux/binfmts.h>
#include <linux/cred.h>

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/xattr.h>

/* For getting human-readable file data */
#include <linux/mnt_namespace.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>

/* for generate_random_uuid */
#include <linux/random.h>
#include <linux/uuid.h>

/* for relay support */
#include <linux/debugfs.h>
#include <linux/relay.h>
#include <linux/spinlock.h>

/* for UNIX domain sockets */
#include <linux/net.h>
#include <net/sock.h>
#include <net/af_unix.h>

/* for IP sockets */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <linux/provenance.h>
#include <linux/dcache.h>

#include <linux/provenance_network.h>
#include <linux/provenance_fs.h>

#include <linux/linkage.h>

#include "provmon_proto.h"

MODULE_AUTHOR("Adam M. Bates");
MODULE_DESCRIPTION("Provenance Monitor (LPM)");
MODULE_LICENSE("GPL");


int bufs = 256;
int buf_size_shift = 20;
int boot_buf_size = 10240 * 4;


//Orig values
//int bufs = 32;
//int buf_size_shift = 20;
//int boot_buf_size = 1024;

module_param(bufs, int, 0);
module_param(buf_size_shift, int, 0);
module_param(boot_buf_size, int, 0);

MODULE_PARM_DESC(bufs, "Number of relay sub-buffers for provenance data (default: 32)");
MODULE_PARM_DESC(buf_size_shift, "Log base 2 of sub-buffer size (default: 20=1MiB");
MODULE_PARM_DESC(boot_buf_size, "Size of temporary boot buffer (default: 1024)");

#define BITS_PER_PAGE (PAGE_SIZE*8)
#define BITS_PER_PAGE_MASK (BITS_PER_PAGE-1)
#define PROVID_MAP_PAGES 4
#define NUM_PROVIDS (PROVID_MAP_PAGES * BITS_PER_PAGE)
static atomic_t provid_free[PROVID_MAP_PAGES] = {
	[0 ... PROVID_MAP_PAGES-1] = ATOMIC_INIT(BITS_PER_PAGE)
};
static void *provid_page[PROVID_MAP_PAGES] = {
	[0 ... PROVID_MAP_PAGES-1] = NULL
};
static int provid_last = -1;

static char *boot_buffer;
static unsigned boot_bytes = 0;
static struct rchan *relay;
static DEFINE_SPINLOCK(relay_lock);

static atomic64_t sock_counter = ATOMIC64_INIT(0);

/******************************************************************************
 *
 * RELAY SETUP
 *
 ******************************************************************************/

/*
 * Writes to the relay
 */
static void write_to_relay(const void *data, size_t length)
{
	unsigned long flags;
	spin_lock_irqsave(&relay_lock, flags);
	if (unlikely(!relay)) {
		if (boot_bytes + length > boot_buf_size)
			panic("Provenance Monitor: Boot buffer overrun");
		memcpy(boot_buffer + boot_bytes, data, length);
		boot_bytes += length;
	} else {
		relay_write(relay, data, length);
	}
	spin_unlock_irqrestore(&relay_lock, flags);
}

/*
 * Implementation of relay behavior
 */
static struct dentry *relay_dentry;

static struct dentry *relay_create_file(const char *filename,
		struct dentry *parent, int mode, struct rchan_buf *buf,
		int *is_global)
{
	*is_global = 1;
	relay_dentry = dget(debugfs_create_file(filename, mode, parent, buf,
			&relay_file_operations));
	return relay_dentry;
}

static int relay_remove_file(struct dentry *dentry)
{
	dput(relay_dentry);
	debugfs_remove(dentry);
	return 0;
}

static int relay_subbuf_start(struct rchan_buf *buf, void *subbuf,
		void *prev_subbuf, size_t prev_padding)
{
	/* Prevent loss of provenance data */
	if (relay_buf_full(buf))
		panic("Provenance Monitor: no space left in relay!");
	return 1;
}

static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = relay_create_file,
	.remove_buf_file = relay_remove_file,
	.subbuf_start = relay_subbuf_start
};

/* Initial messages */
static uuid_be boot_uuid;
static __initdata struct provmsg_boot init_bootmsg = {
	.msg.len_lo = MSGLEN_LO(sizeof(struct provmsg_boot)),
	.msg.len_hi = MSGLEN_HI(sizeof(struct provmsg_boot)),
	.msg.type = PROVMSG_BOOT,
	.msg.cred_id = 0,
	/* .uuid is {0} to start with */
};

static __initdata struct provmsg_setid init_setidmsg = {
	.msg.len_lo = MSGLEN_LO(sizeof(struct provmsg_setid)),
	.msg.len_hi = MSGLEN_HI(sizeof(struct provmsg_setid)),
	.msg.type = PROVMSG_SETID,
	.msg.cred_id = 0,
	/* Static, so all IDs are (correctly) inited to 0=root */
};

/*
 * Sets up the relay
 */
static int __init provmon_init_relay(void)
{
	relay = relay_open("provenance", NULL, (1 << buf_size_shift),
			bufs, &relay_callbacks, NULL);
	if (!relay)
		panic("Provenance Monitor: Could not create relay");
	init_bootmsg.uuid = boot_uuid;
	write_to_relay(&init_bootmsg, sizeof(init_bootmsg));
	write_to_relay(&init_setidmsg, sizeof(init_setidmsg));
	printk(KERN_INFO "Provenance Monitor: Replaying boot buffer: %uB\n", boot_bytes);
	write_to_relay(boot_buffer, boot_bytes);
	kfree(boot_buffer);
	return 0;
}
core_initcall(provmon_init_relay);


/******************************************************************************
 *
 * HELPER FUNCTIONS
 *
 ******************************************************************************/

/*
 * Grabs the argv and envp from a bprm.
 */
static int copy_bytes_bprm(struct linux_binprm *bprm, char *dst,
		unsigned int count)
{
	int rv = 0;
	unsigned int ofs, bytes;
	struct page *page = NULL, *new_page;
	const char *kaddr;
	unsigned long src;

	src = bprm->p;
	ofs = src % PAGE_SIZE;

	while (count) {
		/* Map new page if there's more to come */
		new_page = get_arg_page(bprm, src, 0);
		if (!new_page) {
			rv = -E2BIG;
			goto out_unmap;
		}

		if (page) {
			/* Unmap and unpin old page */
			kunmap(page);
			put_arg_page(page);
		}

		page = new_page;
		kaddr = kmap(page);
		flush_arg_page(bprm, ofs, page);

		bytes = min_t(unsigned int, count, PAGE_SIZE - ofs);
		memcpy(dst, kaddr + ofs, bytes);
		src += bytes;
		dst += bytes;
		count -= bytes;
		ofs = 0;
	}

	/* Success: return number of bytes copied */
	rv = src - bprm->p;

out_unmap:
	if (page) {
		/* Unmap and unpin page */
		kunmap(page);
		put_arg_page(page);
	}
	return rv;
}

/*
 * Returns the next available identifier.  Adapted from alloc_pidmap in
 * kernel/pid.c.
 */
static int alloc_provid(void)
{
	int i, offset, page, max_scan, id, last = provid_last;

	id = last + 1;
	if (id >= NUM_PROVIDS)
		id = 0;
	offset = id & BITS_PER_PAGE_MASK;
	page = id / BITS_PER_PAGE;
	max_scan = PROVID_MAP_PAGES - !offset;

	for (i = 0; i <= max_scan; i++) {
		if (likely(atomic_read(&provid_free[page]))) {
			do {
				if (!test_and_set_bit(offset,
							provid_page[page])) {
					atomic_dec(&provid_free[page]);
					provid_last = id;
					return id;
				}
				offset = find_next_zero_bit(provid_page[page],
						BITS_PER_PAGE, offset);
				id = page * BITS_PER_PAGE + offset;
			} while (offset < BITS_PER_PAGE && id < NUM_PROVIDS &&
					(i != max_scan || id < last ||
					 !((last+1) & BITS_PER_PAGE_MASK)));
		}
		if (page < PROVID_MAP_PAGES)
			page++;
		else
			page = 0;
		offset = 0;
		id = page * BITS_PER_PAGE;
	}
	return -1;
}

/*
 * Frees a provenance identifier.  Adapted from free_pidmap in kernel/pid.c.
 */
static void free_provid(int id) {
	int offset, page;
	offset = id & BITS_PER_PAGE_MASK;
	page = id / BITS_PER_PAGE;

	clear_bit(offset, provid_page[page]);
	atomic_inc(&provid_free[page]);
}

/******************************************************************************
 *
 * PROCESS/CRED HOOKS
 *
 ******************************************************************************/

/*
 * Initializes a new cred_provenance object
 */
static void cred_provenance_init(struct cred_provenance *cprov,
		const struct cred_provenance *old)
{
	struct provmsg_credfork buf;

	cprov->flags = CPROV_INITED;

	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_CREDFORK;
	buf.msg.cred_id = old->cpid;
	buf.forked_cred = cprov->cpid;
	write_to_relay(&buf, sizeof(buf));
}


/*
 * Prepare a new set of credentials
 */
static int provmon_cred_prepare(struct cred *new, const struct cred *old,
                             gfp_t gfp)
{
	struct cred_provenance *old_cprov = old->provenance;
	struct cred_provenance *cprov;
	int rv, id;

	if (unlikely(old_cprov->flags & CPROV_OPAQUE)) {
		kref_get(&old_cprov->refcount);
		new->provenance = old_cprov;
		return 0;
	}
	cprov = kmalloc(sizeof(*cprov), gfp);
	if (!cprov)
		return -ENOMEM;

	rv = -ENOMEM;
	id = alloc_provid();
	if (id < 0)
		goto out_free;
	cprov->cpid = id;
	kref_init(&cprov->refcount);
	cred_provenance_init(cprov, old_cprov);

	new->provenance = cprov;

	return 0;
	free_provid(id);
out_free:
	kfree(cprov);
	return rv;
}

/*
 * Allocate the provenance part of a blank set of credentials - used only with
 * cred_transfer in the context of keys
 */
static int provmon_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct cred_provenance *cprov;
	int id;

	cprov = kzalloc(sizeof(*cprov), gfp);
	if (!cprov)
		return -ENOMEM;

	id = alloc_provid();
	if (id < 0)
		return -ENOMEM;
	cprov->cpid = id;
	kref_init(&cprov->refcount);
	// i.e. not inited 
	cprov->flags = 0;

	cred->provenance = cprov;

	return 0;

}

/*
 * Destroys a cred_provenance object (called once its refcount falls to zero)
 */
static void cred_provenance_destroy(struct kref *ref)
{
	struct cred_provenance *cprov = container_of(ref, struct cred_provenance,
			refcount);
	int id = cprov->cpid;
	int inited = cprov->flags & CPROV_INITED;
	struct provmsg_credfree buf;

	kfree(cprov);
	free_provid(id);

	if (!inited)
		return;
	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_CREDFREE;
	buf.msg.cred_id = id;
	write_to_relay(&buf, sizeof(buf));
}

/*
 * Free the provenance part of a set of credentials
 */
static void provmon_cred_free(struct cred *cred)
{
	struct cred_provenance *cprov = cred->provenance;

	cred->provenance = NULL;
	kref_put(&cprov->refcount, cred_provenance_destroy);
}

/*
 * Copies an existing set of credentials into an already-allocated blank
 * set of credentials - used only with cred_alloc_blank in the context of keys
 */
static void provmon_cred_transfer(struct cred *new, const struct cred *old)
{
	struct cred_provenance *old_cprov = old->provenance;
	struct cred_provenance *cprov = new->provenance;

	if (unlikely(old_cprov->flags & CPROV_OPAQUE)) {
		free_provid(cprov->cpid);
		kfree(cprov);
		kref_get(&old_cprov->refcount);
		new->provenance = old_cprov;
	} else {
		cred_provenance_init(cprov, old_cprov);
	}

	return;
}

/*
 * Install a new set of credentials
 */
static int provmon_task_fix_setuid(struct cred *new, const struct cred *old,
		int flags)
{
	const struct cred_provenance *cprov = new->provenance;
	struct provmsg_setid buf;

	if (cprov->flags & CPROV_OPAQUE)
		return cap_task_fix_setuid(new, old, flags);
		 
	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_SETID;
	buf.msg.cred_id = cprov->cpid;
	buf.uid = new->uid;
	buf.gid = new->gid;
	buf.suid = new->suid;
	buf.sgid = new->sgid;
	buf.euid = new->euid;
	buf.egid = new->egid;
	buf.fsuid = new->fsuid;
	buf.fsgid = new->fsgid;
	write_to_relay(&buf, sizeof(buf));

	return cap_task_fix_setuid(new, old, flags);
}

/******************************************************************************
 *
 * FILESYSTEM HOOKS
 *
 ******************************************************************************/

/*
 * These four hooks, taken together, catch inode creation and deletion
 */
static int provmon_inode_alloc_provenance(struct inode *inode)
{

        struct inode_provenance *iprov;

	iprov = kzalloc(sizeof(*iprov), GFP_KERNEL);
	if (!iprov)
	        return -ENOMEM;
	iprov->version = 0;
        inode->i_provenance = iprov;

	return 0;
}

static int provmon_inode_init_provenance(struct inode *inode, struct inode *dir,char **name, void **value, size_t *len)
{
        struct inode_provenance *iprov = inode->i_provenance;

        iprov->is_new = 1;

        return -EOPNOTSUPP;
}

static void provmon_d_instantiate(struct dentry *dentry, struct inode *inode)
{

        struct inode_provenance *iprov;
	const struct cred_provenance *curprov;
	const struct sb_provenance *sbp;
	struct provmsg_inode_alloc allocmsg;
	struct provmsg_setattr attrmsg;
	struct provmsg_link *linkmsg;
	
	if (!inode)
	        return;

	iprov = inode->i_provenance;	
	if (!iprov->is_new)
                return;
	
	linkmsg = kmalloc(sizeof(*linkmsg) + dentry->d_name.len, GFP_KERNEL);
	if (!linkmsg) {
		printk(KERN_ERR "Provenance Monitor: Failed to allocate link msg\n");
                return;
	}

	//Keeps us from re-logging PROVMSG_INODE_ALLOC, PROVMSG_SETATTR, PROVMSG_LINK
	iprov->is_new = 0;

	curprov = current_provenance();
	sbp = inode->i_sb->s_provenance;

        msg_initlen(&allocmsg.msg, sizeof(allocmsg));
        allocmsg.msg.type = PROVMSG_INODE_ALLOC;
        allocmsg.msg.cred_id = curprov->cpid;
        allocmsg.inode.sb_uuid = sbp->uuid;
        allocmsg.inode.ino = inode->i_ino;

        msg_initlen(&attrmsg.msg, sizeof(attrmsg));
	attrmsg.msg.type = PROVMSG_SETATTR;
        attrmsg.msg.cred_id = curprov->cpid;
        attrmsg.inode = allocmsg.inode;
        attrmsg.uid = inode->i_uid;
	attrmsg.gid = inode->i_gid;
        attrmsg.mode = inode->i_mode;

        msg_initlen(&linkmsg->msg, sizeof(*linkmsg) + dentry->d_name.len);
        linkmsg->msg.type = PROVMSG_LINK;
	linkmsg->msg.cred_id = curprov->cpid;
	linkmsg->inode = allocmsg.inode;
	linkmsg->dir = dentry->d_parent->d_inode->i_ino;
	memcpy(linkmsg->fname, dentry->d_name.name,  dentry->d_name.len);

	/* Allocate together and write as a unit */
        write_to_relay(&allocmsg, sizeof(allocmsg));
	write_to_relay(&attrmsg, sizeof(attrmsg));
        write_to_relay(linkmsg, sizeof(*linkmsg) + dentry->d_name.len);
        kfree(linkmsg);

	return;
}




//Deleting an inode (when nlink hits 0)
static void provmon_inode_free_provenance(struct inode *inode)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp = inode->i_sb->s_provenance;
	struct provmsg_inode_dealloc msg;

	kfree(inode->i_provenance);
	if (inode->i_nlink != 0)
		return;
		
	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_INODE_DEALLOC;
	msg.msg.cred_id = curprov->cpid;
	msg.inode.sb_uuid = sbp->uuid;
	msg.inode.ino = inode->i_ino;

	write_to_relay(&msg, sizeof(msg));
}

/*
 * Accessing an inode - called at file open and useful for directory reads which
 * pass provenance from the metadata stored in the directory inode itself.
 */
static int provmon_inode_permission(struct inode *inode, int mask)
{  
        const struct cred_provenance *curprov;
	struct sb_provenance *sbp;
	struct inode_provenance *iprov;
	struct provmsg_inode_p *msg;

	curprov = current_provenance();

	/* Only proceed if the task is not tagged as provenance opaque */
	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	/* Prevent processes other than the handler from messing with the log */
	if (relay_dentry && inode == relay_dentry->d_inode) {
		return -EPERM;
	}

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	/* Allocate an inode_provenance struct if one is not already there
	   in order to track version information (see file_permission) */
	if(!inode->i_provenance) {
	  provmon_inode_alloc_provenance(inode);
	  /* This is not a newly allocated inode */
	  ((struct inode_provenance *)inode->i_provenance)->is_new = 0;
	}

	msg_initlen(&msg->msg, sizeof(*msg));
	msg->msg.type = PROVMSG_INODE_P;
	msg->msg.cred_id = curprov->cpid;

	if (inode) {
		sbp = inode->i_sb->s_provenance;
		iprov = inode->i_provenance;
		msg->inode.sb_uuid = sbp->uuid;
		msg->inode.ino = inode->i_ino;
		msg->inode_version = iprov->version;
	} else {
		msg->inode.sb_uuid = NULL_UUID_BE;
		msg->inode.ino = 0;
		msg->inode_version = 0;
	}

	msg->mask = mask;
	write_to_relay(msg, sizeof(*msg));

	kfree(msg);
	return 0;
}

/*
 * Adding a new filename for an inode
 */
static int provmon_inode_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp;
	struct provmsg_link *msg;
	int len = new_dentry->d_name.len;

	msg = kmalloc(sizeof(*msg) + len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg_initlen(&msg->msg, sizeof(*msg) + len);
	msg->msg.type = PROVMSG_LINK;
	msg->msg.cred_id = curprov->cpid;

	sbp = old_dentry->d_sb->s_provenance;
	msg->inode.sb_uuid = sbp->uuid;
	msg->inode.ino = old_dentry->d_inode->i_ino;
	msg->dir = dir->i_ino;
	memcpy(msg->fname, new_dentry->d_name.name, len); 

	write_to_relay(msg, sizeof(*msg) + len);
	kfree(msg);
	return 0;
}

/*
 * Removing a filename for an inode
 */
static int provmon_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp;
	struct provmsg_unlink *msg;
	int len = dentry->d_name.len;

	msg = kmalloc(sizeof(*msg) + len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg_initlen(&msg->msg, sizeof(*msg) + len);
	msg->msg.type = PROVMSG_UNLINK;
	msg->msg.cred_id = curprov->cpid;

	sbp = dir->i_sb->s_provenance;
	msg->dir.sb_uuid = sbp->uuid;
	msg->dir.ino = dir->i_ino;
	memcpy(msg->fname, dentry->d_name.name, len);

	write_to_relay(msg, sizeof(*msg) + len);
	kfree(msg);
	return 0;
}

/*
 * Changing a filename for an inode
 */
static int provmon_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp = old_dentry->d_sb->s_provenance;
	struct provmsg_link *linkmsg;
	struct provmsg_unlink *unlinkmsg;
	int oldlen = old_dentry->d_name.len;
	int newlen = new_dentry->d_name.len;

	linkmsg = kmalloc(sizeof(*linkmsg) + newlen, GFP_KERNEL);
	if (!linkmsg)
		return -ENOMEM;
	unlinkmsg = kmalloc(sizeof(*unlinkmsg) + oldlen, GFP_KERNEL);
	if (!unlinkmsg) {
		kfree(linkmsg);
		return -ENOMEM;
	}

	msg_initlen(&linkmsg->msg, sizeof(*linkmsg) + newlen);
	linkmsg->msg.type = PROVMSG_LINK;
	linkmsg->msg.cred_id = curprov->cpid;
	linkmsg->inode.sb_uuid = sbp->uuid;
	linkmsg->inode.ino = old_dentry->d_inode->i_ino;
	linkmsg->dir = new_dir->i_ino;
	memcpy(linkmsg->fname, new_dentry->d_name.name, newlen);

	msg_initlen(&unlinkmsg->msg, sizeof(*unlinkmsg) + oldlen);
	unlinkmsg->msg.type = PROVMSG_UNLINK;
	unlinkmsg->msg.cred_id = curprov->cpid;
	unlinkmsg->dir.sb_uuid = sbp->uuid;
	unlinkmsg->dir.ino = old_dir->i_ino;
	memcpy(unlinkmsg->fname, old_dentry->d_name.name, oldlen);

	/* Allocate together and write as a unit */
	write_to_relay(linkmsg, sizeof(*linkmsg) + newlen);
	write_to_relay(unlinkmsg, sizeof(*unlinkmsg) + oldlen);
	kfree(unlinkmsg);
	kfree(linkmsg);
	return 0;
}

/*
 * Changing inode attributes - specifically, we're tracking owner, group, and
 * mode.
 */
int provmon_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp = dentry->d_sb->s_provenance;
	const struct inode *i = dentry->d_inode;
	struct provmsg_setattr msg;

	if ((attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)) == 0)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SETATTR;
	msg.msg.cred_id = curprov->cpid;
	msg.inode.sb_uuid = sbp->uuid;
	msg.inode.ino = i->i_ino;
	msg.uid = (attr->ia_valid & ATTR_UID) ? attr->ia_uid : i->i_uid;
	msg.gid = (attr->ia_valid & ATTR_GID) ? attr->ia_gid : i->i_gid;
	msg.mode = (attr->ia_valid & ATTR_MODE) ? attr->ia_mode : i->i_mode;

	write_to_relay(&msg, sizeof(msg));

	return 0;
}

/*
 * Reading a symbolic link
 */
static int provmon_inode_readlink(struct dentry *dentry)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp = dentry->d_sb->s_provenance;
	struct provmsg_readlink msg;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_READLINK;
	msg.msg.cred_id = curprov->cpid;
	msg.inode.sb_uuid = sbp->uuid;
	msg.inode.ino = dentry->d_inode->i_ino;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Reading or writing an open file.  The only calls to this function have @mask
 * set to either MAY_READ or MAY_WRITE, nothing else, and never both.
 */
static int provmon_file_permission(struct file *file, int mask)
{
        const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp;
	struct provmsg_file_p msg;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_FILE_P;
	msg.msg.cred_id = curprov->cpid;

	if (file && file->f_dentry && file->f_dentry->d_inode) {		
	  /* Bates: we wish to start tracking inode versions.
	     In order to do so, we need to check the version no in
	     the prov struct in each inode. If it is not already
	     there (which will happen if an inode was created
	     before the prov-bang), allocate: */
	  if(!file->f_dentry->d_inode->i_provenance) {
	    provmon_inode_alloc_provenance(file->f_dentry->d_inode);
	    /* This is not a newly allocated inode */
	    ((struct inode_provenance *)file->f_dentry->d_inode->i_provenance)->is_new = 0;
	  }
	  
	  /* If this is a write, increment version number by one */
	  // Bates: Should this go before or after the msg is created?
	  // For now I am going to say before, meaning either
	  // "I READ this version", or 
	  // "My write PRODUCED this version"
	  if(mask & MAY_WRITE)
	    ((struct inode_provenance *)file->f_dentry->d_inode->i_provenance)->version++;

	  sbp = file->f_dentry->d_sb->s_provenance;
	  msg.inode.sb_uuid = sbp->uuid;
	  msg.inode.ino = file->f_dentry->d_inode->i_ino;
	  msg.inode_version = ((struct inode_provenance *)file->f_dentry->d_inode->i_provenance)->version;
	  
	} 
	else {
		msg.inode.sb_uuid = NULL_UUID_BE;
		msg.inode.ino = 0;
		msg.inode_version = 0;
	}

	msg.mask = mask;
	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Mapping an open file into a process's address space.  XXX I'm not sure what
 * it means to have a negative dentry on this file.  We must assume that a
 * file's full permissions are used by the resulting memory accesses, e.g. a
 * file mapped read-write is both read and written by the process at all times.
 * TODO: What does this "at all times" imply?  Ouch!
 */
static int provmon_file_mmap(struct file *file, unsigned long reqprot,
                          unsigned long prot, unsigned long flags,
                          unsigned long addr, unsigned long addr_only)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sb_provenance *sbp;
	struct provmsg_mmap msg;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_MMAP;
	msg.msg.cred_id = curprov->cpid;

	if (file && file->f_dentry && file->f_dentry->d_inode) {
	  /* Allocate an inode_provenance struct if one is not already there
	     in order to track version information (see file_permission) */
	  if(!file->f_dentry->d_inode->i_provenance) {
	    provmon_inode_alloc_provenance(file->f_dentry->d_inode);
	    /* This is not a newly allocated inode */
	    ((struct inode_provenance *)file->f_dentry->d_inode->i_provenance)->is_new = 0;
	  }

	  sbp = file->f_dentry->d_sb->s_provenance;
	  msg.inode.sb_uuid = sbp->uuid;
	  msg.inode.ino = file->f_dentry->d_inode->i_ino;
	  msg.inode_version = ((struct inode_provenance *)file->f_dentry->d_inode->i_provenance)->version;
	} else {
	  msg.inode.sb_uuid = NULL_UUID_BE;
	  msg.inode.ino = 0;
	  msg.inode_version = 0;
	}

	msg.prot = prot;
	msg.flags = flags;
	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Superblock (filesystem) allocation hooks
 */
static int provmon_sb_alloc_provenance(struct super_block *sb)
{
	struct sb_provenance *sbp;

	sbp = kzalloc(sizeof(*sbp), GFP_KERNEL);
	if (!sbp)
		return -ENOMEM;

	sb->s_provenance = sbp;
	                                                          
	return 0;
}

static void provmon_sb_free_provenance(struct super_block *sb)
{
	struct sb_provenance *sbp = sb->s_provenance;

	sb->s_provenance = NULL;
	kfree(sbp);
}

/*
 * Load the UUID from this filesystem's root inode if there is one, and create a
 * new temporary one if it doesn't support xattrs (e.g. temporary filesystems).
 */
/* Precondition asserted by BUG_ON: sb != NULL */
/* Precondition asserted by get_sb: sb->s_root != NULL */
static int provmon_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	struct sb_provenance *sbp;
	struct dentry *d_root;
	struct inode *i_root;
	int rv = 0;
	int i;

	/* Paranoia sets in... */
	sbp = sb->s_provenance;
	d_root = dget(sb->s_root);
	i_root = d_root->d_inode;

	if (!i_root->i_op->getxattr ||
	    !strcmp("tmpfs", sb->s_type->name) ||
	    !strcmp("devtmpfs", sb->s_type->name)) {
		/* 
		 * XXX Treats filesystems with no xattr support as new every 
		 * time - provenance continuity is lost here! 
		 */ 
		generate_random_uuid(sbp->uuid.b); 
		printk(KERN_WARNING "Provenance Monitor: no xattr/tmpfs for %s. Provenance continuity will be lost.\n", sb->s_type->name); 
		printk(KERN_WARNING "Provenance Monitor: Assigning temporary UUID label "); 
		for (i = 0; i < 16; i++) { 
			if (i == 4 || i == 6 || i == 8) 
				printk(KERN_WARNING  "-"); 
			printk(KERN_WARNING  "%02x", sbp->uuid.b[i]); 
		}
		printk(KERN_WARNING  " to %s.\n", sb->s_type->name); 
		goto out;
	} 

	/* mutex_lock(&i_root->i_mutex); */
	rv = i_root->i_op->getxattr(d_root, XATTR_NAME_PROVENANCE, &sbp->uuid, 16);
	mutex_unlock(&i_root->i_mutex);

	if (rv == 16) {
		rv = 0;
	} else if (rv >= 0 || rv == -ENODATA) {
		/* Only mount filesystems that are correctly labeled */
	        printk(KERN_ERR "Provenance Monitor: Missing or malformed UUID label on %s.\n",sb->s_type->name);
		printk(KERN_WARNING "Provenance Monitor: the UUID label is ");
		for (i = 0; i < 16; i++) {
		  if (i == 4 || i == 6 || i == 8)
		    printk(KERN_WARNING "-");
		  printk(KERN_WARNING "%02x", sbp->uuid.b[i]);
		}
		printk(KERN_ERR "\nIf this is your root filesystem, kernel may "
				"panic or drop to initrd.\n");
		//rv = -EPERM;
		rv = 0;
	} else {
		printk(KERN_ERR "Provenance Monitor: getxattr dev=%s type=%s "
				"err=%d\n", sb->s_id, sb->s_type->name, -rv);
		/* rv from getxattr falls through */
	}
out:
	dput(d_root);
	return rv;
}



/******************************************************************************
 *
 * BPRM hooks
 *
 ******************************************************************************/
/*
 * Run when a process is being transformed by execve.  Has the argv and envp at
 * its disposal, and may be called more than once if there in an interpreter
 * involved.
 */
static int provmon_bprm_check_provenance(struct linux_binprm *bprm)
{
  
        int rv;

	const struct cred_provenance *curprov = current_provenance();
	struct cred_provenance *newprov = bprm->cred->provenance;
	const struct sb_provenance *sbp;
	struct provmsg_exec *msg;
	char xattr[7];
	unsigned long len;
	
	// Don't worry about the internal forkings etc. of opaque programs 
	if (curprov->flags & CPROV_OPAQUE){
	  return 0;
	}

	// Examination of exec.c:open_exec() shows that nothing in this
	// expression can be NULL 
	if (bprm->file->f_dentry->d_inode->i_op->getxattr) {
		rv = bprm->file->f_dentry->d_inode->i_op->getxattr(
				bprm->file->f_dentry,
				XATTR_NAME_PROVENANCE, xattr, 7);
		if (rv >= 0 && !strncmp(xattr, "opaque", 6))
			newprov->flags |= CPROV_OPAQUE;
	}

	/* Allocate an inode_provenance struct if one is not already there
	   in order to track version information (see file_permission) */
	if(!bprm->file->f_dentry->d_inode->i_provenance) {
	  provmon_inode_alloc_provenance(bprm->file->f_dentry->d_inode);
	  /* This is not a newly allocated inode */
	  ((struct inode_provenance *)bprm->file->f_dentry->d_inode->i_provenance)->is_new = 0;
	}

	len = bprm->exec - bprm->p;
	msg = kmalloc(sizeof(*msg) + len, GFP_KERNEL);
	if (!msg) {
		printk(KERN_ERR "Provenance Monitor: Failed to allocate exec message\n");
		return -ENOMEM;
	}

	rv = copy_bytes_bprm(bprm, msg->argv_envp, len);
	if (rv < 0) {
		printk(KERN_ERR "Provenance Monitor: Exec copy failed %d\n", rv);
		goto out;
	}
	msg_initlen(&msg->msg, sizeof(*msg) + len);
	msg->msg.type = PROVMSG_EXEC;
	msg->msg.cred_id = newprov->cpid;
	msg->argc = bprm->argc;

	sbp = bprm->file->f_dentry->d_sb->s_provenance;
	msg->inode.sb_uuid = sbp->uuid;
	msg->inode.ino = bprm->file->f_dentry->d_inode->i_ino;
	msg->inode_version = ((struct inode_provenance *)bprm->file->f_dentry->d_inode->i_provenance)->version;
	write_to_relay(msg, sizeof(*msg) + len);

	rv = 0;

out:
	kfree(msg);
	return rv;
}

/*
 * Committing (and possibly changing) credentials at process execution
 */
static void provmon_bprm_committing_creds(struct linux_binprm *bprm)
{
	const struct cred_provenance *cprov = bprm->cred->provenance;
	struct provmsg_setid buf;

	if (cprov->flags & CPROV_OPAQUE){
		return;
	}

	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_SETID;
	buf.msg.cred_id = cprov->cpid;
	buf.uid = bprm->cred->uid;
	buf.gid = bprm->cred->gid;
	buf.suid = bprm->cred->suid;
	buf.sgid = bprm->cred->sgid;
	buf.euid = bprm->cred->euid;
	buf.egid = bprm->cred->egid;
	buf.fsuid = bprm->cred->fsuid;
	buf.fsgid = bprm->cred->fsgid;
	write_to_relay(&buf, sizeof(buf));
}

/******************************************************************************
 *
 * XSI IPC hooks
 *
 ******************************************************************************/

/*
 * XSI IPC
 */
static int provmon_shm_alloc_provenance(struct shmid_kernel *shp)
{
	struct shm_provenance *shmprov;

	shmprov = kzalloc(sizeof(*shmprov), GFP_KERNEL);
	if (!shmprov)
		return -ENOMEM;
	shmprov->shmid = alloc_provid();
	shp->shm_perm.provenance = shmprov;
	return 0;
}

static void provmon_shm_free_provenance(struct shmid_kernel *shp)
{
	struct shm_provenance *shmprov = shp->shm_perm.provenance;
	int id = shmprov->shmid;

	shp->shm_perm.provenance = NULL;
	kfree(shmprov);
	free_provid(id);
}

static int provmon_msg_msg_alloc_provenance(struct msg_msg *msg) {
	struct msg_provenance *msgprov;

	msgprov = kzalloc(sizeof(*msgprov), GFP_KERNEL);
	if (!msgprov)
		return -ENOMEM;
	msgprov->msgid = alloc_provid();
	msg->provenance = msgprov;
	return 0;
}

static void provmon_msg_msg_free_provenance(struct msg_msg *msg) {
	struct msg_provenance *msgprov = msg->provenance;
	int id = msgprov->msgid;

	msg->provenance = NULL;
	kfree(msgprov);
	free_provid(id);
}

/*
 * Attaching to XSI shared memory
 */
static int provmon_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,
		int shmflg)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct shm_provenance *shmprov = shp->shm_perm.provenance;
	struct provmsg_shmat msg;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SHMAT;
	msg.msg.cred_id = curprov->cpid;
	msg.shmid = shmprov->shmid;
	msg.flags = shmflg;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}


/*
 * Sending a message to an XSI message queue
 */
static int provmon_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
		int msqflg) {
	const struct cred_provenance *curprov = current_provenance();
	const struct msg_provenance *msgprov = msg->provenance;
	struct provmsg_mqsend logmsg;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	msg_initlen(&logmsg.msg, sizeof(logmsg));
	logmsg.msg.type = PROVMSG_MQSEND;
	logmsg.msg.cred_id = curprov->cpid;
	logmsg.msgid = msgprov->msgid;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}

/*
 * Receiving a message from an XSI message queue
 */
static int provmon_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
		struct task_struct *target, long type, int mode) {
	const struct cred_provenance *curprov = target->cred->provenance;
	const struct msg_provenance *msgprov = msg->provenance;
	struct provmsg_mqrecv logmsg;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;

	msg_initlen(&logmsg.msg, sizeof(logmsg));
	logmsg.msg.type = PROVMSG_MQRECV;
	logmsg.msg.cred_id = curprov->cpid;
	logmsg.msgid = msgprov->msgid;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}


/******************************************************************************
 *
 * PROTOCOL-SPECIFIC SOCKET HANDLERS
 *
 ******************************************************************************/

// Returns the next socket ID for this system.
static void next_sockid(struct sockid *label)
{

	u64 counter = atomic64_inc_return(&sock_counter);
	label->high = counter >> 32;
	label->low = counter & ((1LL << 32) - 1);

}


static int provmon_sk_alloc_provenance(struct sock *sk, int family, gfp_t priority)
{
	struct sock_provenance *prov;

	prov = kzalloc(sizeof(*prov), priority);
	if (!prov)
		return -ENOMEM;

	// For UNIX sockets, this will become the local ID.  For TCP sockets, it
	// will be the remote ID.  For UDP sockets, it will be unused.
	next_sockid(&prov->short_id);
	prov->short_set = 1;
	prov->full_set = 0;

	sk->sk_provenance = prov;

	return 0;
}

static void provmon_sk_free_provenance(struct sock *sk)
{
	struct sock_provenance *prov = sk->sk_provenance;
	sk->sk_provenance = NULL;
	kfree(prov);
}

// Socket buffer allocation hooks
static int provmon_skb_shinfo_alloc_provenance(struct sk_buff *skb, int recycling,
		gfp_t gfp)
{
  
	struct skb_provenance *prov;

	if (recycling)
		return 0;


	prov = kmalloc(sizeof(*prov), gfp);
	if (!prov)
		return -ENOMEM;

	prov->set = 0;
	skb_shinfo(skb)->provenance = prov;

	return 0;
}

static void provmon_skb_shinfo_free_provenance(struct sk_buff *skb, int recycling)
{
        struct skb_provenance *prov;

        prov = skb_shinfo(skb)->provenance;

	BUG_ON(!prov);

	if (recycling) 
		prov->set = 0;
		return;

	kfree(prov);
	skb_shinfo(skb)->provenance = NULL;
}

static int provmon_skb_shinfo_copy(struct sk_buff *skb,
		struct skb_shared_info *shinfo, gfp_t gfp)
{
        struct skb_provenance *oldprov;
	struct skb_provenance *prov;

        oldprov = skb_shinfo(skb)->provenance;

	prov = kmalloc(sizeof(*prov), gfp);
	if (!prov)
		return -ENOMEM;

	*prov = *oldprov;
	shinfo->provenance = prov;
	return 0;
}

// Socket allocation hooks
static void provenance_opt_kfree_rcu(struct rcu_head *head)
{
	kfree(container_of(head, struct ip_options_rcu, rcu));
}


static int provmon_socket_post_create(struct socket *sock, int family, int type,
		int protocol, int kern)
{

  struct inet_sock *inet;
  struct ip_options *old, *opt=NULL;
  int rv;

  if (family != AF_INET)
    return 0;

  rv = provenance_init_ip_options(opt);
  if(rv < 0) {
    printk(KERN_WARNING "Provenance Monitor: Failed to allocate in %s\n",__func__);
    return rv;
  }

  /* Opt may be null for legitimate reasons */
  if(opt) {
    inet = inet_sk(sock->sk);
    old = rcu_dereference(inet->opt);
    rcu_assign_pointer(inet->opt, opt);
    
    if (old) {
      printk(KERN_WARNING "Provenance Monitor: Blowing away some IP Options in %s\n",__func__);
      //printk(KERN_WARNING "Provenance Monitor: inet_opt was already set in %s\n",__func__);
      call_rcu(&get_ip_options_rcu(old)->rcu, provenance_opt_kfree_rcu);
    }
    
    /*
      if (old) {
      printk(KERN_WARNING "Provenance Monitor: inet_opt was already set??\n");
      kfree_ip_options(opt);
      }
    */
  }

  return 0;

}

// Create the temporary request_sock from which the eventual accepted socket
// will be cloned.  We have the only reference to @req at this point, so we can
// play fast and loose with RCU.
static int provmon_inet_conn_request(struct sock *sk, struct sk_buff *skb,
		struct request_sock *req)
{

  struct ip_options *old,*opt=NULL;
  struct inet_request_sock *irsk;
  int rv;

  if (sk->sk_family != AF_INET)
    return 0;

  rv = provenance_init_ip_options(opt);
  if(rv < 0){
    printk(KERN_WARNING "Provenance Monitor: Failed to allocate in %s\n",__func__);
    return rv;
  }

  /* Opt may be null for legitimate reasons */
  if(opt) {
    irsk = inet_rsk(req);
    old = rcu_dereference(irsk->opt);
    rcu_assign_pointer(irsk->opt, opt);
    
    if (old){
      printk(KERN_WARNING "Provenance Monitor: Blowing away some IP Options in %s\n",__func__);
      call_rcu(&get_ip_options_rcu(old)->rcu, provenance_opt_kfree_rcu);
      /* kfree_ip_options(irsk->opt); */
    }

    //irsk->opt = opt;
  }

  return 0;
}

// Completing a connection at the client side of a TCP socket
static void provmon_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	struct sock_provenance *prov = sk->sk_provenance;

	// Discard the ID we got from the listening socket
	if(prov)
	  prov->full_set = 0;
}

// Sending on a UNIX domain socket
static int send_unix_msg(struct sock *peersk)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sock_provenance *pprov = peersk->sk_provenance;
	struct provmsg_socksend msg;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKSEND;
	msg.msg.cred_id = curprov->cpid;
	msg.peer = pprov->short_id;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}


// Receiving on a UNIX domain socket (any kind)
static void recv_unix_msg(struct sock *sk)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sock_provenance *skp = sk->sk_provenance;
	struct provmsg_sockrecv * msg = NULL;
	struct sockaddr_un addr;

	msg = kzalloc(sizeof(*msg) + sizeof(addr), GFP_KERNEL);
	if (!msg) {
	  printk(KERN_ERR "Provenance Monitor: Failed to allocate sockrecv msg for unix\n");
	  return;
	}

	//err = kernel_getpeername(sk->sk_socket, (struct sockaddr *)&addr, &slen);

	msg->msg.type = PROVMSG_SOCKRECV;
	msg->msg.cred_id = curprov->cpid;
	msg->sock.host = boot_uuid;
	msg->sock.sock = skp->short_id;	
	msg->family = sk->sk_family;
	msg->protocol = sk->sk_protocol;

	/* Most of the time kernel_getpeername isn't returning a name for the socket */
	/* When this is the case, we should just skip embeddeding sockaddr_un */
	//if(err < 0 || addr.sun_path[0] == 0){
	msg_initlen(&(msg->msg),sizeof(*msg) + sizeof(addr));
	write_to_relay(msg,sizeof(*msg) + sizeof(addr));
	  /*
	}
	else{
	  msg_initlen(&(msg->msg),sizeof(*msg) + sizeof(struct sockaddr_un));
	  msg->addr_len = slen;
	  memcpy(msg->addr,&addr,sizeof(struct sockaddr_un));
	  write_to_relay(msg,sizeof(*msg) + sizeof(struct sockaddr_un));
	}
	  */
	kfree(msg);
}


// Sending on a TCP socket
static int send_tcp_msg(struct socket *sock)
{
  /*
	const struct cred_provenance *curprov = current_provenance();
	const struct sock_provenance *skp = sock->sk->sk_provenance;
	struct provmsg_socksend msg;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKSEND;
	msg.msg.cred_id = curprov->cpid;
	msg.peer = skp->short_id;
	
	write_to_relay(&msg, sizeof(msg));
	*/

	const struct cred_provenance *curprov = current_provenance();
	const struct sock_provenance *skp = sock->sk->sk_provenance;
	struct provmsg_socksend * msg;
	struct sockaddr_storage addr;
	
	msg = kzalloc(sizeof(*msg) + sizeof(addr), GFP_KERNEL);
	if (!msg) {
	  printk(KERN_ERR "Provenance Monitor: Failed to allocate socksend msg for tcp\n");
	  return -ENOMEM;
	}

	/*
	err = kernel_getpeername(sock, (struct sockaddr *)&addr, &slen);
	if (err < 0){
	  printk(KERN_ERR "Provenance Monitor: Failed to recover peer address in recv_tcp_msg\n");
	}	
	else
	  printk(KERN_ERR "BATES: (SEND_TCP_MSG) Got peer name.\n\tLength=%d sizeof(sockaddr_storage)=%d sizeof(sockaddr_in)=%d\n\tFamily=%s\n\tDSTIP=%pI4\n\tPort=%d\n\n",
		 slen,sizeof(struct sockaddr_storage),sizeof(struct sockaddr_in),
		 (addr.ss_family == AF_INET) ? "AF_INET" : "AF_INET6",
		 &((struct sockaddr_in *)&addr)->sin_addr,
		 ((struct sockaddr_in *)&addr)->sin_port);
	*/

	msg->msg.type = PROVMSG_SOCKSEND;
	msg->msg.cred_id = curprov->cpid;
	msg->peer = skp->short_id;
	msg->family = sock->sk->sk_family;
	msg->protocol = sock->sk->sk_protocol;
	msg->addr_len = 0; /*slen;*/

	msg_initlen(&msg->msg,sizeof(*msg) + sizeof(addr));
	/* memcpy(msg->addr,&addr,sizeof(struct sockaddr_storage)); */
	write_to_relay(msg, sizeof(*msg) + sizeof(addr));

	/*
	if(err >= 0 && slen > 0 && addr.ss_family == AF_INET){
	  msg_initlen(&msg->msg,sizeof(*msg) + sizeof(struct sockaddr_in));
	  memcpy(msg->addr,&addr,sizeof(struct sockaddr_in));
	  write_to_relay(msg, sizeof(*msg) + sizeof(struct sockaddr_in));
	}
	else if(err >= 0 && slen > 0 && addr.ss_family == AF_INET6){	  
	  msg_initlen(&msg->msg,sizeof(*msg) + sizeof(struct sockaddr_in6));
	  memcpy(msg->addr,&addr,sizeof(struct sockaddr_in6));
	  write_to_relay(msg, sizeof(*msg) + sizeof(struct sockaddr_in6));
	}
	*/
	kfree(msg);


	return 0;
}


// Receiving on a TCP socket
static void recv_tcp_msg(struct socket *sock)
{
	const struct cred_provenance *curprov = current_provenance();
	const struct sock_provenance *skp = sock->sk->sk_provenance;
	struct provmsg_sockrecv * msg;
	struct sockaddr_storage addr;
	
	/* Hi-Fi dropped packets if they did not have provenance identifiers
	   (i.e., they were sent from a provenance-unaware host).	   
	   Personally, I'd still rather know that the packet was received! */	   
	if (!skp->full_set){
	  /* return; */
	}

	msg = kmalloc(sizeof(*msg) + sizeof(addr), GFP_KERNEL);
	if (!msg) {
	  printk(KERN_ERR "Provenance Monitor: Failed to allocate sockrecv msg for tcp\n");
	  return;
	}

	/*
	err = kernel_getpeername(sock, (struct sockaddr *)&addr, &slen);
	if (err < 0)
	  printk(KERN_ERR "Provenance Monitor: Failed to recover peer address in recv_tcp_msg\n");
	*/

	msg->msg.type = PROVMSG_SOCKRECV;
	msg->msg.cred_id = curprov->cpid;
	msg->sock = skp->full_id;
	msg->family = sock->sk->sk_family;
	msg->protocol = sock->sk->sk_protocol;
	msg->addr_len = 0; /* slen; */


	msg_initlen(&msg->msg,sizeof(*msg) + sizeof(addr));
	/* memcpy(msg->addr,&addr,sizeof(struct sockaddr_in));*/
	write_to_relay(msg, sizeof(*msg) + sizeof(addr));

	/*
	if(slen > 0 && addr.ss_family == AF_INET){
	  msg_initlen(&msg->msg,sizeof(*msg) + sizeof(struct sockaddr_in));
	  memcpy(msg->addr,&addr,sizeof(struct sockaddr_in));
	  write_to_relay(msg, sizeof(*msg) + sizeof(struct sockaddr_in));
	}
	else if(slen > 0 && addr.ss_family == AF_INET6){	  
	  msg_initlen(&msg->msg,sizeof(*msg) + sizeof(struct sockaddr_in6));
	  memcpy(msg->addr,&addr,sizeof(struct sockaddr_in6));
	  write_to_relay(msg, sizeof(*msg) + sizeof(struct sockaddr_in6));
	}
	*/

	kfree(msg);

}


// Sending on a UDP socket
static int send_udp_msg(struct sk_buff *skb)
{
	const struct cred_provenance *curprov = current_provenance();
	struct skb_provenance *skp = skb_shinfo(skb)->provenance;
	struct provmsg_socksend msg;

	if (!skp->set) {
	  next_sockid(&skp->id.sock);
	  skp->set = 1;
	}
	
	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKSEND;
	msg.msg.cred_id = curprov->cpid;
	msg.peer = skp->id.sock;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

// Receiving on a UDP socket
static int recv_udp_msg(struct sk_buff *skb)
{
	const struct cred_provenance *curprov = current_provenance();
	struct skb_provenance *skp = skb_shinfo(skb)->provenance;
	struct provmsg_sockrecv msg;

	if (!skp->set)
		return 0;
	
	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKRECV;
	msg.msg.cred_id = curprov->cpid;
	msg.sock = skp->id;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}



/******************************************************************************
 *
 * SOCKET HOOKS
 *
 ******************************************************************************/

// Sending on a socket
static int provmon_socket_sendmsg(struct socket *sock, struct msghdr *msg,
		int size)
{
	const struct cred_provenance *curprov = current_provenance();
	struct cmsghdr *cmsg;
	struct sock *peer;

	if (curprov->flags & CPROV_OPAQUE)
		return 0;


	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
		if (cmsg->cmsg_level == SOL_IP &&
				cmsg->cmsg_type == IP_RETOPTS) {
			return -EPERM;
		}

	switch (sock->sk->sk_family) {
	case AF_UNIX:
	        // Non-stream sockets are better handled by unix_may_send
	        if (sock->sk->sk_type != SOCK_STREAM)
		        break;
		peer = unix_sk(sock->sk)->peer;
		if (!peer)
			break;

		return send_unix_msg(peer);
	case AF_INET:
	        // XXX just TCP for now, UDP handled by append_data 
	        if (sock->sk->sk_protocol != IPPROTO_TCP){
			break;
	        }
		return send_tcp_msg(sock);
	}
	return 0;
}

// Appending data to an outgoing datagram
static int provmon_socket_dgram_append(struct sock *sk, struct sk_buff *head)
{
	const struct cred_provenance *curprov = current_provenance();

	if (curprov->flags & CPROV_OPAQUE)
		return 0;
	
	// XXX Just UDP, def. not stream sockets 
	if (sk->sk_family != AF_INET 
	    || (sk->sk_protocol != IPPROTO_UDP
		&& sk->sk_protocol != IPPROTO_ICMP))
		return 0;

	return send_udp_msg(head);
}


// Receiving on a socket
static void provmon_socket_post_recvmsg(struct socket *sock, struct msghdr *msg,
		int size, int flags)
{
	const struct cred_provenance *curprov = current_provenance();

	if (curprov->flags & CPROV_OPAQUE)
	  return;

	// XXX more later?
	switch (sock->sk->sk_family) {
	case AF_UNIX:
		recv_unix_msg(sock->sk);
		break;
	case AF_INET:
	        if (sock->sk->sk_protocol != IPPROTO_TCP)
			return;

		recv_tcp_msg(sock);
		break;
	}
}


// Receiving a UDP datagram
static void provmon_socket_dgram_post_recv(struct sock *sk, struct sk_buff *skb)
{
	const struct cred_provenance *curprov = current_provenance();

	if (curprov->flags & CPROV_OPAQUE)
		return;

	// XXX Just UDP for now; other protos might need hook placements
	if (sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_UDP)
	  return;

	recv_udp_msg(skb);
}


// Delivering a packet to a socket
static int provmon_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sock_provenance *skp = sk->sk_provenance;
	struct skb_provenance *sbp = skb_shinfo(skb)->provenance;

	// These cases s hould only happen if the allocation hooks 
	// are disabled added for debug purposes
	if(!skp || !sbp)
	  return 0;

	// XXX Only TCP 
	if (sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return 0;

	if (skp->full_set || !sbp->set){
		return 0;
	}

	skp->full_id = sbp->id;
	skp->full_set = 1;
	return 0;
}


// Sending datagrams on a UNIX domain socket (closer hook than sendmsg)
static int provmon_unix_may_send(struct socket *sock, struct socket *other)
{
	const struct cred_provenance *curprov = current_provenance();

	if (curprov->flags & CPROV_OPAQUE)
	  return 0;

	/* During poweroff/reboot, occasional null pointer dereferences
	   occurred here.  Disallow if null. */
	if(!sock || !other){
	  printk("Bates: Null Pointer in provmon_unix_may_send. Disallowing.\n\tsock=%p\n\tother=%p\n\n",sock,other);
	  return -EPERM;
	}
	  
	// This should only be called by DGRAM/SEQPACKET sockets
	BUG_ON(sock->sk->sk_type == SOCK_STREAM);
	return send_unix_msg(other->sk);
}

/******************************************************************************
 *
 * NETFILTER HANDLERS/HOOKS
 *
 ******************************************************************************/


// TCP/UDP packet arrival
static int tcp_udp_in(struct sk_buff *skb)
{
        int rv;
	
	struct skb_provenance *prov = skb_shinfo(skb)->provenance;

	rv = provenance_detach_packet_label(skb); 

	if(rv == 0)
	  prov->set = 1;

	return 0;
}


// TCP packet transmission
static int tcp_out(struct sk_buff *skb)
{
	struct sock_provenance *prov = skb->sk->sk_provenance;
	int rv;

	if (!prov->short_set) {
	  struct iphdr *iph = ip_hdr(skb);
	  printk(KERN_WARNING "Provenance Monitor: short_id not set for this proto=%d packet! (tcp_out)\n",iph->protocol);
	  return 0;
	}
	rv = provenance_label_packet(skb);//, &prov->short_id);
	
	return rv;
}

// UDP packet transmission
static int udp_out(struct sk_buff *skb)
{
	struct skb_provenance *prov = skb_shinfo(skb)->provenance;
	int rv;

	if (!prov->set)
	  return 0;

	rv = provenance_label_packet(skb);//, &prov->id.sock);

	return rv;
}



// IPv4 packet arrival - handle by protocol
static unsigned int provmon_ipv4_in(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
        struct iphdr *iph;
  
	if(!skb || !ip_hdr(skb)){
	  printk(KERN_WARNING "Bates: This is a big stupid.  dropping\n");
	  return NF_DROP;
	}

	iph = ip_hdr(skb);

	switch (iph->protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	  if (tcp_udp_in(skb)){
	    return NF_DROP;
	  }
		break;
	}
	return NF_ACCEPT;
}


// IPv4 packet transmission - handle by protocol
static unsigned int provmon_ipv4_out(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	  if (udp_out(skb))
	    return NF_DROP;
	  break;
	case IPPROTO_TCP:
	  if (tcp_out(skb))
	    return NF_DROP;
	  break;
	}

	return NF_ACCEPT;
}


// Initializes the Netfilter hooks
static int __init provmon_nf_init(void)
{
	static struct nf_hook_ops provmon_ipv4_hooks[] = {
		{
			.hook = provmon_ipv4_in,
			.pf = PF_INET,
			.hooknum = NF_INET_LOCAL_IN,
			.priority = NF_IP_PRI_FIRST,
		},
		{
			.hook = provmon_ipv4_out,
			.pf = PF_INET,
			.hooknum = NF_INET_LOCAL_OUT,
			.priority = NF_IP_PRI_LAST,
		},
	};

	if (nf_register_hooks(provmon_ipv4_hooks, ARRAY_SIZE(provmon_ipv4_hooks)))
	  panic("Provenance Monitor: failed to register netfilter hooks");
	return 0;
}
postcore_initcall(provmon_nf_init);


/******************************************************************************
 *
 * PERMISSION HOOKS
 *
 ******************************************************************************/


// Feign ignorance to prevent options from being overwritten
static int provmon_socket_setsockopt(struct socket *sock, int level, int optname)
{

  if (sock->sk->sk_family == AF_INET && level == SOL_IP &&
      optname == IP_OPTIONS) {
    printk(KERN_WARNING "Provenance Monitor: %s setting IP options via setsockopt\n",
	   current->comm);
    return -ENOPROTOOPT;
  }
  return 0;

}


// Feign ignorance to make OpenSSH work again
static int provmon_socket_getsockopt(struct socket *sock, int level, int optname)
{
  if (sock->sk->sk_family == AF_INET && level == SOL_IP &&
      optname == IP_OPTIONS){
    printk(KERN_WARNING "Provenance Monitor: Feigning IP Options ignorance (getsockopt)\n");
    return -ENOPROTOOPT;
  }
  return 0;
}

/******************************************************************************
 *
 * LPM INITIALIZATION
 *
 ******************************************************************************/

/*
 * Sets up the provid bitmap
 */
static int init_provid_map(void)
{
	int i;
	void *page;

	for (i = 0; i < PROVID_MAP_PAGES; i++) {
		page = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (unlikely(!page)) {
			while (--i >= 0)
				kfree(provid_page[i]);
			return -ENOMEM;
		}
		provid_page[i] = page;
	}
	return 0;
}

/*
 * Fills out the initial kernel credential structure
 */
static int set_init_creds(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	struct cred_provenance *cprov;
	int id;

	cprov = kzalloc(sizeof(*cprov), GFP_KERNEL);
	if (!cprov)
		return -ENOMEM;

	id = alloc_provid();
	if (id < 0)
		goto out_nomem;
	cprov->cpid = id;
	kref_init(&cprov->refcount);
	cprov->flags = CPROV_INITED;

	cred->provenance = cprov;
	return 0;

out_nomem:
	kfree(cprov);
	return -ENOMEM;
}

static struct provenance_operations provmon_provenance_ops = {
	.name    = "provmon",

	/* Provenance-generating hooks */
#define HANDLE(HOOK) .HOOK = provmon_##HOOK

	// Cred Hooks
	HANDLE(cred_prepare),
	HANDLE(cred_alloc_blank),
	HANDLE(cred_free),
	HANDLE(cred_transfer),
	HANDLE(task_fix_setuid),

	// Inode Hooks	
	HANDLE(inode_alloc_provenance),
	HANDLE(inode_init_provenance),
	HANDLE(d_instantiate),
	HANDLE(inode_free_provenance),
	HANDLE(inode_permission),
	HANDLE(inode_link),
	HANDLE(inode_unlink),
	HANDLE(inode_rename),
	HANDLE(inode_setattr),
	HANDLE(inode_readlink),

	// Superblock hooks 
	HANDLE(sb_alloc_provenance),
	HANDLE(sb_free_provenance),
	HANDLE(sb_kern_mount),

	// File Hooks
	HANDLE(file_permission),
	HANDLE(file_mmap),

	// binprm hooks 
	HANDLE(bprm_check_provenance),
	HANDLE(bprm_committing_creds),

	//IPC Hooks
	HANDLE(shm_alloc_provenance),
	HANDLE(shm_free_provenance),
	HANDLE(msg_msg_alloc_provenance),
	HANDLE(msg_msg_free_provenance),
	HANDLE(shm_shmat),
	HANDLE(msg_queue_msgsnd),
	HANDLE(msg_queue_msgrcv),


	//  These 2 init the IP options	
	HANDLE(socket_post_create),
	HANDLE(inet_conn_request), 

	HANDLE(inet_conn_established),

	// Network Allocations TCP & UNIX?
	HANDLE(sk_alloc_provenance),
	/* HANDLE(sk_clone_provenance), */
	HANDLE(sk_free_provenance),

	//Network Hooks -- Unix
	HANDLE(unix_may_send), 

	//Network Hooks -- UDP
	HANDLE(skb_shinfo_alloc_provenance),
	HANDLE(skb_shinfo_free_provenance),
	HANDLE(skb_shinfo_copy),
	HANDLE(socket_dgram_append),
	HANDLE(socket_dgram_post_recv),

	//Network Hooks -- TCP
	HANDLE(socket_sendmsg),
	HANDLE(socket_post_recvmsg),
	HANDLE(socket_sock_rcv_skb),

	//Permission hooks
	HANDLE(socket_setsockopt),
	HANDLE(socket_getsockopt),

};

static int __init provmon_init(void)
{
	int rv = 0;

	if (!provenance_module_enable(&provmon_provenance_ops)) {
		printk(KERN_ERR "Provenance Monitor: ERROR - failed to enable module\n");
		return -EINVAL;
	}
	printk(KERN_INFO "Provenance Monitor: module enabled\n");

	boot_buffer = kmalloc(boot_buf_size, GFP_KERNEL);
	rv = init_provid_map();
	if (rv)
		return rv;
	if (set_init_creds())
		panic("Provenance Monitor: Failed to allocate creds for initial task.");
	/* Generate a random boot UUID */
	generate_random_uuid(boot_uuid.b);

	/* Finally register */
	if (register_provenance(&provmon_provenance_ops))
		panic("Provenance Monitor: failed to register operations");

	printk(KERN_INFO "Provenance Monitor: registered\n");
	return 0;
}
provenance_initcall(provmon_init);


