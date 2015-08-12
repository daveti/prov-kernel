/*
 * Structure definitions for the Provenance Monitor provenance system
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

#ifndef _SECURITY_PROVMON_H
#define _SECURITY_PROVMON_H


#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/uuid.h>

#include "provmon_proto.h"


/* Key names for xattrs */
#define XATTR_PROVMON_SUFFIX "provenance"
#define XATTR_NAME_PROVMON XATTR_SECURITY_PREFIX XATTR_PROVMON_SUFFIX

/* IP options number */
#define IPOPT_PROVMON 0x9e


/*
 * Provenance label for struct cred.  "Opaque" processes are such that credentials
 * they fork are considered part of the original process, so we use a reference
 * counter to make sure these are freed at the appropriate time and no earlier.
 */
struct cred_provenance {
	struct kref refcount;
	u32 cpid;
	int flags;
#define CPROV_INITED (1 << 0)
#define CPROV_OPAQUE (1 << 1)
};


/*
 * Provenance label for filesystems via struct super_block.  This UUID is stored
 * in the xattr of the root inode for persistence.  If we encounter a filesystem
 * with no such label, we create one and store it ourselves.
 */
struct sb_provenance {
	uuid_be uuid;
};

/* Provenance structures for XSI IPC */
struct msg_provenance {
	u32 msgid;
};

struct shm_provenance {
	u32 shmid;
};


/* Provenance structures for sockets */
struct sock_provenance {
	struct host_sockid full_id;
	struct sockid short_id;
	u8 full_set;
	u8 short_set;
};

struct skb_provenance {
	struct host_sockid id;
	u8 set;
};


/* Label option for IP */
struct sockid_opt {
	u8 num;
	u8 len;
	struct host_sockid label;
} __attribute__((packed));


/* Provenance structure for inodes. */
struct inode_provenance {
        int is_new;
};

#endif
