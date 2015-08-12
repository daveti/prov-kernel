/*
 * Kernel-to-userspace protocol definitions for the Provenance Monitor provenance system
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

#ifndef _SECURITY_PROVMON_INTERPRET_H
#define _SECURITY_PROVMON_INTERPRET_H

#include "provmon_proto.h"

#define PATH_LENGTH 255

static inline int provmon_strcpyif(char * buf, int buflen, char * str, int strlen){
  int rv = 0;
  if( strlen < buflen ){
    //Copy the string over, set return value to bytes copied
    memcpy(buf,str,strlen);
    rv += strlen;
    //Add a null byte after every call to memcpy
    memcpy(buf + strlen, "\0", 1);
  }
  else
    printk(KERN_ERR "Bates: provmon_strcpyif, buffer of insufficient length. truncating. (%s)\n",buf);
  return rv;
}

static inline int copy_uuid_be(uuid_be *uuid, char*buf,int buflen)
{

  int i,pos=0;  

  if(buflen < 19){
    return -ENAMETOOLONG;
  }

  for (i = 0; i < 16; i++) {
    if (i == 4 || i == 6 || i == 8){
      memcpy(buf+pos,"-",1);
      pos += 1;
    }
    sprintf(buf+pos,"%02x", uuid->b[i]);
    pos += 2;
  }
  return pos;
}

int provmon_dentry_mountpoint(struct dentry *d, char *buf, int buflen) {
  struct dentry *root = d->d_sb->s_root;
  struct list_head *pos=NULL, *head=&current->nsproxy->mnt_ns->list;
  struct vfsmount * mnt = NULL;
  struct qstr * name = NULL;
  int len = 0, counter=0;

  list_for_each(pos,head){
        mnt = list_entry(pos, struct vfsmount, mnt_list);
        name = &mnt->mnt_mountpoint->d_name;    
        if (mnt->mnt_root == root) {
	  //If your mountpoint does not start with a '/', we will add one.
	  if((char)name->name[0] != '/')
	    len += provmon_strcpyif(buf + len, buflen - len, "/", 1);

	  len += provmon_strcpyif(buf + len, buflen - len, (char *)name->name, name->len);

	  counter += 1;	  
	}   
  }
  if(counter > 1)	    
    printk(KERN_ERR "Bates: provmon_dentry_mountpoint, TWO MOUNTPOINTS = %s\n",buf);
  else if(counter == 0)
    printk(KERN_ERR "Bates: provmon_dentry_mountpoint, NO MOUNTPOINTS for root=%s and dentry=%s\n",
	   (&root->d_name)->name,
	   (&d->d_name)->name);
  
  //If your mountpoint does not end with a '/', or we couldn't find a mntpoint, we will add a '/'
  if(counter == 0 || (name->len > 1 && (char)name->name[name->len-1] != '/'))
    len += provmon_strcpyif(buf + len, buflen - len, "/", 1);


  return len;
}

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
int provmon_dentry_path_rec(struct dentry *dentry, char *buf, int buflen){

  struct qstr * name = &dentry->d_name;
  int len = 0;

  if(!IS_ROOT(dentry)){
    len += provmon_dentry_path_rec(dentry->d_parent, buf + len, buflen - len);

    /*
    //Handles parent directory case.  If parent dir is '/' we don't wnat to add another '/'
    //If parent dir is anything else, we need to add '/'
    if(len > 0 && (char)(((buf+len)-1)[0]) != '/' )
      len += provmon_strcpyif(buf + len, buflen - len, "/", 1);
    */
  }

  //If you are just a '/', we don't want you here
  if(name->len > 1 || (char)name->name[0] != '/')
    len += provmon_strcpyif(buf + len, buflen - len, (char *)name->name, name->len);

  return len;
}

int provmon_dentry_path(struct dentry *dentry, char *buf, int buflen)
{
        int len = 0;

	spin_lock(&dcache_lock);
	len += provmon_dentry_path_rec(dentry,buf,buflen);
	spin_unlock(&dcache_lock);

	return len;
}

int provmon_inode_to_dentry(struct inode * inode, char *buf, int buflen)
{


	struct list_head *pos=NULL, *head=&inode->i_dentry;
	int counter = 0, len = 0;
	struct dentry *alias;

	if(!inode)
	  return len;

	//Get UUID of partition
	//len += copy_uuid_be(inode->i_sb->s_provenance,buf,buflen);
	//len += provmon_strcpyif(buf + len, buflen - len , ":", 1);

	list_for_each(pos,head){
	  //If there are multiple dentries, add comma.
	  if(counter >= 1)
	    len += provmon_strcpyif(buf + len, buflen - len, ",", 1);
	  
	  //Get dentry
	  alias = list_entry(pos, struct dentry, d_alias);
	  
	  //Copy in the mount point
	  len += provmon_dentry_mountpoint(alias, buf + len, buflen - len);
	  
	  //Copy in the  dentry full buf
	  len += provmon_dentry_path(alias, buf + len, buflen - len);
	  
	  counter += 1;
	}
	
	/*
	  if(counter > 1)
	    printk(KERN_ERR "Bates: provmon_inode_permission, TWO DENTRIES: %s\n",buf);
	  else
	    printk(KERN_ERR "Bates: provmon_inode_permission, filename=%s\n",buf);
	*/

	return len;

}

#endif
