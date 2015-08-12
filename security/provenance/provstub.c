/*
 * Prov Stub sample LPM module
 *
 * Author: Adam M. Bates <amb@cs.uoregon.edu> 
 * Adapted from Blabbermouth skeleton LSM by Mohammad Nauman (recluze)
 *
 * Copyright (C) 2013 MIT Lincoln Laboratory 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/provenance.h>
#include <linux/usb.h>
#include <linux/moduleparam.h>

/* for IP sockets */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/udp.h>


#ifdef CONFIG_DEFAULT_PROVENANCE_PROVSTUB

MODULE_AUTHOR("Adam M. Bates");
MODULE_DESCRIPTION("ProvStub: Minimal Instantiation of the Linux Provenance Module");
MODULE_LICENSE("GPL");

// should we print out debug messages
static int debug = 1;

module_param(debug, bool, 0600);

#define MY_NAME "Provenance Stub"

#define prov_dbg(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_INFO "%s: %s: " fmt ,	\
				MY_NAME , __func__ , 	\
				## arg);			\
	} while (0)


/******************************************************************************
 *
 * LPM HOOKS
 *
 ******************************************************************************/

// Feign ignorance to prevent options from being overwritten
static int provstub_socket_setsockopt(struct socket *sock, int level, int optname)
{

  if (sock->sk->sk_family == AF_INET && level == SOL_IP &&
      optname == IP_OPTIONS) {
    return -ENOPROTOOPT;
  }
  return 0;

}


// Feign ignorance to make OpenSSH work again
static int provstub_socket_getsockopt(struct socket *sock, int level, int optname)
{
  if (sock->sk->sk_family == AF_INET && level == SOL_IP &&
      optname == IP_OPTIONS){
    return -ENOPROTOOPT;
  }
  return 0;
}

/*
static int provstub_bprm_check_provenance (struct linux_binprm *bprm)
{
	prov_dbg("file %s, e_uid = %d, e_gid = %d\n",
		 bprm->filename, bprm->cred->euid, bprm->cred->egid);

	return 0;
}
*/


/******************************************************************************
 *
 * LPM INITIALIZATION
 *
 ******************************************************************************/


static struct provenance_operations provstub_provenance_ops = {
	.name    = "provstub",

/* Provenance-generating hooks */
#define HANDLE(HOOK) .HOOK = provstub_##HOOK

	HANDLE(socket_setsockopt),
	HANDLE(socket_getsockopt),

	//HANDLE(bprm_check_provenance),
};

static int __init provstub_init (void)
{

	if (!provenance_module_enable(&provstub_provenance_ops)) {
		printk(KERN_ERR "Prov Stub: ERROR - failed to enable module\n");
		return -EINVAL;
	}
	printk(KERN_INFO "Prov Stub: module enabled\n");

	/* register ourselves with the provenance framework */
	if (register_provenance (&provstub_provenance_ops)) {
		printk (KERN_INFO 
			"Failure registering Prov Stub module with the kernel\n");
			return -EINVAL;
	}
	printk (KERN_INFO "Prov Stub module initialized");

	return 0;
}

provenance_initcall (provstub_init);

#endif



