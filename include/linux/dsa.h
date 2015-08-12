/* dsa.h: digital signature architecture
 *
 * Copyright (C) 2005 David HÃrdeman (david@xxxxxxxx).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Ported by daveti
 * Sep 29, 2014
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef _LINUX_DSA_H
#define _LINUX_DSA_H
#ifdef __KERNEL__

#include <crypto/hash.h>
#include <linux/crypto/mpi.h>
#include <linux/scatterlist.h>

#define DSA_DIGEST_SIZE 44
#define DSA_HMAC_BLOCK_SIZE 64
#define DSA_PART_P 0
#define DSA_PART_Q 1
#define DSA_PART_G 2
#define DSA_PART_Y 3
#define DSA_PART_X 4
#define DSA_PARTS 5	/* private key */
#define DSA_PUBLIC_PARTS 4 /* public key */
#define DSA_SIG_PARTS 2
#define DSA_SIG_PART_R 0
#define DSA_SIG_PART_S 1
#define DSA_SIG_PART_SIZE 20
// Stardard (1024,160) - len(sig)=40 bytes
#define DSA_PART_P_HC_LEN	128 /* hardcode length - bytes */
#define DSA_PART_Q_HC_LEN	20
#define DSA_PART_G_HC_LEN	128
#define DSA_PART_Y_HC_LEN	128
#define DSA_PART_X_HC_LEN	20
// Non-FIPS (1024,152) - len(sig)=38 bytes
#define DSA_PART_P_NF_HC_LEN       128 /* hardcode length - bytes */
#define DSA_PART_Q_NF_HC_LEN       19
#define DSA_PART_G_NF_HC_LEN       128
#define DSA_PART_Y_NF_HC_LEN       128
#define DSA_PART_X_NF_HC_LEN       19
#define SHA1_HASH_LEN 20

// Bates: Adding size for unencoded DSA Signature
#define DSA_SIGNATURE_RAW_SIZE     (DSA_PART_Q_NF_HC_LEN + DSA_PART_X_NF_HC_LEN)

/* Missing MPI macros - thanks to David@2gen */
#define MPI_WSIZE(buf, size)            \
    do {                                \
        *buf++ = ((size >> 8) & 0xff);  \
        *buf++ = ((size     ) & 0xff);  \
    } while (0)


struct key_payload_dsa {
	MPI part[DSA_PARTS]; /* p,q,g,y,x */
	/* public key: (p,q,g,y)
	 * private key: (p,q,g,x)
	 */
};

struct dsa_ctx {
	struct hash_desc desc;	/* SHA1 alg */
	struct scatterlist sg;	/* crypto sg */
	struct hash_desc desc_verify; /* SHA1 alg for verification */
	struct scatterlist sg_verify; /* crypto sg for verification */
        struct key_payload_dsa *key; /* private/public key */
	/* Generated during signing */
	u8 digest[SHA1_HASH_LEN]; /* SHA1 digest */
	u8 sig[DSA_DIGEST_SIZE]; /* DSA signature */
	u8 sig_len;		 /* NOTE: we support different sig size, like 38/40. Max = 44 */
	MPI mpi_sig[DSA_SIG_PARTS]; /* DSA signature in MPI format */
	/* Generated during verification */
	u8 digest_verify[SHA1_HASH_LEN]; /* SHA1 digest for verification */
	MPI mpi_sig_verify[DSA_SIG_PARTS]; /* DSA signature in MPI format */
};

/* APIs */
void dsa_debug_key(struct dsa_ctx *ctx,
                const u8 *p, unsigned int p_len,
                const u8 *q, unsigned int q_len,
                const u8 *g, unsigned int g_len,
                const u8 *y, unsigned int y_len,
                const u8 *x, unsigned int x_len);
void dsa_set_key(struct dsa_ctx *ctx,
		const u8 *p, unsigned int p_len,
		const u8 *q, unsigned int q_len,
		const u8 *g, unsigned int g_len,
		const u8 *y, unsigned int y_len,
		const u8 *x, unsigned int x_len);
void dsa_check_key(struct dsa_ctx *ctx);
int dsa_parse_key(struct dsa_ctx *ctx, const u8 *key, unsigned int keylen, int is_pub);
void dsa_destroy_key(struct dsa_ctx *ctx);
int dsa_init(struct dsa_ctx *ctx);
int dsa_sign(struct dsa_ctx *ctx, const u8 *data, unsigned int data_len);
int dsa_verify(struct dsa_ctx *ctx, const u8 *sig, unsigned int sig_len,
		const u8 *data, unsigned int data_len);

#if 0
/* Hardcoded DSA key parameters - for perf eval */
const char dsa_key_hc_parm_p[DSA_PART_P_HC_LEN] =
"\xfd\x7f\x53\x81\x1d\x75\x12\x29\x52\xdf\x4a\x9c\x2e\xec\xe4\xe7\xf6\x11\xb7\x52\x3c\xef\x44\x00\xc3\x1e\x3f\x80\xb6\x51\x26\x69"
"\x45\x5d\x40\x22\x51\xfb\x59\x3d\x8d\x58\xfa\xbf\xc5\xf5\xba\x30\xf6\xcb\x9b\x55\x6c\xd7\x81\x3b\x80\x1d\x34\x6f\xf2\x66\x60\xb7"
"\x6b\x99\x50\xa5\xa4\x9f\x9f\xe8\x04\x7b\x10\x22\xc2\x4f\xbb\xa9\xd7\xfe\xb7\xc6\x1b\xf8\x3b\x57\xe7\xc6\xa8\xa6\x15\x0f\x04\xfb"
"\x83\xf6\xd3\xc5\x1e\xc3\x02\x35\x54\x13\x5a\x16\x91\x32\xf6\x75\xf3\xae\x2b\x61\xd7\x2a\xef\xf2\x22\x03\x19\x9d\xd1\x48\x01\xc7"
;
const char dsa_key_hc_parm_q[DSA_PART_Q_HC_LEN] =
"\x97\x60\x50\x8f\x15\x23\x0b\xcc\xb2\x92\xb9\x82\xa2\xeb\x84\x0b\xf0\x58\x1c\xf5"
;
const char dsa_key_hc_parm_g[DSA_PART_G_HC_LEN] =
"\xf7\xe1\xa0\x85\xd6\x9b\x3d\xde\xcb\xbc\xab\x5c\x36\xb8\x57\xb9\x79\x94\xaf\xbb\xfa\x3a\xea\x82\xf9\x57\x4c\x0b\x3d\x07\x82\x67"
"\x51\x59\x57\x8e\xba\xd4\x59\x4f\xe6\x71\x07\x10\x81\x80\xb4\x49\x16\x71\x23\xe8\x4c\x28\x16\x13\xb7\xcf\x09\x32\x8c\xc8\xa6\xe1"
"\x3c\x16\x7a\x8b\x54\x7c\x8d\x28\xe0\xa3\xae\x1e\x2b\xb3\xa6\x75\x91\x6e\xa3\x7f\x0b\xfa\x21\x35\x62\xf1\xfb\x62\x7a\x01\x24\x3b"
"\xcc\xa4\xf1\xbe\xa8\x51\x90\x89\xa8\x83\xdf\xe1\x5a\xe5\x9f\x06\x92\x8b\x66\x5e\x80\x7b\x55\x25\x64\x01\x4c\x3b\xfe\xcf\x49\x2a"
;
const char dsa_key_hc_parm_y[DSA_PART_Y_HC_LEN] =
"\xa2\x8a\x43\xb9\x5d\x73\x6b\x5a\x5a\xfe\xb5\xa0\x7d\x2c\x89\x65\xeb\xf3\x52\xa3\xe2\x9b\xa7\xe3\x65\x11\x12\x0c\xcc\xa2\xb7\x60"
"\x51\xcd\xfb\x87\xfd\x9e\xe7\x58\xe5\xb1\x15\x98\x66\x63\x18\x6f\x46\x83\x27\xbf\x5a\xc5\x00\xf1\x89\xcb\x70\x6f\x62\x16\xab\xbc"
"\x4b\xb7\x25\x8f\x92\x15\x06\x06\x5d\xb3\x36\x98\x3c\x31\x26\x7c\xe7\x8c\x94\x27\xfa\xb8\xda\xd0\xc6\x4b\x54\xf1\xef\xf6\x0e\xc6"
"\x01\xdd\x1a\xbc\x25\xd9\x56\x93\x80\x37\x94\xd9\x67\x33\xd5\x65\x69\x93\x1f\x07\xc7\x72\xa5\x13\x23\x83\xac\x6e\xab\xda\xfb\xc4"
;
const char dsa_key_hc_parm_x[DSA_PART_X_HC_LEN] =
"\x87\xa0\x68\x97\x5e\xf2\x51\xb4\x50\x51\x0d\xee\x08\x73\x41\x19\x5c\xa6\x8c\x16"
;
#endif

#endif
#endif

