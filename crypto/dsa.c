/*
 * DSA Digital Signature Algorithm (FIPS-186).
 *
 * Copyright (c) 2005 David HÃrdeman <david@xxxxxxxx>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Ported by daveti
 * Reference: http://lkml.iu.edu/hypermail/linux/kernel/0601.3/0977.html
 * NOTE: compared to the orignal patch, HUGE changes are made:
 * 1. Getting rid of the crypto framework
 * 2. Replacing digest alg with hash alg
 * 3. Exporting main interfaces to include/linux/dsa.h
 * The right usage looks like:
 * dsa_init()->dsa_parse_key()->dsa_sign()/dsa_verify()->dsa_destory_key()(if needed)
 * Sep 29, 2014
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/dsa.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/time.h>

/* daveti: enable debug */
#if 1
#define dprintk(x...) printk(x)
#else
#define dprintk(x...) do { } while(0)
#endif

/* daveti: microBM */
#define DSA_MBM_SEC_IN_USEC      1000000
#define DSA_MBM_SUB_TV(s, e)             \
        ((e.tv_sec*DSA_MBM_SEC_IN_USEC+e.tv_usec) - \
        (s.tv_sec*DSA_MBM_SEC_IN_USEC+s.tv_usec))
/* microBM flag
 * Should be disabled when there is a BM in the caller
 */
static int dsa_mbm_flag = 0;
/* daveti: self verification 
 * Should be disabled in perf eval
 */
static int self_verify_debug = 0;
/* daveti: debug logging
 * Should be disabled in perf eval
 */
static int dsa_debug_flag = 0;

/****************
 * Generate a random secret exponent k less than q
 */
static MPI dsa_gen_k(MPI q)
{
	MPI k = mpi_alloc(mpi_get_nlimbs(q));
	unsigned int nbits = mpi_get_nbits(q);
	unsigned int nbytes = (nbits + 7)/8;
	char *rndbuf = NULL;

	if (dsa_debug_flag)
		dprintk("dsa: choosing a random k\n");

	while(1) {
		if (!rndbuf) {
			rndbuf = kmalloc(nbytes, GFP_ATOMIC);
			if (!rndbuf) {
				printk(KERN_ERR "dsa: failed to create buffer\n");
				return NULL;
			}
			get_random_bytes(rndbuf, nbytes);
		} else {
			/* change only some of the higher bits */
			get_random_bytes(rndbuf, min(nbytes, (unsigned int)4));
		}

		mpi_set_buffer(k, rndbuf, nbytes, 0);
		if(mpi_test_bit( k, nbits - 1)) {
			mpi_set_highbit(k, nbits - 1);
		} else {
			mpi_set_highbit(k, nbits - 1);
			mpi_clear_bit(k, nbits - 1);
		}

		/* check: k < q */
		if(!(mpi_cmp(k, q) < 0))
			continue;

		/* check: k > 0 */
		if(!(mpi_cmp_ui(k, 0) > 0))
			continue;

		/* okay */
		break;
	}

	kfree(rndbuf);
	return k;
}

/* Internal signing function - manipulating MPI directly */
static void dsa_sign_hash(MPI r, MPI s, MPI hash, struct key_payload_dsa *skey)
{
	MPI k, kinv, tmp;

	// debug
	unsigned int nbytes;
	char *buf;
	int rc;

start:
	/* select a random k with 0 < k < q */
	k = dsa_gen_k(skey->part[DSA_PART_Q]);
	if (!k) {
		printk(KERN_ERR "dsa: failed to create buffer\n");
		return;
	}

	/* r = (g^k mod p) mod q */
	rc = mpi_powm(r, skey->part[DSA_PART_G], k, skey->part[DSA_PART_P]);
        // debug r
        if (dsa_debug_flag) {
		buf = mpi_get_buffer(r, &nbytes, NULL);
		printk(KERN_INFO "daveti: mpi_powm returned [%d], r_len [%d]\n",
			rc, nbytes);
		if (!mpi_cmp_ui(r, 0)) 
			printk(KERN_INFO "daveti: r = 0 after mpi_powm\n");
	}
	rc = mpi_fdiv_r(r, r, skey->part[DSA_PART_Q]);
	// debug r
	if (dsa_debug_flag) {
		buf = mpi_get_buffer(r, &nbytes, NULL);
		printk(KERN_INFO "daveti: mpi_fdiv_r returned [%d], r_len [%d]\n",
			rc, nbytes);
	}
	if (!mpi_cmp_ui(r, 0)) {
		if (dsa_debug_flag)
			printk(KERN_INFO "daveti: r = 0, re-select a random k\n");
		goto start;
	}

	/* kinv = k^(-1) mod q */
	kinv = mpi_alloc(mpi_get_nlimbs(k));
	mpi_invm(kinv, k, skey->part[DSA_PART_Q]);

	/* s = (kinv * ( hash + x * r)) mod q */
	tmp = mpi_alloc(mpi_get_nlimbs(skey->part[DSA_PART_P]));
	mpi_mul(tmp, skey->part[DSA_PART_X], r);
	mpi_add(tmp, tmp, hash);
	mpi_mulm(s , kinv, tmp, skey->part[DSA_PART_Q]);

        if (!mpi_cmp_ui(s, 0)) {
		if (dsa_debug_flag) 
			printk(KERN_INFO "daveti: s = 0, re-select a random k\n");
                goto start;
        }

	mpi_free(k);
	mpi_free(kinv);
	mpi_free(tmp);
}

/*
 * perform DSA algorithm signature verification
 * Ported from crypto/signature/dsa.c
 */
static int dsa_verify_sig(const MPI datahash, const MPI sig[], const MPI pkey[])
{
        MPI p, q, g, y, r, s;
        MPI w = NULL, u1 = NULL, u2 = NULL, v = NULL;
        MPI base[3];
        MPI exp[3];
        int rc;

        if (!datahash ||
            !sig[DSA_SIG_PART_R] || !sig[DSA_SIG_PART_S] ||
            !pkey[DSA_PART_P] || !pkey[DSA_PART_Q] ||
	    !pkey[DSA_PART_G] || !pkey[DSA_PART_Y])
                return -EINVAL;

        p = pkey[DSA_PART_P];    /* prime */
        q = pkey[DSA_PART_Q];    /* group order */
        g = pkey[DSA_PART_G];    /* group generator */
        y = pkey[DSA_PART_Y];    /* g^x mod p */
        r = sig[DSA_SIG_PART_R];
        s = sig[DSA_SIG_PART_S];

        if (!(mpi_cmp_ui(r, 0) > 0 && mpi_cmp(r, q) < 0)) {
                printk("DSA_verify assertion failed [0 < r < q]\n");
                return -EKEYREJECTED;
        }

        if (!(mpi_cmp_ui(s, 0) > 0 && mpi_cmp(s, q) < 0)) {
                printk("DSA_verify assertion failed [0 < s < q]\n");
                return -EKEYREJECTED;
        }

        rc = -ENOMEM;
        w  = mpi_alloc(mpi_get_nlimbs(q)); if (!w ) goto cleanup;
        u1 = mpi_alloc(mpi_get_nlimbs(q)); if (!u1) goto cleanup;
        u2 = mpi_alloc(mpi_get_nlimbs(q)); if (!u2) goto cleanup;
        v  = mpi_alloc(mpi_get_nlimbs(p)); if (!v ) goto cleanup;

        /* w = s^(-1) mod q */
        if (mpi_invm(w, s, q) < 0)
                goto cleanup;

        /* u1 = (datahash * w) mod q */
        if (mpi_mulm(u1, datahash, w, q) < 0)
                goto cleanup;

        /* u2 = r * w mod q  */
        if (mpi_mulm(u2, r, w, q) < 0)
                goto cleanup;

        /* v =  g^u1 * y^u2 mod p mod q */
        base[0] = g;    exp[0] = u1;
        base[1] = y;    exp[1] = u2;
        base[2] = NULL; exp[2] = NULL;

        if (mpi_mulpowm(v, base, exp, p) < 0)
                goto cleanup;

        if (mpi_fdiv_r(v, v, q) < 0)
                goto cleanup;

        rc = (mpi_cmp(v, r) == 0) ? 0 : -EKEYREJECTED;

cleanup:
        mpi_free(w);
        mpi_free(u1);
        mpi_free(u2);
        mpi_free(v);
        return rc;
}

/* Parse a signature into the dsa_ctx in MPI format */
static void dsa_parse_sig(struct dsa_ctx *ctx, const u8 *sig, unsigned int sig_len)
{
	int r_s_len, i;
	MPI tmp;

	/* Defensive checking */
	if (sig_len % 2) {
		printk(KERN_ERR "bad sig_len [%d] - unable to parse the signature\n", sig_len);
		return;
	}

	r_s_len = sig_len / 2;
	if (dsa_debug_flag)
		printk(KERN_INFO "signature r/s length - [%d]\n", r_s_len);

	/* Construct the MPI */
	tmp = mpi_alloc(1);
	for (i = 0; i < DSA_SIG_PARTS; i++) {
		mpi_set_buffer(tmp, (sig+i*r_s_len), r_s_len, 0);
		mpi_copy(&ctx->mpi_sig_verify[i], tmp);
	}

	mpi_free(tmp);
}

/* Parse a binary key into the dsa_ctx */
int dsa_parse_key(struct dsa_ctx *ctx, const u8 *key, unsigned int keylen, int is_pub)
{
	struct key_payload_dsa *dkey;
	int ret;

	if (!ctx || !ctx->key ) {
		printk(KERN_ERR "Null dsa ctx or key\n");
		ret = -EINVAL;
		goto out;
	}

	dkey = ctx->key;

	/* TODO: parse the key */

#if 0
	ret = 0;
	for (i = 0; i < DSA_PARTS; i++) {
		if (mpi_copy(&dkey->part[i], skey->part[i]))
			ret = -ENOMEM;
	}

	if (ret) {
		for (i = 0; i < DSA_PARTS; i++)
			mpi_free(dkey->part[i]);
		kfree(dkey);
	}
#endif

out:
	return ret;
}

/* Check the key */
void dsa_check_key(struct dsa_ctx *ctx)
{
	MPI tmp, tmp2, p, q, g, y, x;
	MPI a, b, c;
	int nbits;
	int rc;

        if (!ctx || !ctx->key) {
                printk(KERN_ERR "Null dsa ctx or key\n");
                return;
        }

	/* Ignore the prime checking for now */
	p = ctx->key->part[DSA_PART_P];
	q = ctx->key->part[DSA_PART_Q];
	g = ctx->key->part[DSA_PART_G];
	y = ctx->key->part[DSA_PART_Y];
	x = ctx->key->part[DSA_PART_X];

	/* q - 152/160-bit prime */
	nbits = mpi_get_nbits(q);
	if ((nbits != 160) && (nbits != 152))
		printk(KERN_ERR "bad q - [%d/152/160] bits\n", nbits);

	/* p - 1024-bit prime, s.t. (p-1)mod_q=0 */
	nbits = mpi_get_nbits(p);
	if (nbits != 1024)
		printk(KERN_ERR "bad p - [%d/1024] bits\n", nbits);

	tmp = mpi_alloc(mpi_get_nlimbs(p));
	mpi_set_ui(tmp, 1);
	mpi_subm(tmp, p, tmp, q);
	if (mpi_cmp_ui(tmp, 0))
		printk(KERN_ERR "bad p - (p-1)mod_q != 0\n");
	
	/* g - TODO */

	/* x - s.t. 0<x<q */
	if (mpi_cmp_ui(x, 0) <= 0 || mpi_cmp(x, q) >= 0)
		printk(KERN_ERR "bad x - not in range (0,q)\n");

	/* y - s.t. g^x%p */
	tmp2 = mpi_alloc(mpi_get_nlimbs(p));
	rc = mpi_powm(tmp2, g, x, p);
	if (dsa_debug_flag)
	  printk(KERN_INFO "daveti: mpi_powm returned [%d]\n", rc);

	if (mpi_cmp(y, tmp2))
	    printk(KERN_ERR "Crypto(DSA): bad y - g^x mod_p != y\n");

	/* Test for mpi_powm */
	a = mpi_alloc(128);
	b = mpi_alloc(128);
	c = mpi_alloc(128);
	if (!a || !b || !c)
	    printk(KERN_ERR "Crypto (DSA): mpi_alloc test failed\n");
	mpi_set_ui(a, 4);
	mpi_set_ui(b, 5);
	mpi_set_ui(c, 2);
	rc = mpi_powm(tmp, a, b, c);

	if (dsa_debug_flag)
	  printk(KERN_INFO "daveti: mpi_powm test returned [%d]\n", rc);

	if (mpi_cmp_ui(tmp, 0))
	    printk(KERN_ERR "Crypto (DSA): bad test - a^b mod_c != 0\n");

	mpi_free(tmp);
}

/* Debug/display the key */
void dsa_debug_key(struct dsa_ctx *ctx,
                const u8 *p, unsigned int p_len,
                const u8 *q, unsigned int q_len,
                const u8 *g, unsigned int g_len,
                const u8 *y, unsigned int y_len,
                const u8 *x, unsigned int x_len)
{
	unsigned int nbytes;
	char *buf;
	
        if (!ctx || !ctx->key) {
                printk(KERN_ERR "Crypto (DSA): Null dsa ctx or key\n");
                return;
        }

	/* p */
	buf = mpi_get_buffer(ctx->key->part[DSA_PART_P], &nbytes, NULL);
	if (nbytes != p_len) {
		printk(KERN_ERR "Crypto (DSA): p/mpi_p length [%d/%d] not matching\n",
			p_len, nbytes);
	} else {
		if (memcmp(buf, p, p_len)) {
			printk(KERN_ERR "Crypto (DSA): p/mpi_p not matching - dump mpi_p\n");
			print_hex_dump(KERN_DEBUG,
				"", DUMP_PREFIX_ADDRESS,
				32, 1, (void *)buf,
				p_len, 1);
		}
	}

	/* q */
        buf = mpi_get_buffer(ctx->key->part[DSA_PART_Q], &nbytes, NULL);
        if (nbytes != q_len) {
                printk(KERN_ERR "Crypto (DSA): q/mpi_q length [%d/%d] not matching\n",
                        q_len, nbytes);
        } else {
                if (memcmp(buf, q, q_len)) {
                        printk(KERN_ERR "Crypto (DSA): q/mpi_q not matching - dump mpi_q\n");
                        print_hex_dump(KERN_DEBUG,
                                "", DUMP_PREFIX_ADDRESS,
                                32, 1, (void *)buf,
                                q_len, 1);
                }
        }

	/* g */
        buf = mpi_get_buffer(ctx->key->part[DSA_PART_G], &nbytes, NULL);
        if (nbytes != g_len) {
                printk(KERN_ERR "Crypto (DSA): g/mpi_g length [%d/%d] not matching\n",
                        g_len, nbytes);
        } else {
                if (memcmp(buf, g, g_len)) {
                        printk(KERN_ERR "Crypto (DSA): g/mpi_g not matching - dump mpi_g\n");
                        print_hex_dump(KERN_DEBUG,
                                "", DUMP_PREFIX_ADDRESS,
                                32, 1, (void *)buf,
                                g_len, 1);
                }
        }

	/* y */
        buf = mpi_get_buffer(ctx->key->part[DSA_PART_Y], &nbytes, NULL);
        if (nbytes != y_len) {
                printk(KERN_ERR "Crypto (DSA): y/mpi_y length [%d/%d] not matching\n",
                        y_len, nbytes);
        } else {
                if (memcmp(buf, y, y_len)) {
                        printk(KERN_ERR "Crypto (DSA): y/mpi_y not matching - dump mpi_y\n");
                        print_hex_dump(KERN_DEBUG,
                                "", DUMP_PREFIX_ADDRESS,
                                32, 1, (void *)buf,
                                y_len, 1);
                }
        }

	/* x */
        buf = mpi_get_buffer(ctx->key->part[DSA_PART_X], &nbytes, NULL);
        if (nbytes != x_len) {
                printk(KERN_ERR "Crypto (DSA): x/mpi_x length [%d/%d] not matching\n",
                        x_len, nbytes);
        } else {
                if (memcmp(buf, x, x_len)) {
                        printk(KERN_ERR "Crypto (DSA): x/mpi_x not matching - dump mpi_x\n");
                        print_hex_dump(KERN_DEBUG,
                                "", DUMP_PREFIX_ADDRESS,
                                32, 1, (void *)buf,
                                x_len, 1);
                }
        }

}

/* Set a key into the dsa_ctx */
void dsa_set_key(struct dsa_ctx *ctx,
		const u8 *p, unsigned int p_len,
                const u8 *q, unsigned int q_len,
                const u8 *g, unsigned int g_len,
                const u8 *y, unsigned int y_len,
                const u8 *x, unsigned int x_len)
{
	MPI tmp;

	if (!ctx || !ctx->key) {
		printk(KERN_ERR "Null dsa ctx or key\n");
		return;
	}

	tmp =  mpi_alloc(1);

	/* p */
	mpi_set_buffer(tmp, p, p_len, 0);
	mpi_copy(&ctx->key->part[DSA_PART_P], tmp);

        /* q  */
        mpi_set_buffer(tmp, q, q_len, 0);
        mpi_copy(&ctx->key->part[DSA_PART_Q], tmp);

        /* g */
        mpi_set_buffer(tmp, g, g_len, 0);
        mpi_copy(&ctx->key->part[DSA_PART_G], tmp);

        /* y */
        mpi_set_buffer(tmp, y, y_len, 0);
        mpi_copy(&ctx->key->part[DSA_PART_Y], tmp);

        /* x */
        mpi_set_buffer(tmp, x, x_len, 0);
        mpi_copy(&ctx->key->part[DSA_PART_X], tmp);
}

/* Init a dsa_ctx */
int dsa_init(struct dsa_ctx *ctx)
{
	int ret;

	/* Allocate the key */
	ctx->key = kmalloc(sizeof(struct key_payload_dsa), GFP_ATOMIC);
	if (!ctx->key) {
		printk(KERN_ERR "Crypto (DSA): failed to allocate memory for key\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Init the digest */
	memset(ctx->digest, 0x0, SHA1_HASH_LEN);
	memset(ctx->digest_verify, 0x0, SHA1_HASH_LEN);

	/* Init the signature */
	memset(ctx->sig, 0x0, DSA_DIGEST_SIZE);

	/* Init SHA1 for the signing */
	printk(KERN_INFO "daveti: init desc for signing in %s\n", __FUNCTION__);
	ctx->desc.tfm = crypto_alloc_hash("sha1", 0, 0);
	if (IS_ERR(ctx->desc.tfm)) {
		printk(KERN_ERR "daveti: crypto_alloc_hash failed [%ld]\n", PTR_ERR(ctx->desc.tfm));
		ret = -1;
	} else {
		ctx->desc.flags = 0;
		ret = 0;
	}

	/* Init SHA1 for the verification */
        printk(KERN_INFO "daveti: init desc for verification in %s\n", __FUNCTION__);
        ctx->desc_verify.tfm = crypto_alloc_hash("sha1", 0, 0);
        if (IS_ERR(ctx->desc_verify.tfm)) {
                printk(KERN_ERR "daveti: crypto_alloc_hash failed [%ld]\n", PTR_ERR(ctx->desc_verify.tfm));
                ret = -1;
        } else {
                ctx->desc_verify.flags = 0;
                ret = 0;
        }

out:
	return ret;
}

int dsa_sign(struct dsa_ctx *ctx, const u8 *data, unsigned int data_len)
{
	MPI hash, r, s;
	unsigned int rbytes, sbytes;
	unsigned int rbits, sbits;
	char *rbuf, *sbuf;
	int sig_len = 0;
	struct timeval start_tv, end_tv;

	/* Make calls easier */
	struct hash_desc *desc = &(ctx->desc);
	struct scatterlist *sg = &(ctx->sg);
	u8 *outp = ctx->sig;
	u8 *buffer = ctx->digest;

//daveti: microBM (hashing) starts
if (dsa_mbm_flag)
	do_gettimeofday(&start_tv);

	/* Generate the SHA1 digest */
	sg_init_one(sg, data, data_len);
	crypto_hash_init(desc);
	crypto_hash_update(desc, sg, data_len);
	crypto_hash_final(desc, buffer);

if (dsa_mbm_flag) {
	do_gettimeofday(&end_tv);
	printk(KERN_INFO "daveti_MBM_dsa_sign_hash: [%lu] us\n",
        	DSA_MBM_SUB_TV(start_tv, end_tv));
}
//daveti: microBM (hashing) ends

	/* Generate the DSA digest */
	hash = mpi_alloc(1);
	r = mpi_alloc(1);
	s = mpi_alloc(1);
	if (!hash || !r || !s) {
		printk(KERN_ERR "Crypto (DSA): failed to allocate mpis\n");
		goto out1;
	}

	mpi_set_buffer(hash, buffer, SHA1_HASH_LEN, 0);
//daveti: microBM (DSA) starts
if (dsa_mbm_flag)
	do_gettimeofday(&start_tv);

	dsa_sign_hash(r, s, hash, ctx->key);

if (dsa_mbm_flag) {
	do_gettimeofday(&end_tv);
	printk(KERN_INFO "daveti_MBM_dsa_sign_dsa: [%lu] us\n",
        	DSA_MBM_SUB_TV(start_tv, end_tv));
}
//daveti: microBM (DSA) ends

	/* Save the MPI signature */
	mpi_copy(&ctx->mpi_sig[DSA_SIG_PART_R], r);
	mpi_copy(&ctx->mpi_sig[DSA_SIG_PART_S], s);

	/* Generate the binary signature */
	rbuf = mpi_get_buffer(r, &rbytes, NULL);
	sbuf = mpi_get_buffer(s, &sbytes, NULL);
	if (!rbuf || !sbuf) {
		printk(KERN_ERR "Crypto (DSA): failed to allocate buffers\n");
		goto out2;
	}

	/* Defensive checking */
#ifdef DSA_SIG_40 
	if (rbytes != DSA_SIG_PART_SIZE || sbytes != DSA_SIG_PART_SIZE) {
		printk(KERN_ERR "Crypto (DSA): bad r/s length [%d/%d]\n",
			rbytes, sbytes);
		goto out2;
	}
#else
	if (dsa_debug_flag)
		printk(KERN_INFO "dsa: r/s length [%d/%d]\n", rbytes, sbytes);
#endif

	/* NOTE: with certain encoding style, like ASN.1 DER,
 	 * the normal size of the DSA signature is 44 bytes.
 	 * Without any encoding scheme, the raw size should be
 	 * 40 bytes. With smaller (L,N) of the key, the raw size
 	 * could be 38 bytes. In our implementation, we always
 	 * do not use any encoding (which means MPI_WSIZE() is
 	 * not needed) and we always assume the length of r and
 	 * s are equal. All these are reflected in this function
 	 * and dsa_parse_signature().
 	 * Oct 5, 2014
 	 * daveti
 	 */

	/* Get the final result */
	if (dsa_debug_flag)
		rbits = mpi_get_nbits(r);
	//MPI_WSIZE(outp, rbits);
	memcpy(outp, rbuf, rbytes);
	outp += rbytes;
	sig_len += rbytes;

	if (dsa_debug_flag)
		sbits = mpi_get_nbits(s);
	//MPI_WSIZE(outp, sbits);
	memcpy(outp, sbuf, sbytes);
	sig_len += sbytes;

	//Debug
	if (dsa_debug_flag)
		printk(KERN_INFO "dsa: r/s bits [%d/%d]\n", rbits, sbits);

out2:
	kfree(rbuf);
	kfree(sbuf);
out1:
	mpi_free(hash);
	mpi_free(r);
	mpi_free(s);

	/* Save the sig_len into the dsa ctx */
	ctx->sig_len = sig_len;

	/* Return the total length of the signature */
	return sig_len;
}

int dsa_verify(struct dsa_ctx *ctx, const u8 *sig, unsigned int sig_len,
		const u8 *data, unsigned int data_len)
{
	MPI hash;
	int ret, i;
	struct timeval start_tv, end_tv;

	/* Generate the SHA1 digest */
        struct hash_desc *desc = &(ctx->desc_verify);
        struct scatterlist *sg = &(ctx->sg_verify);
        u8 *buffer = ctx->digest_verify;

//daveti: microBM (hasing) - starts
if (dsa_mbm_flag)
	do_gettimeofday(&start_tv);

        sg_init_one(sg, data, data_len);
        crypto_hash_init(desc);
        crypto_hash_update(desc, sg, data_len);
        crypto_hash_final(desc, buffer);

if (dsa_mbm_flag) {
	do_gettimeofday(&end_tv);
	printk(KERN_INFO "daveti_MBM_dsa_verify_hash: [%lu] us\n",
        	DSA_MBM_SUB_TV(start_tv, end_tv));
}
//daveti: microBM (hasing) - ends

        hash = mpi_alloc(1);
        if (!hash) {
                printk(KERN_ERR "Crypto (DSA): failed to allocate mpi for hash\n");
		ret = -1;
                goto out;
        }
        mpi_set_buffer(hash, buffer, SHA1_HASH_LEN, 0);

	/* Defensive checking - should be removed in practice */
	if (self_verify_debug)
		if (memcmp(ctx->digest_verify, ctx->digest, SHA1_HASH_LEN))
			printk(KERN_ERR "Crypto (DSA): SHA1 digests differs from signing\n");

	/* Convert the signature into MPI format */
	dsa_parse_sig(ctx, sig, sig_len);

        /* Defensive checking - should be removed in practice */
	if (self_verify_debug)
		for (i = 0; i < DSA_SIG_PARTS; i++)
			if (mpi_cmp(ctx->mpi_sig[i], ctx->mpi_sig_verify[i]))
				printk(KERN_ERR "Crypto (DSA): signature MPI [%d] differs from signing\n", i);

	/* Verify the signature */
//daveti: microBM (DSA) - starts
if (dsa_mbm_flag)
	do_gettimeofday(&start_tv);

	ret = dsa_verify_sig(hash, ctx->mpi_sig_verify, ctx->key->part);

if (dsa_mbm_flag) {
	do_gettimeofday(&end_tv);
	printk(KERN_INFO "daveti_MBM_dsa_verify_dsa: [%lu] us\n",
        	DSA_MBM_SUB_TV(start_tv, end_tv));
}
//daveti: microBM (DSA) - ends

	mpi_free(hash);
out:
	return ret;
}

/* Destroy the parsed and stored private key */
void dsa_destroy_key(struct dsa_ctx *ctx)
{
	int i;

	if (ctx->key) {
		for (i = 0; i < DSA_PARTS; i++)
			mpi_free(ctx->key->part[i]);
		kfree(ctx->key);
	}
}

EXPORT_SYMBOL_GPL(dsa_check_key);
EXPORT_SYMBOL_GPL(dsa_parse_key);
EXPORT_SYMBOL_GPL(dsa_set_key);
EXPORT_SYMBOL_GPL(dsa_debug_key);
EXPORT_SYMBOL_GPL(dsa_destroy_key);
EXPORT_SYMBOL_GPL(dsa_init);
EXPORT_SYMBOL_GPL(dsa_sign);
EXPORT_SYMBOL_GPL(dsa_verify);

MODULE_AUTHOR("Dave Tian");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DSA Signing Algorithm");
