#include <linux/provenance_network.h>

/***************************************************************
 *
 *  HIFI PACKET LABELING FUNCTIONS
 *
 ***************************************************************/
#ifdef CONFIG_PROVENANCE_NETWORK_OFF

int provenance_label_packet(struct sk_buff *skb){return 0;}
int provenance_detach_packet_label(struct sk_buff *skb){return -1;}
int provenance_init_ip_options(struct ip_options * opt){return 0;}

#endif

#if defined(CONFIG_PROVENANCE_NETWORK_HIFI) || defined(CONFIG_PROVENANCE_NETWORK_DSA)

int provenance_init_ip_options(struct ip_options * opt) {


  /* Gotta fit in 40 bytes minus  2 for the Type/Length octets*/
  BUILD_BUG_ON(DSA_SIGNATURE_RAW_SIZE > (MAX_IPOPTLEN-2));

  //Allocate enough for the following:
  //   IPOPT NUMBER ( unsigned char )
  //   IPOPT LENGTH ( unsigned char )
  //   IPOPT DATA ( struct pktid )

  opt = kzalloc_ip_options(MAX_IPOPTLEN, GFP_ATOMIC);
  if (!opt)
    return -ENOMEM;

  opt->optlen = MAX_IPOPTLEN;
  /* Option-Type octet */
  opt->__data[0] = IPOPT_PROVENANCE;
  /* Option-Length octet (data plus 2 bytes for type and length*/
  opt->__data[1] = MAX_IPOPTLEN;

  // There's an error in ip_options parsing.
  //   we will add 2 extra bytes and then set them both to IPOPT_END 
  /*
  for(i=0; i< (MAX_IPOPTLEN-2+sizeof(struct sockid_opt));i++){
    opt->__data[2+opt->__data[1]+1] = IPOPT_END;
  }
  */

  // This is done automatically for us in kzalloc_ip_options
  /* rhel_ip_options_set_alloc_flag(opt); */

  return 0;

}

#endif

#ifdef CONFIG_PROVENANCE_NETWORK_HIFI

// Adds a label to the packet in skb.
int provenance_label_packet(struct sk_buff *skb)
{
  struct iphdr *iph = ip_hdr(skb);
  struct sock_provenance *prov = skb->sk->sk_provenance;
  struct sockid *label = &prov->short_id;
  struct host_sockid *lp;
  u8 *p = NULL;

  //Many different ways to get at the IP Options to find the packet label
  //This works for outgoing packets
  if(skb->sk){
    struct inet_sock *inet = inet_sk(skb->sk);
    p = find_packet_label_alt(inet->opt,1);
  }
  //Use Devin's magic numbers for incoming packets
  if(!p){
    p = find_packet_label((u8 *) (iph + 1), (iph->ihl - 5) * 4,1);
  }

  if (!p) {
    return 0;
  }
  
  //Write label and fix checksum
  lp = (struct host_sockid *) (p + 2);
  lp->host = prov->full_id.host;
  lp->sock = *label;
  ip_send_check(iph);

  return 0;
}

// Removes the label from the packet in @skb and returns it in @label.
int provenance_detach_packet_label(struct sk_buff *skb)
{

  struct iphdr *iph = ip_hdr(skb);
  struct inet_sock *inet;
  struct skb_provenance *prov = skb_shinfo(skb)->provenance;
  struct host_sockid *label =  &prov->id;
  u8 * p= NULL;
  
  //Many different ways to get at the IP Options to find the packet label
  //This works for outgoing packets
  if(skb->sk){
    inet = inet_sk(skb->sk);  
    p = find_packet_label_alt(inet->opt,0);
  }
  if(!p){
    p = find_packet_label((u8 *) (iph + 1), (iph->ihl - 5) * 4,0);
  }

  if (!p){
    return -1;
  }

  *label = *((struct host_sockid *) (p + 2));

  memmove(skb_pull(skb, sizeof(struct sockid_opt)), iph, p - (u8 *) iph);
  skb_reset_network_header(skb);

  //Do a little fixup...
  iph = ip_hdr(skb);
  iph->tot_len -= sizeof(struct sockid_opt);
  iph->ihl -= sizeof(struct sockid_opt) / 4;
  ip_send_check(iph);
  return 0;

}
#endif

/***************************************************************
 *
 *  DSA PACKET SIGNING FUNCTIONS
 *
 ***************************************************************/
#ifdef CONFIG_PROVENANCE_NETWORK_DSA

// Retrieve the immutable part of the pkt
static u8 *get_packet_immutable(struct sk_buff *skb)
{
	u8 *data = NULL;
	int data_len = 0;
	struct iphdr *iph = NULL;
	u8 ttl;

	if (!skb) {
		printk(KERN_ERR "get_packet_immutable: skb NULL\n");
		return data;
	}

	data_len = skb->len;
	data = kmalloc(data_len, GFP_ATOMIC);
	if (!data) {
		printk(KERN_ERR "get_packet_immutable: kmalloc failed for [%d] bytes\n", data_len);
		return data;
	}

	/* Get the IP header */
	iph = ip_hdr(skb);
	if (!iph) {
		printk(KERN_ERR "get_packet_immutable: ip_hdr failed\n");
		return data;
	}

	/* Save and reset the TTL */
	ttl = iph->ttl;
	iph->ttl = 0;

	/* Copy the pkt data */
	if (!skb_is_nonlinear(skb))
		memcpy(data, skb->data, data_len);
	else
		skb_copy_bits(skb, 0, data, data_len);

	/* Reset the TTL in IP header */
	iph->ttl = ttl;

	return data;
}

// daveti: DSA here
// May consider to wrap up all the stuffs here into a struct
static DEFINE_SPINLOCK(lpm_dsa_lock);
static struct dsa_ctx lpm_dsa_ctx;
static int dsa_ctx_inited;
static int dsa_use_non_fips = 1;
static int dsa_debug = 0;
static int dsa_bm_flag = 0;
static int dsa_self_verify = 0;
// daveti: BM macro
#define DSA_BM_SEC_IN_USEC      1000000
#define DSA_BM_SUB_TV(s, e)             \
	((e.tv_sec*DSA_BM_SEC_IN_USEC+e.tv_usec) - \
	(s.tv_sec*DSA_BM_SEC_IN_USEC+s.tv_usec))

// Adds a label to the packet in skb.
int provenance_label_packet(struct sk_buff *skb)/*, const struct sockid *label)*/
{
	struct iphdr *iph = ip_hdr(skb);
	struct dsa_pktid *lp;
	u8 *p = NULL;

	//daveti: DSA
        int rc;
        u8 *sig = NULL;
	u8 *data = NULL;
        unsigned int sig_len, data_len;
        struct timeval start_tv, end_tv;
	int dsa_failed = 0;
	struct dsa_ctx *pkt_dsa_ctx_p = NULL;

        if (unlikely(dsa_ctx_inited == 0)) {
		/* SMP protection for global dsa ctx */
		spin_lock(&lpm_dsa_lock);

		/* Defensive checking for race condition */
		if (dsa_ctx_inited == 1)
			goto dsa_start;
		else if (dsa_ctx_inited == -1)
			goto out;

                /* Init the dsa ctx at first
                 * NOTE: do NOT init this within the provmon_init!
                 * daveti
                 */
                printk(KERN_INFO "Provenance Monitor: Init DSA CTX\n");
                rc = dsa_init(&lpm_dsa_ctx);
                if (rc) {
                        printk(KERN_ERR "Provenance Monitor: Init DSA CTX failed with error [%d]\n", rc);
                        /* Save the error */
                        dsa_ctx_inited = -1;
                } else {
                        /* Hardcode the key parms */
                        printk(KERN_INFO "Provenance Monitor: Set the DSA key parms: use-Non-FIPS [%d]\n",
                                dsa_use_non_fips);
                        if (dsa_use_non_fips) {
                                dsa_set_key(&lpm_dsa_ctx,
                                        dsa_key_nf_hc_parm_p, DSA_PART_P_NF_HC_LEN,
                                        dsa_key_nf_hc_parm_q, DSA_PART_Q_NF_HC_LEN,
                                        dsa_key_nf_hc_parm_g, DSA_PART_G_NF_HC_LEN,
                                        dsa_key_nf_hc_parm_y, DSA_PART_Y_NF_HC_LEN,
                                        dsa_key_nf_hc_parm_x, DSA_PART_X_NF_HC_LEN);

                                if (dsa_debug) {
                                        printk(KERN_INFO "Provenance Monitor: Debug the DSA key parms\n");
                                        dsa_debug_key(&lpm_dsa_ctx,
                                                dsa_key_nf_hc_parm_p, DSA_PART_P_NF_HC_LEN,
                                                dsa_key_nf_hc_parm_q, DSA_PART_Q_NF_HC_LEN,
                                                dsa_key_nf_hc_parm_g, DSA_PART_G_NF_HC_LEN,
                                                dsa_key_nf_hc_parm_y, DSA_PART_Y_NF_HC_LEN,
                                                dsa_key_nf_hc_parm_x, DSA_PART_X_NF_HC_LEN);
                                }
                        }
                        else {
                                dsa_set_key(&lpm_dsa_ctx,
                                        dsa_key_hc_parm_p, DSA_PART_P_HC_LEN,
                                        dsa_key_hc_parm_q, DSA_PART_Q_HC_LEN,
                                        dsa_key_hc_parm_g, DSA_PART_G_HC_LEN,
                                        dsa_key_hc_parm_y, DSA_PART_Y_HC_LEN,
                                        dsa_key_hc_parm_x, DSA_PART_X_HC_LEN);

                                if (dsa_debug) {
                                        printk(KERN_INFO "Provenance Monitor: Debug the DSA key parms\n");
                                        dsa_debug_key(&lpm_dsa_ctx,
                                                dsa_key_hc_parm_p, DSA_PART_P_HC_LEN,
                                                dsa_key_hc_parm_q, DSA_PART_Q_HC_LEN,
                                                dsa_key_hc_parm_g, DSA_PART_G_HC_LEN,
                                                dsa_key_hc_parm_y, DSA_PART_Y_HC_LEN,
                                                dsa_key_hc_parm_x, DSA_PART_X_HC_LEN);
                                }
                        }

                        /* Check the key */
                        printk(KERN_INFO "Provenance Monitor: Check the DSA key parms\n");
                        dsa_check_key(&lpm_dsa_ctx);

                        /* Mark it init'd */
                        dsa_ctx_inited = 1;
                }

		/* Unlock */
		spin_unlock(&lpm_dsa_lock);
        }

	/* Do not care about dsa_ctx_inited == -1 */

dsa_start:
	/* DSA starts */
	if (likely(dsa_ctx_inited == 1)) {
                /* DSA sign */
		data_len = skb->len;
		data = get_packet_immutable(skb);
		if (!data) {
			printk(KERN_ERR "Provenance Monitor: get_packet_immutable failed\n");
			goto out;
		}

		/* Allocate dsa_ctx per pkt to avoid spin_lock */
		pkt_dsa_ctx_p = kmalloc(sizeof(struct dsa_ctx), GFP_ATOMIC);
		if (!pkt_dsa_ctx_p) {
			printk(KERN_ERR "Provenance Monitor: allocation for pkt dsa ctx failed\n");
			goto out;
		}

		/* Init the pkt dsa ctx */
		memset(pkt_dsa_ctx_p, 0x0, sizeof(struct dsa_ctx));
		memcpy(pkt_dsa_ctx_p, &lpm_dsa_ctx, sizeof(struct dsa_ctx));

//daveti: microBM (sign) starts
if (dsa_bm_flag)
	do_gettimeofday(&start_tv);
                rc = dsa_sign(pkt_dsa_ctx_p, data, data_len);
if (dsa_bm_flag) {
	do_gettimeofday(&end_tv);
	printk(KERN_INFO "daveti_BM_dsa_sign: [%lu] us\n",
        	DSA_BM_SUB_TV(start_tv, end_tv));
}
//daveti: microBM (sign) ends
		if (dsa_debug) {
			printk(KERN_INFO "Provenance Monitor: [%d] (or %d?) bytes signature for [%d] bytes data\n",
			       rc, pkt_dsa_ctx_p->sig_len, data_len);
			print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
				pkt_dsa_ctx_p->sig, pkt_dsa_ctx_p->sig_len, 0);
		}

                /* DSA verify */
		if (dsa_self_verify) {
			sig = pkt_dsa_ctx_p->sig;
			sig_len = pkt_dsa_ctx_p->sig_len;
//daveti: microBM (verify) starts
if (dsa_bm_flag)
	do_gettimeofday(&start_tv);
			rc = dsa_verify(pkt_dsa_ctx_p, sig, sig_len, data, data_len);
if (dsa_bm_flag) {
	do_gettimeofday(&end_tv);
	printk(KERN_INFO "daveti_BM_dsa_verify: [%lu] us\n",
        	DSA_BM_SUB_TV(start_tv, end_tv));
}
//daveti: microBM (verify) ends
			if (!rc)
                        	printk(KERN_INFO "Provenance Monitor: dsa_verify succeeded\n");
                	else
                        	printk(KERN_ERR "Provenance Monitor: dsa_verify failed\n");
		}
        }

out:

	//Many different ways to get at the IP Options to find the packet label
	//This works for outgoing packets
	if(skb->sk){
	  struct inet_sock *inet = inet_sk(skb->sk);
	  p = find_packet_label_alt(inet->opt,1);
	}
	//Use Devin's magic numbers for incoming packets
	if(!p){
	  p = find_packet_label((u8 *) (iph + 1), (iph->ihl - 5) * 4,1);
	}

	if (!p) {
	  goto free_out;
	}

	/* Bug if DSA failed */
	/* Oops! We can't bug when DSA fails because it will fail for fragmentation */
	/*
	if(dsa_ctx_inited != 1 || dsa_failed == 1)
	  panic("Provenance Monitor: DSA Initialization/Signature Failure when attempting to label packet.");
	*/
	/* Write label and fix checksum */
	if(dsa_ctx_inited == 1 && dsa_failed != 1 && pkt_dsa_ctx_p){
	  lp = (struct dsa_pktid *) (p + 2);
	  memcpy((void *)lp, pkt_dsa_ctx_p->sig, pkt_dsa_ctx_p->sig_len);
	}

	ip_send_check(iph);

	if (dsa_debug)
	  printk(KERN_INFO "Provenance Monitor: sig_is_put into the option\n");

free_out:
	/* Free the mem */
        if (pkt_dsa_ctx_p)
                kfree(pkt_dsa_ctx_p);
	if (data)
		kfree(data);

	return 0;
}


// Removes the label from the packet in @skb and returns it in @label.
int provenance_detach_packet_label(struct sk_buff *skb)
{

        struct iphdr *iph = ip_hdr(skb);
	struct inet_sock *inet;
	struct skb_provenance *prov = skb_shinfo(skb)->provenance;
	struct pktid *label = &(prov->sig);
	u8 * p= NULL;
	
	//Many different ways to get at the IP Options to find the packet label
	//This works for outgoing packets
	if(skb->sk){
	  inet = inet_sk(skb->sk);	  
	  p = find_packet_label_alt(inet->opt,0);
	}
	if(!p){
	  p = find_packet_label((u8 *) (iph + 1), (iph->ihl - 5) * 4,0);
	}

	if (!p){
	  return -1;
	}

	*label = *((struct pktid *) (p + 2));

	memmove(skb_pull(skb, sizeof(struct sockid_opt)), iph, p - (u8 *) iph);
	skb_reset_network_header(skb);

	//Do a little fixup...
	iph = ip_hdr(skb);
	iph->tot_len -= sizeof(struct sockid_opt);
	iph->ihl -= sizeof(struct sockid_opt) / 4;
	ip_send_check(iph);
	return 0;
}

#endif

u8* find_packet_label_alt(struct ip_options *opts,int debug){
  
  u8*p;

  if(!opts || opts->optlen<1)
    goto out_fail;

  p = opts->__data;

  while(p < opts->__data + opts->optlen){
    switch(p[0]){
      case IPOPT_PROVENANCE:		  
	// Make sure it's the right length      
	if(p[1] != MAX_IPOPTLEN)
	  goto out_fail;
	
	return p;      
    case IPOPT_END:
      goto out_fail;
    case IPOPT_NOOP:
      p++;
      break;
    default:
      p++;
      break;
    }
  }

 out_fail:
  return NULL;

}


// Finds the label in a set of options.
u8 *find_packet_label(u8 *opts, int len, int debug)
{
  
	u8 *p = opts;

	while (p < opts + len)
		switch (p[0]) {
		case IPOPT_PROVENANCE:		  
			// Make sure it's the right length
			if (p + MAX_IPOPTLEN > opts + len ||
			    p[1] != MAX_IPOPTLEN)
				return NULL;
			return p;
		case IPOPT_END:
		  goto out_fail;
		case IPOPT_NOOP:
			p++;
			break;
		default:
			if (p[1] < 2)
			  goto out_fail;
			p += p[1];
			break;
		}

 out_fail:
	//printk(KERN_WARNING "Provenance Monitor: no space found for packet label!\n");
	return NULL;
}
