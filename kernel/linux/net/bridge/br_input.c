/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#if defined(CONFIG_MIPS_BRCM)
#include <linux/if_vlan.h>
#include <linux/timer.h>
#endif
#include "br_private.h"

const unsigned char bridge_ula[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static int br_pass_frame_up_finish(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
#if defined(CONFIG_MIPS_BRCM)
	/* If pass up to IP, remove VLAN header */
	if (skb->protocol == __constant_htons(ETH_P_8021Q)) {
		unsigned short proto;
		struct vlan_hdr *vhdr = (struct vlan_hdr *)(skb->data);

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (skb) {
			memmove(skb->data - ETH_HLEN + VLAN_HLEN,
				skb->data - ETH_HLEN, 12);
			skb_pull(skb, VLAN_HLEN);
			skb->mac.raw += VLAN_HLEN;
			skb->nh.raw += VLAN_HLEN;
			skb->h.raw += VLAN_HLEN;
		}
		/* make sure protocol is correct before passing up */
		proto = vhdr->h_vlan_encapsulated_proto;
		skb->protocol = proto;
		/* TODO: do we need to assign skb->priority? */
	}
#endif
	netif_rx(skb);

	return 0;
}

static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	br->statistics.rx_packets++;
	br->statistics.rx_bytes += skb->len;

	indev = skb->dev;
	skb->dev = br->dev;

	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
			br_pass_frame_up_finish);
}

extern void addr_debug();

void query_timeout(unsigned long ptr)
{
	struct net_bridge_mc_fdb_entry *dst;
	struct net_bridge_mc_fdb_entry *tmp = NULL;
	struct list_head *lh;
	struct net_bridge *br;
    
	br = (struct net_bridge *) ptr;

	spin_lock_bh(&br->mcl_lock);
	list_for_each_safe_rcu(lh, tmp, &br->mc_list) {
	    dst = (struct net_bridge_mc_fdb_entry *) list_entry(lh, struct net_bridge_mc_fdb_entry, list);
	    if (jiffies > dst->tstamp) {
		list_del_rcu(&dst->list);
		kfree(dst);
	    }
	}
	spin_unlock_bh(&br->mcl_lock);
		
	mod_timer(&br->igmp_timer, jiffies + TIMER_CHECK_TIMEOUT*HZ);		
}

void addr_debug(unsigned char *dest)
{
#define NUM2PRINT 50
	char buf[NUM2PRINT * 3 + 1];	/* 3 chars per byte */
	int i = 0;
	for (i = 0; i < 6 && i < NUM2PRINT; i++) {
		sprintf(buf + i * 3, "%2.2x ", 0xff & dest[i]);
	}
	printk("%s ", buf);
}


#if defined(CONFIG_MIPS_BRCM)
addr_conv(unsigned char *in, char * out)
{
    sprintf(out, "%02x%02x%02x%02x%02x%02x", in[0], in[1], in[2], in[3], in[4], in[5]);
}

mc_forward(struct net_bridge *br, struct sk_buff *skb, unsigned char *dest,int forward, int clone)
{
	struct net_bridge_mc_fdb_entry *dst;
	struct list_head *lh;
	int status = 0;
	struct sk_buff *skb2;
	struct net_bridge_port *p;

	if (!snooping)
		return 0;

	if (skb->data[9] == 0x2) {
	    // For proxy; need to add some intelligence here 
	    if (!br->proxy) {
		if (skb->data[24] == 0x16)
		    br_mc_fdb_add(br, skb->dev->br_port, dest, skb->mac.ethernet->h_source);
		else if (skb->data[24] == 0x17) {
		    dest[0] = 0x01;
		    dest[1] = 0x00;
		    dest[2] = 0x5e;
		    dest[3] = 0x7F & skb->data[29];
		    dest[4] = skb->data[30];
		    dest[5] = skb->data[31];
		    br_mc_fdb_remove(br, skb->dev->br_port, dest, skb->mac.ethernet->h_source);
		}
		else
		    ;
	    }
	    return status;
	}

	/*
	if (clone) {
		struct sk_buff *skb3;

		if ((skb3 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
			br->statistics.tx_dropped++;
			return;
		}

		skb = skb3;
	}
	*/
	
	list_for_each_rcu(lh, &br->mc_list) {
	    dst = (struct net_bridge_mc_fdb_entry *) list_entry(lh, struct net_bridge_mc_fdb_entry, list);
	    if (!memcmp(&dst->addr, dest, ETH_ALEN)) {
		if (!dst->dst->dirty) {
		    skb2 = skb_clone(skb, GFP_ATOMIC);
		    if (forward)
			br_forward(dst->dst, skb2);
		    else
			br_deliver(dst->dst, skb2);
		}
		dst->dst->dirty = 1;
		status = 1;
	    }
	}
	if (status) {
	    list_for_each_entry_rcu(p, &br->port_list, list) {
		p->dirty = 0;
	  }
	}

	if ((!forward) && (status))
	kfree_skb(skb);

	return status;
}
#endif

int br_handle_frame_finish(struct sk_buff *skb)
{
	struct net_bridge *br;
	unsigned char *dest;
#if defined(CONFIG_MIPS_BRCM)
	unsigned char *src;
#endif
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_port *p;
	int passedup;

	dest = skb->mac.ethernet->h_dest;
#if defined(CONFIG_MIPS_BRCM)
	src = skb->mac.ethernet->h_source;
#endif
	
	rcu_read_lock();
	p = skb->dev->br_port;
	smp_read_barrier_depends();

	if (p == NULL || p->state == BR_STATE_DISABLED) {
		kfree_skb(skb);
		goto out;
	}

	br = p->br;
	passedup = 0;
	if (br->dev->flags & IFF_PROMISC) {
		struct sk_buff *skb2;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 != NULL) {
			passedup = 1;
			br_pass_frame_up(br, skb2);
		}
	}

	if (dest[0] & 1) {
#if defined(CONFIG_MIPS_BRCM)
		if (snooping && br->proxy) {
		  if (skb->data[9] == 0x2) {
		    char destS[16];
		    char srcS[16];

		    if (skb->data[24] == 0x17) {
			unsigned char tmp[6];
			
			tmp[0] = 0x01;
			tmp[1] = 0x00;
			tmp[2] = 0x5e;
			tmp[3] = 0x7F & skb->data[29];
			tmp[4] = skb->data[30];
			tmp[5] = skb->data[31];
			addr_conv(tmp, destS);
		    }
		    else
			addr_conv(dest, destS);
		    addr_conv(src, srcS);
		    sprintf(skb->extif, "%s %s %s/%s", br->dev->name, p->dev->name, destS, srcS);
		  }
		}
		if (!mc_forward(br, skb, dest, 1, !passedup))		
#endif
		br_flood_forward(br, skb, !passedup);
		if (!passedup)
			br_pass_frame_up(br, skb);
		goto out;
	}

	dst = __br_fdb_get(br, dest);
	if (dst != NULL && dst->is_local) {
		if (!passedup)
			br_pass_frame_up(br, skb);
		else
			kfree_skb(skb);
		goto out;
	}

	if (dst != NULL) {
		br_forward(dst->dst, skb);
		goto out;
	}

	br_flood_forward(br, skb, 0);

out:
	rcu_read_unlock();
	return 0;
}

int br_handle_frame(struct sk_buff *skb)
{
	unsigned char *dest;
	struct net_bridge_port *p;

	dest = skb->mac.ethernet->h_dest;

	rcu_read_lock();
	p = skb->dev->br_port;
	if (p == NULL || p->state == BR_STATE_DISABLED)
		goto err;

	if (skb->mac.ethernet->h_source[0] & 1)
		goto err;

	if (p->state == BR_STATE_LEARNING ||
	    p->state == BR_STATE_FORWARDING)
		br_fdb_insert(p->br, p, skb->mac.ethernet->h_source, 0);

	if (p->br->stp_enabled &&
	    !memcmp(dest, bridge_ula, 5) &&
	    !(dest[5] & 0xF0)) {
		if (!dest[5]) {
			NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev, 
				NULL, br_stp_handle_bpdu);
			rcu_read_unlock();
			return 0;
		}
	}

	else if (p->state == BR_STATE_FORWARDING) {
		if (br_should_route_hook && br_should_route_hook(&skb)) {
			rcu_read_unlock();
			return -1;
		}

		if (!memcmp(p->br->dev->dev_addr, dest, ETH_ALEN))
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);
		rcu_read_unlock();
		return 0;
	}

err:
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}
