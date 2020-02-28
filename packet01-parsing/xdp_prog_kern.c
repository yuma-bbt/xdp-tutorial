/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct icmphdr_common { 
	__u8	type;
	__u8	code;
	__sum16	cksum;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}


/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr * ip6h =  nh->pos;
	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h +1 ;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;

}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;
	if (icmp6h +1 > data_end)
			return -1;
	nh->pos = icmp6h +1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;

}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
												void *data_end,
												struct icmphdr_common **icmphdr)
{
	struct icmphdr_common *h = nh->pos;
	if(h + 1 > data_end)
			return -1;
	nh->pos = h + 1;
	*icmphdr = h;

	return h->type;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
										void *data_end,
										struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if(iph + 1 > data_end)
		return -1;

	hdrsize = iph -> ihl * 4;

	if(nh->pos + hdrsize > data_end)
			return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ip6hdr;
	__u16 echo_reply,old_csum;
	struct icmphdr_common *icmphdr;
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP))
		ip_type = parse_iphdr(&nh,data_end,&iphdr);
		goto out;

	/* Assignment additions go below here */
	ip_type = parse_ip6hdr(&nh,data_end,&ip6hdr);
	if (ip_type != IPPROTO_ICMPV6) { 
		goto out;

	}else {
		goto out;
	}


	//icmp header 
	icmp_type = parse_icmphdr_common(&nh,data_end,&icmphdr);
	if (eth_type == bpf_htons(ETH_P_IPV6)
			&& icmp_type == ICMPV6_ECHO_REQUEST) { 
				echo_reply = ICMPV6_ECHO_REPLY;
				}
				else{
					goto out;
				}
								
	action = XDP_TX;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
