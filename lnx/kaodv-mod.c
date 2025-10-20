/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University and Ericsson AB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Erik Nordström, <erik.nordstrom@it.uu.se>
 *
 *****************************************************************************/
#include <linux/if.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/tcp.h>

#include "kaodv-debug.h"
#include "kaodv-ipenc.h"
#include "kaodv-mod.h"
#include "kaodv-netlink.h"
#include "kaodv.h"

#define ACTIVE_ROUTE_TIMEOUT active_route_timeout
#define MAX_INTERFACES 10

/*
 * network namespace index,
 * set once on module load
 */
unsigned int net_id;

MODULE_DESCRIPTION(
    "AODV-UU kernel support. � Uppsala University & Ericsson AB");
MODULE_AUTHOR("Erik Nordström");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

#define ADDR_HOST 1
#define ADDR_BROADCAST 2

void kaodv_update_route_timeouts(struct mod_state *mod_state, int hooknum,
                                 const struct net_device *dev,
                                 struct iphdr *iph)
{
    struct expl_state *expl = &mod_state->expl_state;
    struct netlink_state *netlink = &mod_state->netlink_state;
    struct expl_entry e;
    struct in_addr bcaddr;
    int res;

    bcaddr.s_addr = 0; /* Stop compiler from complaining about
                        * uninitialized bcaddr */

    res = if_info_from_ifindex(mod_state, NULL, &bcaddr, dev->ifindex);

    if (res < 0)
        return;

    if (hooknum == NF_INET_PRE_ROUTING)
        kaodv_netlink_send_rt_update_msg(netlink, PKT_INBOUND, iph->saddr,
                                         iph->daddr, dev->ifindex);
    else if (iph->daddr != INADDR_BROADCAST && iph->daddr != bcaddr.s_addr)
        kaodv_netlink_send_rt_update_msg(netlink, PKT_OUTBOUND, iph->saddr,
                                         iph->daddr, dev->ifindex);

    /* First update forward route and next hop */
    if (kaodv_expl_get(expl, iph->daddr, &e))
    {

        kaodv_expl_update(expl, e.daddr, e.nhop,
                          mod_state->ACTIVE_ROUTE_TIMEOUT, e.flags,
                          dev->ifindex);

        if (e.nhop != e.daddr && kaodv_expl_get(expl, e.nhop, &e))
            kaodv_expl_update(expl, e.daddr, e.nhop,
                              mod_state->ACTIVE_ROUTE_TIMEOUT, e.flags,
                              dev->ifindex);
    }
    /* Update reverse route */
    if (kaodv_expl_get(expl, iph->saddr, &e))
    {

        kaodv_expl_update(expl, e.daddr, e.nhop,
                          mod_state->ACTIVE_ROUTE_TIMEOUT, e.flags,
                          dev->ifindex);

        if (e.nhop != e.daddr && kaodv_expl_get(expl, e.nhop, &e))
            kaodv_expl_update(expl, e.daddr, e.nhop,
                              mod_state->ACTIVE_ROUTE_TIMEOUT, e.flags,
                              dev->ifindex);
    }
}

static unsigned int kaodv_hook(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct net *net = state->net;
    struct mod_state *mod_state = net_generic(net, net_id);
    struct expl_state *expl = &mod_state->expl_state;
    struct queue_state *queue = &mod_state->queue_state;
    struct netlink_state *netlink = &mod_state->netlink_state;

    unsigned int hooknum = state->hook;
    const struct net_device *in = state->in;
    const struct net_device *out = state->out;
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
    struct iphdr *iph = SKB_NETWORK_HDR_IPH(skb);
    struct expl_entry e;
    struct in_addr ifaddr, bcaddr;
    int res = 0;

    memset(&ifaddr, 0, sizeof(struct in_addr));
    memset(&bcaddr, 0, sizeof(struct in_addr));

    /* We are only interested in IP packets */
    if (iph == NULL)
        return NF_ACCEPT;

    /* We want AODV control messages to go through directly to the
     * AODV socket.... */
    if (iph && iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udph;

        udph = (struct udphdr *)((char *)iph + (iph->ihl << 2));

        if (ntohs(udph->dest) == AODV_PORT ||
            ntohs(udph->source) == AODV_PORT)
        {

#ifdef CONFIG_QUAL_THRESHOLD
            mod_state->qual = (skb)->iwq.qual;
            if (mod_state->qual_th && hooknum == NF_INET_PRE_ROUTING)
            {

                if (mod_state->qual && mod_state->qual < mod_state->qual_th)
                {
                    mod_state->pkts_dropped++;
                    return NF_DROP;
                }
            }
#endif /* CONFIG_QUAL_THRESHOLD */
            if (hooknum == NF_INET_PRE_ROUTING && in)
                kaodv_update_route_timeouts(mod_state, hooknum, in, iph);

            return NF_ACCEPT;
        }
    }

    if (hooknum == NF_INET_PRE_ROUTING)
        res = if_info_from_ifindex(mod_state, &ifaddr, &bcaddr, in->ifindex);
    else
        res = if_info_from_ifindex(mod_state, &ifaddr, &bcaddr, out->ifindex);

    if (res < 0)
        return NF_ACCEPT;

    /* Ignore broadcast and multicast packets */
    if (iph->daddr == INADDR_BROADCAST || IN_MULTICAST(ntohl(iph->daddr)) ||
        iph->daddr == bcaddr.s_addr)
        return NF_ACCEPT;

    /* Check which hook the packet is on... */
    switch (hooknum)
    {
    case NF_INET_PRE_ROUTING:
        kaodv_update_route_timeouts(mod_state, hooknum, in, iph);

        /* If we are a gateway maybe we need to decapsulate? */
        if (mod_state->is_gateway && iph->protocol == IPPROTO_MIPE &&
            iph->daddr == ifaddr.s_addr)
        {
            ip_pkt_decapsulate(skb);
            iph = SKB_NETWORK_HDR_IPH(skb);
            return NF_ACCEPT;
        }
        /* Ignore packets generated locally or that are for this
         * node. */
        if (iph->saddr == ifaddr.s_addr || iph->daddr == ifaddr.s_addr)
        {
            return NF_ACCEPT;
        }
        /* Check for unsolicited data packets */
        else if (!kaodv_expl_get(expl, iph->daddr, &e))
        {
            kaodv_netlink_send_rerr_msg(netlink, PKT_INBOUND, iph->saddr,
                                        iph->daddr, in->ifindex);
            return NF_DROP;
        }
        /* Check if we should repair the route */
        else if (e.flags & KAODV_RT_REPAIR)
        {

            kaodv_netlink_send_rt_msg(netlink, KAODVM_REPAIR, iph->saddr,
                                      iph->daddr);

            kaodv_queue_enqueue_packet(queue, skb, okfn);

            return NF_STOLEN;
        }
        break;
    case NF_INET_LOCAL_OUT:

        printk("kaodv NF_INET_LOCAL_OUT for %s", print_ip(iph->daddr));
        if (!kaodv_expl_get(expl, iph->daddr, &e) ||
            (e.flags & KAODV_RT_REPAIR))
        {

            if (!kaodv_queue_find(queue, iph->daddr))
                kaodv_netlink_send_rt_msg(netlink, KAODVM_ROUTE_REQ, 0,
                                          iph->daddr);

            kaodv_queue_enqueue_packet(queue, skb, okfn);

            return NF_STOLEN;
        }
        else if (e.flags & KAODV_RT_GW_ENCAP)
        {
            /* Make sure that also the virtual Internet
             * dest entry is refreshed */
            kaodv_update_route_timeouts(mod_state, hooknum, out, iph);

            skb = ip_pkt_encapsulate(net, skb, e.nhop);

            if (!skb)
                return NF_STOLEN;

            ip_route_me_harder(net, skb, RTN_LOCAL);
        }
        break;
    case NF_INET_POST_ROUTING:
        kaodv_update_route_timeouts(mod_state, hooknum, out, iph);
    }
    return NF_ACCEPT;
}

/*
 * Called when the module is inserted in the kernel.
 */
static char *ifnames[MAX_INTERFACES] = {"wlan0"};
static int ifnames_num = 0;
static int qual_th_default = 0;

module_param_array(ifnames, charp, &ifnames_num, 0444);
module_param(qual_th_default, int, 0);

static struct nf_hook_ops kaodv_ops[] = {
    {
        .hook = kaodv_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = kaodv_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER,
    },
    {
        .hook = kaodv_hook,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_FILTER,
    },
};

/*
//TODO
static ssize_t kaodv_read_proc(struct file *p_file, char *p_buf, size_t p_count,
                               loff_t *p_offset)
{
    int len;

    len = sprintf(
        p_buf,
        "qual threshold=%d\npkts dropped=%lu\nlast qual=%d\ngateway_mode=%d\n",
        mod_state->qual_th, mod_state->pkts_dropped, mod_state->qual,
mod_state->is_gateway);

    return len;
}*/

// TODO
// static const struct file_operations kaodv_proc_fops = {read :
// kaodv_read_proc};

static int __net_init kaodv_init_ns(struct net *net)
{
    struct mod_state *mod_state;
    struct net_device *dev = NULL;
    int i, ret = -ENOMEM;

    mod_state = net_generic(net, net_id);

    mod_state->qual = 0;
    mod_state->pkts_dropped = 0;
    mod_state->qual_th = qual_th_default;
    mod_state->is_gateway = 1;
    mod_state->active_route_timeout = 3000;
    mod_state->net = net;
    mod_state->ifilock = __RW_LOCK_UNLOCKED();
    INIT_LIST_HEAD(&mod_state->ifihead);

    kaodv_expl_init_ns(&mod_state->expl_state);

    ret = kaodv_queue_init_ns(&mod_state->queue_state);
    if (ret < 0)
        return ret;

    ret = kaodv_netlink_init_ns(&mod_state->netlink_state, net);

    if (ret < 0)
        goto cleanup_queue;

    ret = nf_register_net_hook(net, &kaodv_ops[0]);

    if (ret < 0)
        goto cleanup_netlink;

    ret = nf_register_net_hook(net, &kaodv_ops[1]);

    if (ret < 0)
        goto cleanup_hook0;

    ret = nf_register_net_hook(net, &kaodv_ops[2]);

    if (ret < 0)
        goto cleanup_hook1;

    /* Prefetch network device info (ip, broadcast address, ifindex). */
    for (i = 0; i < MAX_INTERFACES; i++)
    {
        if (!ifnames[i])
            break;

        printk("kaodv device %s available!\n", ifnames[i]);
        dev = dev_get_by_name(net, ifnames[i]);

        if (dev)
        {
            if_info_add(mod_state, dev);

            // release reference to dev
            dev_put(dev);
        }
        else
            printk("No device %s available, ignoring!\n", ifnames[i]);
    }

    // TODO
    // if (!proc_create("kaodv", 0, net->proc_net, &kaodv_proc_fops))
    //    KAODV_DEBUG(&mod_state->netlink_state, "Could not create kaodv proc
    //    entry");

    KAODV_DEBUG(&mod_state->netlink_state, "Module init OK");

    return ret;

cleanup_hook1:
    nf_unregister_net_hook(net, &kaodv_ops[1]);
cleanup_hook0:
    nf_unregister_net_hook(net, &kaodv_ops[0]);
cleanup_netlink:
    kaodv_netlink_fini_ns(&mod_state->netlink_state);
cleanup_queue:
    kaodv_queue_fini_ns(&mod_state->queue_state);

    return ret;
}

static void __net_exit kaodv_exit_ns(struct net *net)
{
    struct mod_state *mod_state;
    unsigned int i;

    mod_state = net_generic(net, net_id);

    if_info_purge(mod_state);

    for (i = 0; i < sizeof(kaodv_ops) / sizeof(struct nf_hook_ops); i++)
        nf_unregister_net_hook(net, &kaodv_ops[i]);

    // TODO
    // remove_proc_entry("kaodv", net->proc_net);

    kaodv_queue_fini_ns(&mod_state->queue_state);
    kaodv_expl_fini_ns(&mod_state->expl_state);
    kaodv_netlink_fini_ns(&mod_state->netlink_state);
}

// callback to make the module network namespace aware
static struct pernet_operations net_ops __net_initdata = {
    .init = kaodv_init_ns,
    .exit = kaodv_exit_ns,
    .id = &net_id,
    .size = sizeof(struct mod_state),
};

static int __init kaodv_init(void)
{
    int res;

    printk(KERN_INFO "kaodv_init called\n");

    res = register_pernet_subsys(&net_ops);

    if (res != 0)
        return res;

    res = kaodv_netlink_init();

    return res;
}

/*
 * Called when removing the module from memory...
 */
static void __exit kaodv_exit(void)
{
    printk(KERN_INFO "kaodv_exit called\n");
    kaodv_netlink_fini();
    unregister_pernet_subsys(&net_ops);
}

module_init(kaodv_init);
module_exit(kaodv_exit);
