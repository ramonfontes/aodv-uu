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
#include <linux/netlink.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>

#include "kaodv-debug.h"
#include "kaodv-mod.h"
#include "kaodv-netlink.h"
#include "kaodv-queue.h"
#include "kaodv.h"

static struct sk_buff *kaodv_netlink_build_msg(int type, void *data, int len)
{
    unsigned char *old_tail;
    size_t size = 0;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    void *m;

    size = NLMSG_SPACE(len);

    skb = alloc_skb(size, GFP_ATOMIC);

    if (!skb)
        goto nlmsg_failure;

    old_tail = SKB_TAIL_PTR(skb);
    nlh = nlmsg_put(skb, 0, 0, type, size - sizeof(*nlh), 0);

    m = NLMSG_DATA(nlh);

    memcpy(m, data, len);

    nlh->nlmsg_len = SKB_TAIL_PTR(skb) - old_tail;
    NETLINK_CB(skb).portid = 0; /* from kernel */

    return skb;

nlmsg_failure:
    if (skb)
        kfree_skb(skb);

    printk(KERN_ERR "kaodv: error creating rt timeout message\n");

    return NULL;
}

void kaodv_netlink_send_debug_msg(struct netlink_state *state, char *buf,
                                  int len)
{
    struct sk_buff *skb = NULL;

    skb = kaodv_netlink_build_msg(KAODVM_DEBUG, buf, len);

    if (skb == NULL)
    {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }

    netlink_broadcast(state->kaodvnl, skb, state->peer_pid, AODVGRP_NOTIFY,
                      GFP_USER);
}

void kaodv_netlink_send_rt_msg(struct netlink_state *state, int type, __u32 src,
                               __u32 dest)
{
    struct sk_buff *skb = NULL;
    struct kaodv_rt_msg m;

    memset(&m, 0, sizeof(m));

    m.src = src;
    m.dst = dest;

    skb = kaodv_netlink_build_msg(type, &m, sizeof(struct kaodv_rt_msg));

    if (skb == NULL)
    {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }

    /* 	netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
    netlink_broadcast(state->kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);
}

void kaodv_netlink_send_rt_update_msg(struct netlink_state *state, int type,
                                      __u32 src, __u32 dest, int ifindex)
{
    struct sk_buff *skb = NULL;
    struct kaodv_rt_msg m;

    memset(&m, 0, sizeof(m));

    m.type = type;
    m.src = src;
    m.dst = dest;
    m.ifindex = ifindex;

    skb = kaodv_netlink_build_msg(KAODVM_ROUTE_UPDATE, &m,
                                  sizeof(struct kaodv_rt_msg));

    if (skb == NULL)
    {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }
    /* netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
    netlink_broadcast(state->kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);
}

void kaodv_netlink_send_rerr_msg(struct netlink_state *state, int type,
                                 __u32 src, __u32 dest, int ifindex)
{
    struct sk_buff *skb = NULL;
    struct kaodv_rt_msg m;

    memset(&m, 0, sizeof(m));

    m.type = type;
    m.src = src;
    m.dst = dest;
    m.ifindex = ifindex;

    skb = kaodv_netlink_build_msg(KAODVM_SEND_RERR, &m,
                                  sizeof(struct kaodv_rt_msg));

    if (skb == NULL)
    {
        printk("kaodv_netlink: skb=NULL\n");
        return;
    }
    /* netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
    netlink_broadcast(state->kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);
}

static int kaodv_netlink_receive_peer(struct mod_state *mod_state,
                                      unsigned char type, void *msg,
                                      unsigned int len)
{
    struct expl_state *expl;
    struct netlink_state *netlink;
    int ret = 0;
    struct kaodv_rt_msg *m;
    struct kaodv_conf_msg *cm;
    struct expl_entry e;

    expl = &mod_state->expl_state;
    netlink = &mod_state->netlink_state;

    KAODV_DEBUG(netlink, "Received msg: %s", kaodv_msg_type_to_str(type));

    switch (type)
    {
    case KAODVM_ADDROUTE:
        if (len < sizeof(struct kaodv_rt_msg))
            return -EINVAL;

        m = (struct kaodv_rt_msg *)msg;

        ret = kaodv_expl_get(expl, m->dst, &e);

        if (ret < 0)
        {
            ret = kaodv_expl_update(expl, m->dst, m->nhop, m->time,
                                    m->flags, m->ifindex);
        }
        else
        {
            ret = kaodv_expl_add(expl, m->dst, m->nhop, m->time, m->flags,
                                 m->ifindex);
        }
        kaodv_queue_set_verdict(mod_state, KAODV_QUEUE_SEND, m->dst);
        break;
    case KAODVM_DELROUTE:
        if (len < sizeof(struct kaodv_rt_msg))
            return -EINVAL;

        m = (struct kaodv_rt_msg *)msg;
        kaodv_expl_del(expl, m->dst);
        kaodv_queue_set_verdict(mod_state, KAODV_QUEUE_DROP, m->dst);
        break;
    case KAODVM_NOROUTE_FOUND:
        if (len < sizeof(struct kaodv_rt_msg))
            return -EINVAL;

        m = (struct kaodv_rt_msg *)msg;
        KAODV_DEBUG(netlink, "No route found for %s", print_ip(m->dst));
        kaodv_queue_set_verdict(mod_state, KAODV_QUEUE_DROP, m->dst);
        break;
    case KAODVM_CONFIG:
        if (len < sizeof(struct kaodv_conf_msg))
            return -EINVAL;

        cm = (struct kaodv_conf_msg *)msg;
        mod_state->active_route_timeout = cm->active_route_timeout;
        mod_state->qual_th = cm->qual_th;
        mod_state->is_gateway = cm->is_gateway;
        break;
    default:
        printk("kaodv-netlink: Unknown message type\n");
        ret = -EINVAL;
    }
    return ret;
}

static int kaodv_netlink_rcv_nl_event(struct notifier_block *this,
                                      unsigned long event, void *ptr)
{
    struct mod_state *mod;
    struct expl_state *expl;
    struct queue_state *queue;
    struct netlink_state *netlink;
    struct netlink_notify *n = ptr;

    // access namespace state
    mod = net_generic(n->net, net_id);
    printk("kaodv: net_id %d", net_id);
    expl = &mod->expl_state;
    queue = &mod->queue_state;
    netlink = &mod->netlink_state;

    if (event == NETLINK_URELEASE && n->protocol == NETLINK_AODV && n->portid)
    {
        if (n->portid == netlink->peer_pid)
        {
            netlink->peer_pid = 0;
            kaodv_expl_flush(expl);
            kaodv_queue_flush(queue);
        }
        return NOTIFY_DONE;
    }
    return NOTIFY_DONE;
}

static struct notifier_block kaodv_nl_notifier = {
    .notifier_call = kaodv_netlink_rcv_nl_event,
};

#define RCV_SKB_FAIL(err)                   \
    do                                      \
    {                                       \
        netlink_ack(skb, nlh, (err), NULL); \
        return;                             \
    } while (0)

static inline void kaodv_netlink_rcv_skb(struct sk_buff *skb)
{
    struct mod_state *mod;
    struct netlink_state *netlink;

    int status, type, pid, flags, nlmsglen, skblen;
    struct nlmsghdr *nlh;

    skblen = skb->len;
    if (skblen < sizeof(struct nlmsghdr))
    {
        printk("skblen to small\n");
        return;
    }

    nlh = (struct nlmsghdr *)skb->data;
    nlmsglen = nlh->nlmsg_len;

    if (nlmsglen < sizeof(struct nlmsghdr) || skblen < nlmsglen)
    {
        printk("nlsmsg=%d skblen=%d to small\n", nlmsglen, skblen);
        return;
    }

    pid = nlh->nlmsg_pid;
    flags = nlh->nlmsg_flags;

    if (pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
        RCV_SKB_FAIL(-EINVAL);

    if (flags & MSG_TRUNC)
        RCV_SKB_FAIL(-ECOMM);

    type = nlh->nlmsg_type;

    /* 	printk("kaodv_netlink: type=%d\n", type); */
    /* if (type < NLMSG_NOOP || type >= IPQM_MAX) */
    /* 		RCV_SKB_FAIL(-EINVAL); */

    // write_lock_bh(&queue_lock);

    // access namespace state
    mod = net_generic(sock_net(skb->sk), net_id);
    netlink = &mod->netlink_state;

    if (netlink->peer_pid)
    {
        if (netlink->peer_pid != pid)
        {
            // write_unlock_bh(&queue_lock);
            RCV_SKB_FAIL(-EBUSY);
        }
    }
    else
        netlink->peer_pid = pid;

    // write_unlock_bh(&queue_lock);

    status = kaodv_netlink_receive_peer(mod, type, NLMSG_DATA(nlh),
                                        skblen - NLMSG_LENGTH(0));
    if (status < 0)
        RCV_SKB_FAIL(status);

    if (flags & NLM_F_ACK)
        netlink_ack(skb, nlh, 0, NULL);
}

static struct netlink_kernel_cfg kaodvnlcfg = {
    groups : AODVGRP_MAX,
    input : kaodv_netlink_rcv_skb,
    cb_mutex : NULL,
};

int kaodv_netlink_init(void)
{
    return netlink_register_notifier(&kaodv_nl_notifier);
}

void kaodv_netlink_fini(void)
{
    netlink_unregister_notifier(&kaodv_nl_notifier);
}

int kaodv_netlink_init_ns(struct netlink_state *state, struct net *net)
{
    state->kaodvnl = netlink_kernel_create(net, NETLINK_AODV, &kaodvnlcfg);

    if (state->kaodvnl == NULL)
    {
        printk(KERN_ERR "kaodv_netlink: failed to create netlink socket\n");
        return -1;
    }
    return 0;
}

void kaodv_netlink_fini_ns(struct netlink_state *state)
{
    netlink_kernel_release(state->kaodvnl);
}
