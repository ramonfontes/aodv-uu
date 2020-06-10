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
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <net/icmp.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/sock.h>

#include "kaodv-expl.h"
#include "kaodv-ipenc.h"
#include "kaodv-mod.h"
#include "kaodv-netlink.h"
#include "kaodv-queue.h"
#include "kaodv.h"
/*
 * This is basically a shameless rippoff of the linux kernel's ip_queue module.
 */

#define KAODV_QUEUE_QMAX_DEFAULT 1024
#define KAODV_QUEUE_PROC_FS_NAME "kaodv_queue"
#define NET_KAODV_QUEUE_QMAX 2088
#define NET_KAODV_QUEUE_QMAX_NAME "kaodv_queue_maxlen"

struct kaodv_rt_info {
    __u8 tos;
    __u32 daddr;
    __u32 saddr;
};

struct kaodv_queue_entry {
    struct list_head list;
    struct sk_buff *skb;
    int (*okfn)(struct net *, struct sock *, struct sk_buff *);
    struct kaodv_rt_info rt_info;
};

typedef int (*kaodv_queue_cmpfn)(struct kaodv_queue_entry *, unsigned long);

static inline int __kaodv_queue_enqueue_entry(struct queue_state *queue,
                                              struct kaodv_queue_entry *entry)
{
    if (queue->queue_total >= queue->queue_maxlen) {
        if (net_ratelimit())
            printk(KERN_WARNING "kaodv-queue: full at %d entries, "
                                "dropping packet(s).\n",
                   queue->queue_total);
        return -ENOSPC;
    }
    list_add(&entry->list, &queue->queue_list);
    queue->queue_total++;
    return 0;
}

/*
 * Find and return a queued entry matched by cmpfn, or return the last
 * entry if cmpfn is NULL.
 */
static inline struct kaodv_queue_entry *
__kaodv_queue_find_entry(struct queue_state *queue, kaodv_queue_cmpfn cmpfn,
                         unsigned long data)
{
    struct list_head *p;

    list_for_each_prev(p, &queue->queue_list)
    {
        struct kaodv_queue_entry *entry = (struct kaodv_queue_entry *)p;

        if (!cmpfn || cmpfn(entry, data))
            return entry;
    }
    return NULL;
}

static inline struct kaodv_queue_entry *
__kaodv_queue_find_dequeue_entry(struct queue_state *queue,
                                 kaodv_queue_cmpfn cmpfn, unsigned long data)
{
    struct kaodv_queue_entry *entry;

    entry = __kaodv_queue_find_entry(queue, cmpfn, data);
    if (entry == NULL)
        return NULL;

    list_del(&entry->list);
    queue->queue_total--;

    return entry;
}

static inline void __kaodv_queue_flush(struct queue_state *queue)
{
    struct kaodv_queue_entry *entry;

    while ((entry = __kaodv_queue_find_dequeue_entry(queue, NULL, 0))) {
        kfree_skb(entry->skb);
        kfree(entry);
    }
}

static inline void __kaodv_queue_reset(struct queue_state *state)
{
    __kaodv_queue_flush(state);
}

static struct kaodv_queue_entry *
kaodv_queue_find_dequeue_entry(struct queue_state *queue,
                               kaodv_queue_cmpfn cmpfn, unsigned long data)
{
    struct kaodv_queue_entry *entry;

    write_lock_bh(&queue->queue_lock);
    entry = __kaodv_queue_find_dequeue_entry(queue, cmpfn, data);
    write_unlock_bh(&queue->queue_lock);
    return entry;
}

void kaodv_queue_flush(struct queue_state *queue)
{
    write_lock_bh(&queue->queue_lock);
    __kaodv_queue_flush(queue);
    write_unlock_bh(&queue->queue_lock);
}

int kaodv_queue_enqueue_packet(struct queue_state *queue, struct sk_buff *skb,
                               int (*okfn)(struct net *, struct sock *,
                                           struct sk_buff *))
{
    int status = -EINVAL;
    struct kaodv_queue_entry *entry;
    struct iphdr *iph = SKB_NETWORK_HDR_IPH(skb);

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);

    if (entry == NULL) {
        printk(KERN_ERR "kaodv_queue: OOM in kaodv_queue_enqueue_packet()\n");
        return -ENOMEM;
    }

    /* printk("enquing packet queue_len=%d\n", queue_total); */
    entry->okfn = okfn;
    entry->skb = skb;
    entry->rt_info.tos = iph->tos;
    entry->rt_info.daddr = iph->daddr;
    entry->rt_info.saddr = iph->saddr;

    write_lock_bh(&queue->queue_lock);

    status = __kaodv_queue_enqueue_entry(queue, entry);

    if (status < 0)
        goto err_out_unlock;

    write_unlock_bh(&queue->queue_lock);
    return status;

err_out_unlock:
    write_unlock_bh(&queue->queue_lock);
    kfree(entry);

    return status;
}

static inline int dest_cmp(struct kaodv_queue_entry *e, unsigned long daddr)
{
    return (daddr == e->rt_info.daddr);
}

int kaodv_queue_find(struct queue_state *queue, __u32 daddr)
{
    struct kaodv_queue_entry *entry;
    int res = 0;

    read_lock_bh(&queue->queue_lock);
    entry = __kaodv_queue_find_entry(queue, dest_cmp, daddr);
    if (entry != NULL)
        res = 1;

    read_unlock_bh(&queue->queue_lock);
    return res;
}

int kaodv_queue_set_verdict(struct mod_state *mod, int verdict, __u32 daddr)
{
    struct kaodv_queue_entry *entry;
    int pkts = 0;

    if (verdict == KAODV_QUEUE_DROP) {

        while (1) {
            entry = kaodv_queue_find_dequeue_entry(&mod->queue_state, dest_cmp,
                                                   daddr);

            if (entry == NULL)
                return pkts;

            /* Send an ICMP message informing the application that the
             * destination was unreachable. */
            if (pkts == 0)
                icmp_send(entry->skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

            kfree_skb(entry->skb);
            kfree(entry);
            pkts++;
        }
    } else if (verdict == KAODV_QUEUE_SEND) {
        struct expl_entry e;

        while (1) {
            entry = kaodv_queue_find_dequeue_entry(&mod->queue_state, dest_cmp,
                                                   daddr);

            if (entry == NULL)
                return pkts;

            if (!kaodv_expl_get(&mod->expl_state, daddr, &e)) {
                kfree_skb(entry->skb);
                goto next;
            }
            if (e.flags & KAODV_RT_GW_ENCAP) {

                entry->skb = ip_pkt_encapsulate(mod->net, entry->skb, e.nhop);
                if (!entry->skb)
                    goto next;
            }

            ip_route_me_harder(mod->net, entry->skb, RTN_LOCAL);

            pkts++;

            /* Inject packet */
            entry->okfn(NULL, NULL, entry->skb);
        next:
            kfree(entry);
        }
    }
    return 0;
}

/*
//TODO
static ssize_t kaodv_queue_get_info(struct file *p_file, char *p_buf,
                                    size_t p_count, loff_t *p_offset)
{
    struct queue_state *state = &mod_state->queue_state;
    int len;

    read_lock_bh(&state->queue_lock);

    len = sprintf(p_buf,
                  "Queue length      : %u\n"
                  "Queue max. length : %u\n",
                  state->queue_total, state->queue_maxlen);

    read_unlock_bh(&state->queue_lock);

    return len;
}*/

// TODO
// static const struct file_operations kaodv_proc_fops = {
//    read : kaodv_queue_get_info
//};

static int init_or_cleanup(struct queue_state *state, int init)
{
    int status = -ENOMEM;
    // struct proc_dir_entry *proc;

    if (!init)
        goto cleanup;

    /*
        //TODO
        proc = proc_create(KAODV_QUEUE_PROC_FS_NAME, 0, state->net->proc_net,
                           &kaodv_proc_fops);

        if (!proc) {
            printk(KERN_ERR "kaodv_queue: failed to create proc entry\n");
            return -1;
        }
    */
    return 1;

cleanup:
    synchronize_net();
    kaodv_queue_flush(state);

    // remove_proc_entry(KAODV_QUEUE_PROC_FS_NAME, state->net->proc_net);

    return status;
}

int kaodv_queue_init_ns(struct queue_state *state)
{
    state->queue_maxlen = KAODV_QUEUE_QMAX_DEFAULT;
    state->queue_lock = __RW_LOCK_UNLOCKED();
    state->queue_total = 0;
    INIT_LIST_HEAD(&state->queue_list);

    return init_or_cleanup(state, 1);
}

void kaodv_queue_fini_ns(struct queue_state *state)
{
    init_or_cleanup(state, 0);
}
