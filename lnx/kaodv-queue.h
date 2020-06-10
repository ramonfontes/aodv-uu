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
#ifndef _KAODV_QUEUE_H
#define _KAODV_QUEUE_H

#define KAODV_QUEUE_DROP 1
#define KAODV_QUEUE_SEND 2

#include <linux/list.h>

struct mod_state;

struct queue_state {
    unsigned int queue_maxlen;
    rwlock_t queue_lock;
    unsigned int queue_total;
    struct list_head queue_list;
};

int kaodv_queue_find(struct queue_state *state, __u32 daddr);
int kaodv_queue_enqueue_packet(struct queue_state *state, struct sk_buff *skb,
                               int (*okfn)(struct net *, struct sock *,
                                           struct sk_buff *));
int kaodv_queue_set_verdict(struct mod_state *mod_state, int verdict,
                            __u32 daddr);
void kaodv_queue_flush(struct queue_state *state);
int kaodv_queue_init_ns(struct queue_state *state);
void kaodv_queue_fini_ns(struct queue_state *state);

#endif
