/* Copyright (C) 2013 Cisco Systems, Inc, 2013.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: Vijay Subramanian <vijaynsu@cisco.com>
 * Author: Mythili Prabhu <mysuryan@cisco.com>
 *
 * ECN support is added by Naeem Khademi <naeemk@ifi.uio.no>
 * University of Oslo, Norway.
 *
 * References:
 * IETF draft submission: http://tools.ietf.org/html/draft-pan-aqm-pie-00
 * IEEE  Conference on High Performance Switching and Routing 2013 :
 * "PIE: A * Lightweight Control Scheme to Address the Bufferbloat Problem"
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include "pie.h"

struct fq_pie_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	int		  deficit;
	u32		  dropped; /* number of drops (or ECN marks) on this flow */
	struct pie_vars vars;
};

struct fq_pie_sched_data {
	u32 flows_cnt;
	u32 quantum;
	struct fq_pie_flow *flows;
	u32 *backlogs;
	struct pie_params params;
	struct pie_stats stats;
	u32 new_flow_count;
	struct Qdisc *sch;
	struct timer_list adapt_timer;

	struct list_head old_flows;
	struct list_head new_flows;
};
static unsigned int fq_pie_hash(const struct fq_pie_sched_data *q,
				  struct sk_buff *skb)
{
	return reciprocal_scale(skb_get_hash(skb), q->flows_cnt);
}

static unsigned int fq_pie_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	//struct tcf_proto *filter;
	//struct tcf_result res;
	int result;

	if (TC_H_MAJ(skb->priority) == sch->handle &&
	    TC_H_MIN(skb->priority) > 0 &&
	    TC_H_MIN(skb->priority) <= q->flows_cnt)
		return TC_H_MIN(skb->priority);

	//filter = rcu_dereference_bh(q->filter_list);
	//if (!filter)
	return fq_pie_hash(q, skb) + 1;

	/**qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	result = tcf_classify(skb, filter, &res, false);
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/* fall through 
		case TC_ACT_SHOT:
			return 0;
		}
#endif
		if (TC_H_MIN(res.classid) <= q->flows_cnt)
			return TC_H_MIN(res.classid);
	}
	return 0;*/
}

static inline void flow_queue_add(struct fq_pie_flow *flow,
				  struct sk_buff *skb)
{
	if (flow->head == NULL)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static bool drop_early(struct Qdisc *sch, struct fq_pie_flow *flow, u32 packet_size)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	u32 rnd;
	u32 local_prob = flow->vars.prob;
	u32 mtu = psched_mtu(qdisc_dev(sch));

	/* If there is still burst allowance left skip random early drop */
	if (flow->vars.burst_time > 0)
		return false;

	/* If current delay is less than half of target, and
	 * if drop prob is low already, disable early_drop
	 */
	if ((flow->vars.qdelay < q->params.target / 2)
	    && (flow->vars.prob < MAX_PROB / 5))
		return false;

	/* If we have fewer than 2 mtu-sized packets, disable drop_early,
	 * similar to min_th in RED
	 */
	if (sch->qstats.backlog < 2 * mtu)
		return false;

	/* If bytemode is turned on, use packet size to compute new
	 * probablity. Smaller packets will have lower drop prob in this case
	 */
	if (q->params.bytemode && packet_size <= mtu)
		local_prob = (local_prob / mtu) * packet_size;
	else
		local_prob = flow->vars.prob;

	rnd = prandom_u32();
	if (rnd < local_prob)
		return true;

	return false;
}

static int fq_pie_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	bool enqueue = false;
	int ret;
	struct fq_pie_flow *sel_flow;
	int idx;
	idx = fq_pie_classify(skb, sch, &ret);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return ret;
	}
	idx--;
	
	sel_flow = &q->flows[idx];

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, sel_flow, skb->len)) {
		enqueue = true;
	} else if (q->params.ecn && (sel_flow->vars.prob <= MAX_PROB / 10) &&
		   INET_ECN_set_ce(skb)) {
		/* If packet is ecn capable, mark it if drop probability
		 * is lower than 10%, else drop it.
		 */
		q->stats.ecn_mark++;
		enqueue = true;
	}

	/* we can enqueue the packet */
	if (enqueue) {
		q->stats.packets_in++;
		if (qdisc_qlen(sch) > q->stats.maxq)
			q->stats.maxq = qdisc_qlen(sch);

		flow_queue_add(sel_flow, skb);

		if (list_empty(&sel_flow->flowchain)) {
			list_add_tail(&sel_flow->flowchain, &q->new_flows);
			q->new_flow_count++;
			sel_flow->deficit = q->quantum;
			sel_flow->dropped = 0;
		}
		return NET_XMIT_SUCCESS;
	}

out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch);
	//return qdisc_drop(skb, sch, to_free);
}

static inline struct sk_buff *dequeue_head(struct fq_pie_flow *flow)
{
	struct sk_buff *skb = flow->head;

	flow->head = skb->next;
	skb->next = NULL;
	return skb;
}

static struct sk_buff *fq_pie_qdisc_dequeue(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	skb = qdisc_dequeue_head(sch);
	struct fq_pie_flow *flow;
	struct list_head *head;

begin:
	head = &q->new_flows;
	if(list_empty(head)){
		head = &q->old_flows;
		if (list_empty(head)){
			return NULL;
		}
	}
	flow = list_first_entry(head, struct fq_pie_flow, flowchain);

	if (flow-> deficit <= 0) {
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->old_flows);
		goto begin;
	}

	if (flow->head) {
		skb = dequeue_head(flow);
		q->backlogs[flow - q->flows] -= qdisc_pkt_len(skb);
		sch->qstats.backlog -= qdisc_pkt_len(skb);
		sch->q.qlen--;
	}

	if (!skb) {
		if (!list_empty(&q->old_flows))
			list_move_tail(&flow->flowchain, &q->old_flows);
		else
			list_del_init(&flow->flowchain);
		goto begin;
	}

	flow->deficit -= qdisc_pkt_len(skb);
	pie_process_dequeue(sch, &flow->vars, skb);
	return skb;
}

static void fq_pie_timer(struct timer_list *t)
{
	struct fq_pie_sched_data *q = from_timer(q, t, adapt_timer);
	struct Qdisc *sch = q->sch;
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));
	int i;

	spin_lock(root_lock);

    for(i = 0; i < q->flows_cnt; i++){
		calculate_probability(sch, &q->flows[i].vars);
	}
	
	/* reset the timer to fire after 'tupdate'. tupdate is in jiffies. */
	if (q->params.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.tupdate);
	spin_unlock(root_lock);

}

static const struct nla_policy fq_pie_policy[TCA_FQ_PIE_MAX + 1] = {
	[TCA_FQ_PIE_TARGET] = {.type = NLA_U32},
	[TCA_FQ_PIE_LIMIT] = {.type = NLA_U32},
	[TCA_FQ_PIE_TUPDATE] = {.type = NLA_U32},
	[TCA_FQ_PIE_ALPHA] = {.type = NLA_U32},
	[TCA_FQ_PIE_BETA] = {.type = NLA_U32},
	[TCA_FQ_PIE_ECN] = {.type = NLA_U32},
	[TCA_FQ_PIE_BYTEMODE] = {.type = NLA_U32},
};

static int fq_pie_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_PIE_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_FQ_PIE_MAX, opt, fq_pie_policy, NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	/* convert from microseconds to pschedtime */
	if (tb[TCA_PIE_TARGET]) {
		/* target is in us */
		u32 target = nla_get_u32(tb[TCA_PIE_TARGET]);

		/* convert to pschedtime */
		q->params.target = PSCHED_NS2TICKS((u64)target * NSEC_PER_USEC);
	}

	/* tupdate is in jiffies */
	if (tb[TCA_FQ_PIE_TUPDATE])
		q->params.tupdate = usecs_to_jiffies(nla_get_u32(tb[TCA_PIE_TUPDATE]));

	if (tb[TCA_FQ_PIE_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_PIE_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_FQ_PIE_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_PIE_ALPHA]);

	if (tb[TCA_FQ_PIE_BETA])
		q->params.beta = nla_get_u32(tb[TCA_PIE_BETA]);

	if (tb[TCA_FQ_PIE_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_PIE_ECN]);

	if (tb[TCA_FQ_PIE_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_PIE_BYTEMODE]);

	/* Drop excess packets if new limit is lower */
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_pie_qdisc_dequeue(sch);
		kfree_skb(skb);
		qdisc_tree_decrease_qlen(sch, 1);
	}

	sch_tree_unlock(sch);
	return 0;
}

static int fq_pie_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);

	pie_params_init(&q->params);
	//pie_vars_init(&q->vars);
	sch->limit = q->params.limit;

	sch->limit = 10*1024;
	q->flows_cnt = 1024;
	q->quantum = psched_mtu(qdisc_dev(sch));
	q->sch = sch;

	INIT_LIST_HEAD(&q->new_flows);
	INIT_LIST_HEAD(&q->old_flows);

	timer_setup(&q->adapt_timer, fq_pie_timer, 0);
	mod_timer(&q->adapt_timer, jiffies + HZ / 2);
	int err;
	int i;

	if (opt) {
		int err = fq_pie_change(sch, opt, extack);

		if (err)
			return err;
	}

	if (!q->flows) {
		q->flows = kvcalloc(q->flows_cnt,
				    sizeof(struct fq_pie_flow),
				    GFP_KERNEL);
		if (!q->flows) {
			err = -ENOMEM;
			goto init_failure;
		}
		q->backlogs = kvcalloc(q->flows_cnt, sizeof(u32), GFP_KERNEL);
		if (!q->backlogs) {
			err = -ENOMEM;
			goto alloc_failure;
		}
		for (i = 0; i < q->flows_cnt; i++) {
			struct fq_pie_flow *flow = q->flows + i;

			INIT_LIST_HEAD(&flow->flowchain);
			pie_vars_init(&flow->vars);
		}
	}

	
	return 0;

alloc_failure:
	kvfree(q->flows);
	q->flows = NULL;

init_failure:
	q->flows_cnt = 0;
	return err;
}

static int fq_pie_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* convert target from pschedtime to us */
	if (nla_put_u32(skb, TCA_PIE_TARGET,
			((u32) PSCHED_TICKS2NS(q->params.target)) /
			NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_PIE_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_PIE_TUPDATE, jiffies_to_usecs(q->params.tupdate)) ||
	    nla_put_u32(skb, TCA_PIE_ALPHA, q->params.alpha) ||
	    nla_put_u32(skb, TCA_PIE_BETA, q->params.beta) ||
	    nla_put_u32(skb, TCA_PIE_ECN, q->params.ecn) ||
	    nla_put_u32(skb, TCA_PIE_BYTEMODE, q->params.bytemode))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);struct fq_pie_flow *flow;
	struct list_head *head;

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;

}

static int fq_pie_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	struct tc_pie_xstats st = {
		//.prob		= q->vars.prob,
		//.delay		= ((u32) PSCHED_TICKS2NS(q->vars.qdelay)) /
				   NSEC_PER_USEC,
		/* unscale and return dq_rate in bytes per sec */
		//.avg_dq_rate	= q->vars.avg_dq_rate *
		//		  (PSCHED_TICKS_PER_SEC) >> PIE_SCALE,
		.packets_in	= q->stats.packets_in,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.dropped	= q->stats.dropped,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static void flow_reset(struct fq_pie_flow *flow)
{
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
	flow->tail = NULL;
}

static void fq_pie_reset(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	
	INIT_LIST_HEAD(&q->new_flows);
	INIT_LIST_HEAD(&q->old_flows);
	int i;

	for(i = 0; i < q->flows_cnt; i++) {
		struct fq_pie_flow *flow = q->flows + i;

		flow_reset(flow);
		INIT_LIST_HEAD(&flow->flowchain);
		pie_vars_init(&flow->vars);
	}
	memset(q->backlogs, 0, q->flows_cnt * sizeof(u32));
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
}

static void fq_pie_destroy(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);

	q->params.tupdate = 0;
	kvfree(q->backlogs);
	kvfree(q->flows);
	del_timer_sync(&q->adapt_timer);
}

static struct Qdisc_ops fq_pie_qdisc_ops __read_mostly = {
	.id = "fq_pie",
	.priv_size	= sizeof(struct fq_pie_sched_data),
	.enqueue	= fq_pie_qdisc_enqueue,
	.dequeue	= fq_pie_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= fq_pie_init,
	.destroy	= fq_pie_destroy,
	.reset		= fq_pie_reset,
	.change		= fq_pie_change,
	.dump		= fq_pie_dump,
	.dump_stats	= fq_pie_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init fq_pie_module_init(void)
{
	return register_qdisc(&fq_pie_qdisc_ops);
}

static void __exit fq_pie_module_exit(void)
{
	unregister_qdisc(&fq_pie_qdisc_ops);
}

module_init(fq_pie_module_init);
module_exit(fq_pie_module_exit);

MODULE_DESCRIPTION("Flow Queue Proportional Integral controller Enhanced (FQ-PIE) scheduler");
MODULE_AUTHOR("Gautam Ramakrishnan");
MODULE_AUTHOR("V Saicharan");
MODULE_AUTHOR("Mohit Bhasi");
MODULE_LICENSE("GPL");