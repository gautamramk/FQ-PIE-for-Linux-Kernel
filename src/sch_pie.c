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
#include <net/pie.h>

#define QUEUE_THRESHOLD 10000
#define DQCOUNT_INVALID -1
#define MAX_PROB  0xffffffff
#define PIE_SCALE 8
static bool drop_early(struct Qdisc *sch, u32 packet_size)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	u32 rnd;
	u32 local_prob = q->vars.prob;
	u32 mtu = psched_mtu(qdisc_dev(sch));

	/* If there is still burst allowance left skip random early drop */
	if (q->vars.burst_time > 0)
		return false;

	/* If current delay is less than half of target, and
	 * if drop prob is low already, disable early_drop
	 */
	if ((q->vars.qdelay < q->params.target / 2)
	    && (q->vars.prob < MAX_PROB / 5))
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
		local_prob = q->vars.prob;

	rnd = prandom_u32();
	if (rnd < local_prob)
		return true;

	return false;
}

static int pie_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	bool enqueue = false;

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, skb->len)) {
		enqueue = true;
	} else if (q->params.ecn && (q->vars.prob <= MAX_PROB / 10) &&
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

		return qdisc_enqueue_tail(skb, sch);
	}

out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
}

static const struct nla_policy pie_policy[TCA_PIE_MAX + 1] = {
	[TCA_PIE_TARGET] = {.type = NLA_U32},
	[TCA_PIE_LIMIT] = {.type = NLA_U32},
	[TCA_PIE_TUPDATE] = {.type = NLA_U32},
	[TCA_PIE_ALPHA] = {.type = NLA_U32},
	[TCA_PIE_BETA] = {.type = NLA_U32},
	[TCA_PIE_ECN] = {.type = NLA_U32},
	[TCA_PIE_BYTEMODE] = {.type = NLA_U32},
};

static int pie_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_PIE_MAX + 1];
	unsigned int qlen, dropped = 0;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_PIE_MAX, opt, pie_policy, NULL);
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
	if (tb[TCA_PIE_TUPDATE])
		q->params.tupdate = usecs_to_jiffies(nla_get_u32(tb[TCA_PIE_TUPDATE]));

	if (tb[TCA_PIE_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_PIE_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_PIE_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_PIE_ALPHA]);

	if (tb[TCA_PIE_BETA])
		q->params.beta = nla_get_u32(tb[TCA_PIE_BETA]);

	if (tb[TCA_PIE_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_PIE_ECN]);

	if (tb[TCA_PIE_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_PIE_BYTEMODE]);

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		dropped += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_qdisc_drop(skb, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	sch_tree_unlock(sch);
	return 0;
}

static void pie_timer(struct timer_list *t)
{
	struct pie_sched_data *q = from_timer(q, t, adapt_timer);
	struct Qdisc *sch = q->sch;
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));
	u32 qlen=sch->qstats.backlog;
	spin_lock(root_lock);
	calculate_probability(qlen,&q->params,&q->vars); 

	/* reset the timer to fire after 'tupdate'. tupdate is in jiffies. */
	if (q->params.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.tupdate);
	spin_unlock(root_lock);

}

static int pie_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct pie_sched_data *q = qdisc_priv(sch);

	pie_params_init(&q->params);
	pie_vars_init(&q->vars);
	sch->limit = q->params.limit;

	q->sch = sch;
	timer_setup(&q->adapt_timer, pie_timer, 0);

	if (opt) {
		int err = pie_change(sch, opt, extack);

		if (err)
			return err;
	}

	mod_timer(&q->adapt_timer, jiffies + HZ / 2);
	return 0;
}

static int pie_dump(struct Qdisc *sch, struct sk_buff *skb)
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

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;

}

static int pie_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	struct tc_pie_xstats st = {
		.prob		= q->vars.prob,
		.delay		= ((u32) PSCHED_TICKS2NS(q->vars.qdelay)) /
				   NSEC_PER_USEC,
		/* unscale and return dq_rate in bytes per sec */
		.avg_dq_rate	= q->vars.avg_dq_rate *
				  (PSCHED_TICKS_PER_SEC) >> PIE_SCALE,
		.packets_in	= q->stats.packets_in,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.dropped	= q->stats.dropped,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *pie_qdisc_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	skb = qdisc_dequeue_head(sch);

	if (!skb)
		return NULL;

	struct pie_sched_data *q = qdisc_priv(sch);
	u32 qlen=sch->qstats.backlog;
	pie_process_dequeue(qlen,&q->vars, skb);
	return skb;
}

static void pie_reset(struct Qdisc *sch)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	qdisc_reset_queue(sch);
	pie_vars_init(&q->vars);
}

static void pie_destroy(struct Qdisc *sch)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	q->params.tupdate = 0;
	del_timer_sync(&q->adapt_timer);
}

static struct Qdisc_ops pie_qdisc_ops __read_mostly = {
	.id = "pie",
	.priv_size	= sizeof(struct pie_sched_data),
	.enqueue	= pie_qdisc_enqueue,
	.dequeue	= pie_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= pie_init,
	.destroy	= pie_destroy,
	.reset		= pie_reset,
	.change		= pie_change,
	.dump		= pie_dump,
	.dump_stats	= pie_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init pie_module_init(void)
{
	return register_qdisc(&pie_qdisc_ops);
}

static void __exit pie_module_exit(void)
{
	unregister_qdisc(&pie_qdisc_ops);
}

module_init(pie_module_init);
module_exit(pie_module_exit);

MODULE_DESCRIPTION("Proportional Integral controller Enhanced (PIE) scheduler");
MODULE_AUTHOR("Vijay Subramanian");
MODULE_AUTHOR("Mythili Prabhu");
MODULE_LICENSE("GPL");
