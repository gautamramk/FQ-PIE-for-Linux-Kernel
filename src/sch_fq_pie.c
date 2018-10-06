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


struct fq_pie_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	int		  deficit;
	u32		  dropped; /* number of drops (or ECN marks) on this flow */
	struct pie_vars pvars;
};

struct fq_pie_sched_data {
	u32 flows_cnt;
	struct fq_pie_flow *flows;
	u32 *backlogs;
	struct pie_params params;
	struct pie_stats stats;
}
static unsigned int fq_pie_hash(const struct fq_pie_sched_data *q,
				  struct sk_buff *skb)
{
	return reciprocal_scale(skb_get_hash(skb), q->flows_cnt);
}

static unsigned int fq_pie_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct tcf_proto *filter;
	struct tcf_result res;
	int result;

	if (TC_H_MAJ(skb->priority) == sch->handle &&
	    TC_H_MIN(skb->priority) > 0 &&
	    TC_H_MIN(skb->priority) <= q->flows_cnt)
		return TC_H_MIN(skb->priority);

	filter = rcu_dereference_bh(q->filter_list);
	if (!filter)
		return fq_pie_hash(q, skb) + 1;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	result = tcf_classify(skb, filter, &res, false);
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/* fall through */
		case TC_ACT_SHOT:
			return 0;
		}
#endif
		if (TC_H_MIN(res.classid) <= q->flows_cnt)
			return TC_H_MIN(res.classid);
	}
	return 0;
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
	u32 local_prob = flow->pvars.prob;
	u32 mtu = psched_mtu(qdisc_dev(sch));

	/* If there is still burst allowance left skip random early drop */
	if (flow->pvars.burst_time > 0)
		return false;

	/* If current delay is less than half of target, and
	 * if drop prob is low already, disable early_drop
	 */
	if ((q->pvars.qdelay < q->params.target / 2)
	    && (q->pvars.prob < MAX_PROB / 5))
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
		local_prob = flow->pvars.prob;

	rnd = prandom_u32();
	if (rnd < local_prob)
		return true;

	return false;
}

static int fq_pie_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	bool enqueue = false;

	idx = fq_codel_classify(skb, sch, &ret);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return ret;
	}
	idx--;

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, &q.flows[idx], skb->len)) {
		enqueue = true;
	} else if (q->params.ecn && (&q.flows[idx]->pvars.prob <= MAX_PROB / 10) &&
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

		flow_queue_add(skb, sch);
		return NET_XMIT_SUCCESS;
	}

out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
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
	/*qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		dropped += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_qdisc_drop(skb, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);*/

	sch_tree_unlock(sch);
	return 0;
}

static void pie_process_dequeue(struct Qdisc *sch, struct sk_buff *skb)
{

	struct pie_sched_data *q = qdisc_priv(sch);
	int qlen = sch->qstats.backlog;	/* current queue size in bytes */

	/* If current queue is about 10 packets or more and dq_count is unset
	 * we have enough packets to calculate the drain rate. Save
	 * current time as dq_tstamp and start measurement cycle.
	 */
	if (qlen >= QUEUE_THRESHOLD && q->vars.dq_count == DQCOUNT_INVALID) {
		q->vars.dq_tstamp = psched_get_time();
		q->vars.dq_count = 0;
	}

	/* Calculate the average drain rate from this value.  If queue length
	 * has receded to a small value viz., <= QUEUE_THRESHOLD bytes,reset
	 * the dq_count to -1 as we don't have enough packets to calculate the
	 * drain rate anymore The following if block is entered only when we
	 * have a substantial queue built up (QUEUE_THRESHOLD bytes or more)
	 * and we calculate the drain rate for the threshold here.  dq_count is
	 * in bytes, time difference in psched_time, hence rate is in
	 * bytes/psched_time.
	 */
	if (q->vars.dq_count != DQCOUNT_INVALID) {
		q->vars.dq_count += skb->len;

		if (q->vars.dq_count >= QUEUE_THRESHOLD) {
			psched_time_t now = psched_get_time();
			u32 dtime = now - q->vars.dq_tstamp;
			u32 count = q->vars.dq_count << PIE_SCALE;

			if (dtime == 0)
				return;

			count = count / dtime;

			if (q->vars.avg_dq_rate == 0)
				q->vars.avg_dq_rate = count;
			else
				q->vars.avg_dq_rate =
				    (q->vars.avg_dq_rate -
				     (q->vars.avg_dq_rate >> 3)) + (count >> 3);

			/* If the queue has receded below the threshold, we hold
			 * on to the last drain rate calculated, else we reset
			 * dq_count to 0 to re-enter the if block when the next
			 * packet is dequeued
			 */
			if (qlen < QUEUE_THRESHOLD)
				q->vars.dq_count = DQCOUNT_INVALID;
			else {
				q->vars.dq_count = 0;
				q->vars.dq_tstamp = psched_get_time();
			}

			if (q->vars.burst_time > 0) {
				if (q->vars.burst_time > dtime)
					q->vars.burst_time -= dtime;
				else
					q->vars.burst_time = 0;
			}
		}
	}
}

static void calculate_probability(struct Qdisc *sch)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	u32 qlen = sch->qstats.backlog;	/* queue size in bytes */
	psched_time_t qdelay = 0;	/* in pschedtime */
	psched_time_t qdelay_old = q->vars.qdelay;	/* in pschedtime */
	s32 delta = 0;		/* determines the change in probability */
	u32 oldprob;
	u32 alpha, beta;
	bool update_prob = true;

	q->vars.qdelay_old = q->vars.qdelay;

	if (q->vars.avg_dq_rate > 0)
		qdelay = (qlen << PIE_SCALE) / q->vars.avg_dq_rate;
	else
		qdelay = 0;

	/* If qdelay is zero and qlen is not, it means qlen is very small, less
	 * than dequeue_rate, so we do not update probabilty in this round
	 */
	if (qdelay == 0 && qlen != 0)
		update_prob = false;

	/* In the algorithm, alpha and beta are between 0 and 2 with typical
	 * value for alpha as 0.125. In this implementation, we use values 0-32
	 * passed from user space to represent this. Also, alpha and beta have
	 * unit of HZ and need to be scaled before they can used to update
	 * probability. alpha/beta are updated locally below by 1) scaling them
	 * appropriately 2) scaling down by 16 to come to 0-2 range.
	 * Please see paper for details.
	 *
	 * We scale alpha and beta differently depending on whether we are in
	 * light, medium or high dropping mode.
	 */
	if (q->vars.prob < MAX_PROB / 100) {
		alpha =
		    (q->params.alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 7;
		beta =
		    (q->params.beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 7;
	} else if (q->vars.prob < MAX_PROB / 10) {
		alpha =
		    (q->params.alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 5;
		beta =
		    (q->params.beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 5;
	} else {
		alpha =
		    (q->params.alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 4;
		beta =
		    (q->params.beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 4;
	}

	/* alpha and beta should be between 0 and 32, in multiples of 1/16 */
	delta += alpha * ((qdelay - q->params.target));
	delta += beta * ((qdelay - qdelay_old));

	oldprob = q->vars.prob;

	/* to ensure we increase probability in steps of no more than 2% */
	if (delta > (s32) (MAX_PROB / (100 / 2)) &&
	    q->vars.prob >= MAX_PROB / 10)
		delta = (MAX_PROB / 100) * 2;

	/* Non-linear drop:
	 * Tune drop probability to increase quickly for high delays(>= 250ms)
	 * 250ms is derived through experiments and provides error protection
	 */

	if (qdelay > (PSCHED_NS2TICKS(250 * NSEC_PER_MSEC)))
		delta += MAX_PROB / (100 / 2);

	q->vars.prob += delta;

	if (delta > 0) {
		/* prevent overflow */
		if (q->vars.prob < oldprob) {
			q->vars.prob = MAX_PROB;
			/* Prevent normalization error. If probability is at
			 * maximum value already, we normalize it here, and
			 * skip the check to do a non-linear drop in the next
			 * section.
			 */
			update_prob = false;
		}
	} else {
		/* prevent underflow */
		if (q->vars.prob > oldprob)
			q->vars.prob = 0;
	}

	/* Non-linear drop in probability: Reduce drop probability quickly if
	 * delay is 0 for 2 consecutive Tupdate periods.
	 */

	if ((qdelay == 0) && (qdelay_old == 0) && update_prob)
		q->vars.prob = (q->vars.prob * 98) / 100;

	q->vars.qdelay = qdelay;
	q->vars.qlen_old = qlen;

	/* We restart the measurement cycle if the following conditions are met
	 * 1. If the delay has been low for 2 consecutive Tupdate periods
	 * 2. Calculated drop probability is zero
	 * 3. We have atleast one estimate for the avg_dq_rate ie.,
	 *    is a non-zero value
	 */
	if ((q->vars.qdelay < q->params.target / 2) &&
	    (q->vars.qdelay_old < q->params.target / 2) &&
	    (q->vars.prob == 0) &&
	    (q->vars.avg_dq_rate > 0))
		pie_vars_init(&q->vars);
}



static int fq_pie_init(struct Qdisc *sch, struct nlattr *opt,
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

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;

}

static int fq_pie_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
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

static struct sk_buff *fq_pie_qdisc_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	skb = qdisc_dequeue_head(sch);

	if (!skb)
		return NULL;

	pie_process_dequeue(sch, skb);
	return skb;
}

static void fq_pie_reset(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	qdisc_reset_queue(sch);
	fq_pie_vars_init(&q->vars);
}

static void fq_pie_destroy(struct Qdisc *sch)
{
	struct pie_sched_data *q = qdisc_priv(sch);
	q->params.tupdate = 0;
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
