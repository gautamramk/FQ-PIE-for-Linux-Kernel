#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/pie.h>

struct fq_pie_stats {
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to fq_pie action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u32 ecn_mark;		/* packets marked with ECN */
	u32 new_flow_count; /* number of time packets created a new flow */
};

struct fq_pie_params {
	struct pie_params params_pie;
	u32 ecn_prob;
	u32 flows_cnt;
};

struct fq_pie_flow {
	struct sk_buff *head;
	struct sk_buff *tail;
	struct list_head flowchain;
	s32 deficit;
	u32 backlog;
	u32 qlen;
	struct pie_vars vars;
	struct pie_stats stats;
};

struct fq_pie_sched_data {
	u32 quantum;
	struct fq_pie_flow *flows;
	struct fq_pie_params params;
	struct fq_pie_stats stats;
	struct Qdisc *sch;
	struct timer_list adapt_timer;
	struct list_head old_flows;
	struct list_head new_flows;
};

static unsigned int fq_pie_hash(const struct fq_pie_sched_data *q,
				struct sk_buff *skb)
{
	return reciprocal_scale(skb_get_hash(skb), q->params.flows_cnt);
}

static unsigned int fq_pie_classify(struct sk_buff *skb, struct Qdisc *sch,
				    int *qerr)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);

	return fq_pie_hash(q, skb) + 1;
}

static inline void flow_queue_add(struct fq_pie_flow *flow,
				  struct sk_buff *skb)
{
	if (!flow->head)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static int fq_pie_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				struct sk_buff **to_free)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct fq_pie_flow *sel_flow;
	int uninitialized_var(ret);
	u32 uninitialized_var(pkt_len);
	u32 idx;
	u8 enqueue = false;

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
		sel_flow->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, sel_flow->backlog, &sel_flow->vars,
			&q->params.params_pie, skb->len)) {
		enqueue = true;
	} else if (q->params.params_pie.ecn &&
		   sel_flow->vars.prob <= (MAX_PROB / 100) * q->params.ecn_prob &&
		   INET_ECN_set_ce(skb)) {
		/* If packet is ecn capable, mark it if drop probability
		 * is lower than the parameter ecn_prob, else drop it.
		 */
		q->stats.ecn_mark++;
		sel_flow->stats.ecn_mark++;
		enqueue = true;
	}
	if (enqueue) {
		pkt_len = qdisc_pkt_len(skb);
		q->stats.packets_in++;
		sch->qstats.backlog += pkt_len;
		sch->q.qlen++;
		flow_queue_add(sel_flow, skb);
		if (list_empty(&sel_flow->flowchain)) {
			list_add_tail(&sel_flow->flowchain, &q->new_flows);
			q->stats.new_flow_count++;
			sel_flow->deficit = q->quantum;
			sel_flow->stats.dropped = 0;
			sel_flow->qlen = 0;
			sel_flow->backlog = 0;
		}
		sel_flow->qlen++;
		sel_flow->stats.packets_in++;
		sel_flow->backlog += pkt_len;
		return NET_XMIT_SUCCESS;
	}
out:
	q->stats.dropped++;
	sel_flow->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
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
	struct sk_buff *skb = NULL;
	struct fq_pie_flow *flow;
	struct list_head *head;
	u32 uninitialized_var(pkt_len);

begin:
	head = &q->new_flows;
	if (list_empty(head)) {
		head = &q->old_flows;
		if (list_empty(head))
			return NULL;
	}

	flow = list_first_entry(head, struct fq_pie_flow, flowchain);
	if (flow->deficit <= 0) {
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->old_flows);
		goto begin;
	}

	if (flow->head) {
		skb = dequeue_head(flow);
		pkt_len = qdisc_pkt_len(skb);
		sch->qstats.backlog -= pkt_len;
		sch->q.qlen--;
		qdisc_bstats_update(sch, skb);
	}

	if (!skb) {
		if (head == &q->new_flows && !list_empty(&q->old_flows))
			list_move_tail(&flow->flowchain, &q->old_flows);
		else
			list_del_init(&flow->flowchain);
		goto begin;
	}

	flow->qlen--;
	flow->deficit -= pkt_len;
	flow->backlog -= pkt_len;
	pie_process_dequeue(flow->backlog, &flow->vars, skb);
	return skb;
}

static void fq_pie_timer(struct timer_list *t)
{
	struct fq_pie_sched_data *q = from_timer(q, t, adapt_timer);
	struct Qdisc *sch = q->sch;
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));
	int i;

	spin_lock(root_lock);

	for (i = 0; i < q->params.flows_cnt; i++)
		calculate_probability(q->flows[i].backlog,
				    		&q->flows[i].vars, &q->params.params_pie);

	// reset the timer to fire after 'tupdate'. tupdate is in jiffies.
	if (q->params.params_pie.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.params_pie.tupdate);
	spin_unlock(root_lock);
}

static const struct nla_policy fq_pie_policy[TCA_FQ_PIE_MAX + 1] = {
	[TCA_FQ_PIE_TARGET] = {.type = NLA_U32},
	[TCA_FQ_PIE_LIMIT] = {.type = NLA_U32},
	[TCA_FQ_PIE_TUPDATE] = {.type = NLA_U32},
	[TCA_FQ_PIE_ALPHA] = {.type = NLA_U32},
	[TCA_FQ_PIE_BETA] = {.type = NLA_U32},
	[TCA_FQ_PIE_ECN] = {.type = NLA_U32},
	[TCA_FQ_PIE_QUANTUM] = {.type = NLA_U32},
	[TCA_FQ_PIE_BYTEMODE] = {.type = NLA_U32},
	[TCA_FQ_PIE_FLOWS] = {.type = NLA_U32},
	[TCA_FQ_PIE_ECN_PROB] = {.type = NLA_U32}
};

static int fq_pie_change(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_PIE_MAX + 1];
	unsigned int len_dropped = 0;
	unsigned int num_dropped = 0;
	unsigned int qlen;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_FQ_PIE_MAX, opt, fq_pie_policy, NULL);
	if (err < 0)
		return err;

	if (tb[TCA_FQ_PIE_FLOWS]) {
		if (q->flows)
			return -EINVAL;
		q->params.flows_cnt = nla_get_u32(tb[TCA_FQ_PIE_FLOWS]);
		if (!q->params.flows_cnt ||
		    q->params.flows_cnt > 65536)
			return -EINVAL;
	}

	sch_tree_lock(sch);

	/* convert from microseconds to pschedtime */
	if (tb[TCA_FQ_PIE_TARGET]) {
		/* target is in us */
		u32 target = nla_get_u32(tb[TCA_FQ_PIE_TARGET]);

		/* convert to pschedtime */
		q->params.params_pie.target = PSCHED_NS2TICKS((u64)target * NSEC_PER_USEC);
	}

	/* tupdate is in jiffies */
	if (tb[TCA_FQ_PIE_TUPDATE])
		q->params.params_pie.tupdate = usecs_to_jiffies(nla_get_u32(tb[TCA_FQ_PIE_TUPDATE]));

	if (tb[TCA_FQ_PIE_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_FQ_PIE_LIMIT]);

		q->params.params_pie.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_FQ_PIE_ECN_PROB])
		q->params.ecn_prob = nla_get_u32(tb[TCA_FQ_PIE_ECN_PROB]);

	if (tb[TCA_FQ_PIE_ALPHA])
		q->params.params_pie.alpha = nla_get_u32(tb[TCA_FQ_PIE_ALPHA]);

	if (tb[TCA_FQ_PIE_BETA])
		q->params.params_pie.beta = nla_get_u32(tb[TCA_FQ_PIE_BETA]);

	if (tb[TCA_FQ_PIE_ECN])
		q->params.params_pie.ecn = nla_get_u32(tb[TCA_FQ_PIE_ECN]);

	if (tb[TCA_FQ_PIE_QUANTUM])
		q->quantum = nla_get_u32(tb[TCA_FQ_PIE_QUANTUM]);

	if (tb[TCA_FQ_PIE_BYTEMODE])
		q->params.params_pie.bytemode = nla_get_u32(tb[TCA_FQ_PIE_BYTEMODE]);

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_pie_qdisc_dequeue(sch);

		kfree_skb(skb);
		len_dropped += qdisc_pkt_len(skb);
		num_dropped += 1;
	}
	qdisc_tree_reduce_backlog(sch, num_dropped, len_dropped);

	sch_tree_unlock(sch);
	return 0;
}

static int fq_pie_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	int err;
	int i;

	pie_params_init(&q->params.params_pie);
	sch->limit = 10 * 1024;
	q->params.ecn_prob = 10;
	q->params.params_pie.limit = sch->limit;
	q->params.flows_cnt = 1024;
	q->quantum = psched_mtu(qdisc_dev(sch));
	q->sch = sch;

	INIT_LIST_HEAD(&q->new_flows);
	INIT_LIST_HEAD(&q->old_flows);

	timer_setup(&q->adapt_timer, fq_pie_timer, 0);
	mod_timer(&q->adapt_timer, jiffies + HZ / 2);

	if (opt) {
		int err = fq_pie_change(sch, opt, extack);

		if (err)
			return err;
	}

	if (!q->flows) {
		q->flows = kvcalloc(q->params.flows_cnt,
				    sizeof(struct fq_pie_flow),
				    GFP_KERNEL);
		if (!q->flows) {
			err = -ENOMEM;
			goto init_failure;
		}
		for (i = 0; i < q->params.flows_cnt; i++) {
			struct fq_pie_flow *flow = q->flows + i;

			INIT_LIST_HEAD(&flow->flowchain);
			pie_vars_init(&flow->vars);
		}
	}
	return 0;

init_failure:
	q->params.flows_cnt = 0;

	return err;
}

static int fq_pie_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	/* convert target from pschedtime to us */
	if (nla_put_u32(skb, TCA_FQ_PIE_TARGET,
		((u32)PSCHED_TICKS2NS(q->params.params_pie.target)) /
		NSEC_PER_USEC) ||
		nla_put_u32(skb, TCA_FQ_PIE_LIMIT, sch->limit) ||
		nla_put_u32(skb, TCA_FQ_PIE_TUPDATE, jiffies_to_usecs(q->params.params_pie.tupdate)) ||
		nla_put_u32(skb, TCA_FQ_PIE_ALPHA, q->params.params_pie.alpha) ||
		nla_put_u32(skb, TCA_FQ_PIE_BETA, q->params.params_pie.beta) ||
		nla_put_u32(skb, TCA_FQ_PIE_ECN, q->params.params_pie.ecn) ||
		nla_put_u32(skb, TCA_FQ_PIE_BYTEMODE, q->params.params_pie.bytemode) ||
		nla_put_u32(skb, TCA_FQ_PIE_QUANTUM, q->quantum) ||
		nla_put_u32(skb, TCA_FQ_PIE_FLOWS, q->params.flows_cnt) ||
		nla_put_u32(skb, TCA_FQ_PIE_ECN_PROB, q->params.ecn_prob))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int fq_pie_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct tc_fq_pie_xstats st = {
		.packets_in	= q->stats.packets_in,
		.overlimit	= q->stats.overlimit,
		.dropped	= q->stats.dropped,
		.ecn_mark	= q->stats.ecn_mark,
		.new_flow_count = q->stats.new_flow_count,
	};
	struct list_head *pos;

	sch_tree_lock(sch);
	list_for_each(pos, &q->new_flows)
		st.new_flows_len++;

	list_for_each(pos, &q->old_flows)
		st.old_flows_len++;
	sch_tree_unlock(sch);

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static void fq_pie_destroy(struct Qdisc *sch)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);

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
MODULE_AUTHOR("Leslie Monis");
MODULE_LICENSE("GPL");
