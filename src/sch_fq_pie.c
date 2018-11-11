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
	u32 new_flow_count;     /* number of time packets
				 * created a 'new flow'
				 */
};

struct fq_pie_flow {
	struct sk_buff *head;
	struct sk_buff *tail;
	struct list_head flowchain;
	int deficit;
	u32 backlog;
    u32 qlen;
	struct pie_vars vars;
	struct pie_stats stats;
};

struct fq_pie_sched_data {
    //struct tcf_proto __rcu *filter_list; /* optional external classifier */
	//struct tcf_block *block;
	u32 flows_cnt;
	u32 quantum;
	struct fq_pie_flow *flows;
	struct pie_params params;
	struct fq_pie_stats stats;
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
	int result;
	return fq_pie_hash(q, skb) + 1;
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
	if (flow->backlog < 2 * mtu)
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
    printk(KERN_NOTICE"Enqueue started.\n");
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	bool enqueue = false;
	int uninitialized_var(ret);
    u32 uninitialized_var(pkt_len);
	struct fq_pie_flow *sel_flow;
	unsigned int idx;
	idx = fq_pie_classify(skb, sch, &ret);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return ret;
	}
	idx--;
	printk(KERN_NOTICE"Classify Ended.\n");
	sel_flow = &q->flows[idx];

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		sel_flow->stats.overlimit++;
		goto out;
	}
    printk(KERN_NOTICE"Queue full check ended.\n");
    
    if (!drop_early(sch, sel_flow, skb->len)) {
        //printk(KERN_NOTICE"Dont drop early.\n");
		enqueue = true;
	} else if (q->params.ecn && (sel_flow->vars.prob <= MAX_PROB / 10) &&
		   INET_ECN_set_ce(skb)) {
		/* If packet is ecn capable, mark it if drop probability
		 * is lower than 10%, else drop it.
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
        printk(KERN_NOTICE"Length update and about to add to flow queue.\n");
        flow_queue_add(sel_flow, skb);
        printk(KERN_NOTICE"Added to flow queue.\n");
        if (list_empty(&sel_flow->flowchain)) {
            printk(KERN_NOTICE"Empty flow check started.\n");
            list_add_tail(&sel_flow->flowchain, &q->new_flows);
            q->stats.new_flow_count++;
            sel_flow->deficit = q->quantum;
            sel_flow->stats.dropped = 0;
            sel_flow->qlen = 0;
            sel_flow->backlog = 0;
            printk(KERN_NOTICE"Empty flow check ended.\n");
        }
        printk(KERN_NOTICE"Modifying stats.\n");
        sel_flow->qlen++;
        sel_flow->stats.packets_in++;
        sel_flow->backlog += pkt_len;
        printk(KERN_NOTICE"Enqueue Ended.\n");
        return NET_XMIT_SUCCESS;
    }
out:
    //printk(KERN_NOTICE"Out.\n");
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
    
    //printk(KERN_NOTICE"Dequeue started.\n");
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = NULL;
	struct fq_pie_flow *flow;
	struct list_head *head;
    u32 uninitialized_var(pkt_len);

begin:
	head = &q->new_flows;
	if(list_empty(head)){
		head = &q->old_flows;
		if (list_empty(head)){
			return NULL;
		}
	}
    
    //printk(KERN_NOTICE"Got the head.\n");
	flow = list_first_entry(head, struct fq_pie_flow, flowchain);
	if (flow-> deficit <= 0) {
        //printk(KERN_NOTICE"Deficit is negative.\n");
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->old_flows);
		goto begin;
	}

	if (flow->head) {
        //printk(KERN_NOTICE"Flow is not empty.\n");
		skb = dequeue_head(flow);
        pkt_len = qdisc_pkt_len(skb);
        
        sch->qstats.backlog -= pkt_len;
	    sch->q.qlen--;
        qdisc_bstats_update(sch, skb);
	    
	}
	if (!skb) {
        //printk(KERN_NOTICE"Flow is empty.\n");
		if ((head == &q->new_flows) && !list_empty(&q->old_flows))
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

    for(i = 0; i < q->flows_cnt; i++){
		calculate_probability(q->flows[i].backlog, &q->params, &q->flows[i].vars);
	}
	
	// reset the timer to fire after 'tupdate'. tupdate is in jiffies. 
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
	[TCA_FQ_PIE_QUANTUM] = {.type = NLA_U32},
	[TCA_FQ_PIE_BYTEMODE] = {.type = NLA_U32},
	[TCA_FQ_PIE_FLOWS] = {.type = NLA_U32}
};

static int fq_pie_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_PIE_MAX + 1];
	int err;
	unsigned int dropped = 0;
	int qlen;
	int i;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_FQ_PIE_MAX, opt, fq_pie_policy, NULL);
	if (err < 0)
		return err;

	if (tb[TCA_FQ_PIE_FLOWS]) {
		if (q->flows)
			return -EINVAL;
		q->flows_cnt = nla_get_u32(tb[TCA_FQ_PIE_FLOWS]);
		if (!q->flows_cnt ||
		    q->flows_cnt > 65536)
			return -EINVAL;
	}

	sch_tree_lock(sch);

	/* convert from microseconds to pschedtime */
	if (tb[TCA_FQ_PIE_TARGET]) {
		/* target is in us */
		u32 target = nla_get_u32(tb[TCA_FQ_PIE_TARGET]);

		/* convert to pschedtime */
		q->params.target = PSCHED_NS2TICKS((u64)target * NSEC_PER_USEC);
	}

	/* tupdate is in jiffies */
	if (tb[TCA_FQ_PIE_TUPDATE])
		q->params.tupdate = usecs_to_jiffies(nla_get_u32(tb[TCA_FQ_PIE_TUPDATE]));

	if (tb[TCA_FQ_PIE_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_FQ_PIE_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_FQ_PIE_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_FQ_PIE_ALPHA]);

	if (tb[TCA_FQ_PIE_BETA])
		q->params.beta = nla_get_u32(tb[TCA_FQ_PIE_BETA]);

	if (tb[TCA_FQ_PIE_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_FQ_PIE_ECN]);

	if (tb[TCA_FQ_PIE_QUANTUM])
	{
		q->quantum = nla_get_u32(tb[TCA_FQ_PIE_QUANTUM]);
		for(i = 0; i < q->flows_cnt; i++)
		{
			if(q->flows[i].deficit > q->quantum)
			{
				q->flows[i].deficit = q->quantum;
			}
		}

	}

	if (tb[TCA_FQ_PIE_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_FQ_PIE_BYTEMODE]);

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_pie_qdisc_dequeue(sch);
		kfree_skb(skb);
		dropped += qdisc_pkt_len(skb);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	sch_tree_unlock(sch);
	return 0;
}

static int fq_pie_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
    printk(KERN_NOTICE"Begin fq pie init.\n");
	struct fq_pie_sched_data *q = qdisc_priv(sch);

	pie_params_init(&q->params);
	sch->limit = 10*1024;
	q->params.limit = sch->limit;
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
        printk(KERN_NOTICE"Init flows initialized.\n");
		if (!q->flows) {
			err = -ENOMEM;
			goto init_failure;
		}
		for (i = 0; i < q->flows_cnt; i++) {
			struct fq_pie_flow *flow = q->flows + i;
            printk(KERN_NOTICE"Individual flow initialization.\n");
			INIT_LIST_HEAD(&flow->flowchain);
			pie_vars_init(&flow->vars);
		}
	}
    printk(KERN_NOTICE"Init ended successfully.\n");
	return 0;

	init_failure:
		q->flows_cnt = 0;
    printk(KERN_NOTICE"init_failure.\n");
	return err;
}

static int fq_pie_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fq_pie_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* convert target from pschedtime to us */
	if (nla_put_u32(skb, TCA_FQ_PIE_TARGET,
	   ((u32) PSCHED_TICKS2NS(q->params.target)) /
	    NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_FQ_PIE_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_FQ_PIE_TUPDATE, jiffies_to_usecs(q->params.tupdate)) ||
	    nla_put_u32(skb, TCA_FQ_PIE_ALPHA, q->params.alpha) ||
	    nla_put_u32(skb, TCA_FQ_PIE_BETA, q->params.beta) ||
	    nla_put_u32(skb, TCA_FQ_PIE_ECN, q->params.ecn) ||
	    nla_put_u32(skb, TCA_FQ_PIE_BYTEMODE, q->params.bytemode) ||
	    nla_put_u32(skb, TCA_FQ_PIE_QUANTUM, q->quantum) ||
	    nla_put_u32(skb, TCA_FQ_PIE_FLOWS, q->flows_cnt))
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
    
    //tcf_block_put(q->block);
	q->params.tupdate = 0;
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
	//.reset		= fq_pie_reset,
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
