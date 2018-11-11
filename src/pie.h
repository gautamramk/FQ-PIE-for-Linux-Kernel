#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define QUEUE_THRESHOLD 10000
#define DQCOUNT_INVALID -1
#define MAX_PROB  0xffffffff
#define PIE_SCALE 8

/*#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

static inline void __qdisc_drop(struct sk_buff *skb, struct sk_buff **to_free)
{
	skb->next = *to_free;
	*to_free = skb;
}
*///For testing in my computer. Not needed in newer kernel versions.
/* parameters used */
struct pie_params {
	psched_time_t target;	/* user specified target delay in pschedtime */
	u32 tupdate;		/* timer frequency (in jiffies) */
	u32 limit;		/* number of packets that can be enqueued */
	u32 alpha;		/* alpha and beta are between 0 and 32 */
	u32 beta;		/* and are used for shift relative to 1 */
	bool ecn;		/* true if ecn is enabled */
	bool bytemode;		/* to scale drop early prob based on pkt size */
};

/* variables used */
struct pie_vars {
	u32 prob;		/* probability but scaled by u32 limit. */
	psched_time_t burst_time;
	psched_time_t qdelay;
	psched_time_t qdelay_old;
	u64 dq_count;		/* measured in bytes */
	psched_time_t dq_tstamp;	/* drain rate */
	u32 avg_dq_rate;	/* bytes per pschedtime tick,scaled */
	u32 qlen_old;		/* in bytes */
};

/* statistics gathering */
struct pie_stats {
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to pie_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u32 maxq;		/* maximum queue size */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* private data for the Qdisc */
struct pie_sched_data {
	struct pie_params params;
	struct pie_vars vars;
	struct pie_stats stats;
	struct timer_list adapt_timer;
	struct Qdisc *sch;
};

static void pie_params_init(struct pie_params *params)
{
	params->alpha = 2;
	params->beta = 20;
	params->tupdate = usecs_to_jiffies(30 * USEC_PER_MSEC);	/* 30 ms */
	params->limit = 1000;	/* default of 1000 packets */
	params->target = PSCHED_NS2TICKS(20 * NSEC_PER_MSEC);	/* 20 ms */
	params->ecn = false;
	params->bytemode = false;
}

static void pie_vars_init(struct pie_vars *vars)
{
	vars->dq_count = DQCOUNT_INVALID;
	vars->avg_dq_rate = 0;
	/* default of 100 ms in pschedtime */
	vars->burst_time = PSCHED_NS2TICKS(100 * NSEC_PER_MSEC);
}

static void pie_process_dequeue(int qlen, struct pie_vars *vars, struct sk_buff *skb)
{
	/* If current queue is about 10 packets or more and dq_count is unset
	 * we have enough packets to calculate the drain rate. Save
	 * current time as dq_tstamp and start measurement cycle.
	 */
	if (qlen >= QUEUE_THRESHOLD && vars->dq_count == DQCOUNT_INVALID) {
		vars->dq_tstamp = psched_get_time();
		vars->dq_count = 0;
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
	if (vars->dq_count != DQCOUNT_INVALID) {
		vars->dq_count += skb->len;

		if (vars->dq_count >= QUEUE_THRESHOLD) {
			psched_time_t now = psched_get_time();
			u32 dtime = now - vars->dq_tstamp;
			u32 count = vars->dq_count << PIE_SCALE;

			if (dtime == 0)
				return;

			count = count / dtime;

			if (vars->avg_dq_rate == 0)
				vars->avg_dq_rate = count;
			else
				vars->avg_dq_rate =
				    (vars->avg_dq_rate -
				    (vars->avg_dq_rate >> 3)) + (count >> 3);

			/* If the queue has receded below the threshold, we hold
			 * on to the last drain rate calculated, else we reset
			 * dq_count to 0 to re-enter the if block when the next
			 * packet is dequeued
			 */
			if (qlen < QUEUE_THRESHOLD)
				vars->dq_count = DQCOUNT_INVALID;
			else {
				vars->dq_count = 0;
				vars->dq_tstamp = psched_get_time();
			}

			if (vars->burst_time > 0) {
				if (vars->burst_time > dtime)
					vars->burst_time -= dtime;
				else
					vars->burst_time = 0;
			}
		}
	}
}

static void calculate_probability(u32 qlen, struct pie_params *params, struct pie_vars *vars)
{
	psched_time_t qdelay = 0;	/* in pschedtime */
	psched_time_t qdelay_old = vars->qdelay;	/* in pschedtime */
	s32 delta = 0;		/* determines the change in probability */
	u32 oldprob;
	u32 alpha, beta;
	bool update_prob = true;

	vars->qdelay_old = vars->qdelay;

	if (vars->avg_dq_rate > 0)
		qdelay = (qlen << PIE_SCALE) / vars->avg_dq_rate;
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
	if (vars->prob < MAX_PROB / 100) {
		alpha =
		    (params->alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 7;
		beta =
		    (params->beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 7;
	} else if (vars->prob < MAX_PROB / 10) {
		alpha =
		    (params->alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 5;
		beta =
		    (params->beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 5;
	} else {
		alpha =
		    (params->alpha * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 4;
		beta =
		    (params->beta * (MAX_PROB / PSCHED_TICKS_PER_SEC)) >> 4;
	}

	/* alpha and beta should be between 0 and 32, in multiples of 1/16 */
	delta += alpha * ((qdelay - params->target));
	delta += beta * ((qdelay - qdelay_old));

	oldprob = vars->prob;

	/* to ensure we increase probability in steps of no more than 2% */
	if (delta > (s32) (MAX_PROB / (100 / 2)) &&
	    vars->prob >= MAX_PROB / 10)
		delta = (MAX_PROB / 100) * 2;

	/* Non-linear drop:
	 * Tune drop probability to increase quickly for high delays(>= 250ms)
	 * 250ms is derived through experiments and provides error protection
	 */

	if (qdelay > (PSCHED_NS2TICKS(250 * NSEC_PER_MSEC)))
		delta += MAX_PROB / (100 / 2);

	vars->prob += delta;

	if (delta > 0) {
		/* prevent overflow */
		if (vars->prob < oldprob) {
			vars->prob = MAX_PROB;
			/* Prevent normalization error. If probability is at
			 * maximum value already, we normalize it here, and
			 * skip the check to do a non-linear drop in the next
			 * section.
			 */
			update_prob = false;
		}
	} else {
		/* prevent underflow */
		if (vars->prob > oldprob)
			vars->prob = 0;
	}

	/* Non-linear drop in probability: Reduce drop probability quickly if
	 * delay is 0 for 2 consecutive Tupdate periods.
	 */

	if ((qdelay == 0) && (qdelay_old == 0) && update_prob)
		vars->prob = (vars->prob * 98) / 100;

	vars->qdelay = qdelay;
	vars->qlen_old = qlen;

	/* We restart the measurement cycle if the following conditions are met
	 * 1. If the delay has been low for 2 consecutive Tupdate periods
	 * 2. Calculated drop probability is zero
	 * 3. We have atleast one estimate for the avg_dq_rate ie.,
	 *    is a non-zero value
	 */
	if ((vars->qdelay < params->target / 2) &&
	    (vars->qdelay_old < params->target / 2) &&
	    (vars->prob == 0) &&
	    (vars->avg_dq_rate > 0))
		pie_vars_init(vars);
}