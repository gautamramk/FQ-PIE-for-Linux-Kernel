# FQ-PIE-for-Linux-Kernel

# Course code - CO300

## Assignment : #23

#### Accompanying webpage - https://fq-pie.herokuapp.com/


## Overview

Active queue management is an intelligent packet drop technique in side the NIC buffers, before the queue associated with that particular interface is full. It is an alternative to other methods such as using a tail drop queue, which waits until the queue is completely filled, and then the packet dropping starts.

Active queue management solves issues of buffer-bloat and TCP global synchronisation. There are multiple AQM algorithms designed to combat these issues. Some of them are RED, CoDel, PIE and so on. We have implemented an algorithm called FQ-PIE, which is a combination of a packet scheduling algorithm (FQ) and an AQM algorithm(PIE). It is based on modified Deficit Round Robin (DRR) queue scheduler with the PIE AQM algorithm operating independently on each queue.


### Discussion about the FQ-PIE algorithm
The FQ PIE algorithm can logically be broken down into 2 components. These two components are the Flow Queuing (FQ) and PIE(Proportional Integral Controller Enhanced). Both are discussed below  briefly. Further information about these can be obtained from [1] and [2] respectively.


#### The FQ part
  
Flow: A flow is typically identified by a 5-tuple of source IP, destination IP, source port, destination port, and protocol number.

The intention of Flow Queue scheduler is to give each  flow its own queue. The FQ algorithm operates in two stages :-

#### [](https://github.com/gautamramk/FQ-PIE-for-Linux-Kernel/tree/master/Notes#enqueue)Enqueue

When a packet is en-queued, it is first classified into the appropriate queue. By default, this is done by hashing (using a Jenkins hash function on the 5-tuple of IP protocol, and source and destination IP addresses and port numbers (if they exist) and taking the hash value modulo the number of queues.

####  [](https://github.com/gautamramk/FQ-PIE-for-Linux-Kernel/tree/master/Notes#dequeue)Dequeue
Most of FQ scheduler's work is done during dequeing.

It consists of three parts:

-   selecting a queue from which to dequeue a packet,
-   actually dequeuing it (employing the appropriate algorithm (PIE/CoDel etc) algorithm in the process
-   final bookkeeping.

For the first part, the scheduler first looks at the list of new queues; for the queue at the head of that list, if that queue has a negative number of credits (i.e., it has already dequeued at least a quantum of bytes), it is given an additional quantum of credits, the queue is put onto  _the end of_  the list of old queues, and the routine selects the next queue and starts again.

Otherwise, that queue is selected for dequeue. If the list of new queues is empty, the scheduler proceeds down the list of old queues in the same fashion (checking the credits, and either selecting the queue for dequeuing, or adding credits and putting the queue back at the end of the list).

This is the second step of the process. After having selected a queue from which to dequeue a packet, the underlying algorithm is invoked on that queue. As a result of this, one or more packets may be discarded from the head of the selected queue, before the packet that should be dequeued is returned (or nothing is returned if the queue is or becomes empty while being handled by the underlying algorithm).

Finally, if the underlying algorithm does not return a packet, then the queue must be empty, and the scheduler does one of two things: if the queue selected for dequeue came from the list of new queues, it is moved to  _the end of_  the list of old queues. If instead it came from the list of old queues, that queue is removed from the list, to be added back (as a new queue) the next time a packet arrives that hashes to that queue. Then (since no packet was available for dequeue), the whole dequeue process is restarted from the beginning.

If, instead, the scheduler  did get a packet back from the underlying algorithm, it subtracts the size of the packet from the byte credits for the selected queue and returns the packet as the result of the dequeue operation.


#### The PIE part

PIE is comprised of three simple basic components: 
 - random dropping at enqueuing,  
 - periodic drop probability updates
 - latency calculation.

#### Random drop
PIE randomly drops a packet upon its arrival to a queue according to a drop probability, 
PIE->drop_prob, that is obtained from the drop-probability-calculation component. The random drop is triggered by a packet's arrival before enqueuing into a queue.

    Upon a packet enqueue: 
    randomly drop the packet with a probability of PIE->drop_prob.

#### Drop probability calculation and update

The PIE algorithm periodically updates the drop probability based on the latency samples not only the current latency sample but also whether the latency is trending up or down. This is the classical Proportional Integral (PI) controller method, which is known for eliminating steady-state errors. The PIE algorithm also includes a mechanism by which the drop probability decays exponentially when the system is not congested. The PIE algorithm periodically adjusts the drop probability every T_UPDATE interval. 

Further information about the drop probability calculation and the pseudocode can be found in the [2].

#### Latency calculation

There exists different methods to calculate latency, but we have followed the following 

    current_qdelay = queue_.byte_length()/dequeue_rate


This page describes the implementation of FQ-PIE in C.

## Changes in File Structuring
The original sch_pie.c code was taken, and the necessary pie queue management functions, i.e enqueue, dequeue functions were transferred to pie.h.

sch_fq_pie.c uses the queue management functions of pie, defined in pie.h directly. The implementation of this function was heavily influenced by the Linux Kernel implementation of FQ Codel.

## Important Structures
1. struct fq_pie_flow : This struct represents the necessary variables for a single flow. The **head** and **tail** skbuff pointers represent the list of skb's stored in that flow.
The list_head **flowchain** represents the list_head for the list of flows.
**deficit** represents the number of credits remaining for a given flow.
**backlog** size of the queue in bytes.
**qlen** size of the queue in packets.
Along with these, each flow has its own pie stats and variables.

## Important Functions
The most important functions in this implementation are the enqueue, dequeue and hash functions.

1. fq_pie_hash(const struct fq_pie_sched_data *q, struct sk_buff *skb) : This function takes an skb, applies the Jenkins has function on the tuple <source IP, target IP, source port, target port>. It then scales the value into the range [0, **number of flows** - 1]. The flow number returned here is then incremented by 1, so as to return a value in the range [1, **number of flows**].

2. fq_pie_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free) : This functions takes the input skb, applies the has function, and enqueues the skb into the appropriate flow queue. 

The following code checks if the total number of packets enqueued by ***fq-pie*** algorithm (not per queue) has exceeded the limit. If the limit is exceeded, the packet is dropped and the appropriate statistics are modified.
```
if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
    q->stats.overlimit++;
    del_flow->stats.overlimit++;
    goto out;
} 
```

This segment calls pie's drop function, while passing the appropriate flow data. the else if condition checks if ecn is enabled, marks the packet without dropping if the queue's drop probability is less than 10%.
```
if (!drop_early(sch, sel_flow, skb->len)) {
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
```
Within the main enqueue if condition, the following code checks if the queue we picked is empty. If the queue is empty, it corresponds to a new flow added. The selected flow is added to the list of new flows.

```
if (list_empty(&sel_flow->flowchain)) {
    list_add_tail(&sel_flow->flowchain, &q->new_flows); //add to new flows.
    q->stats.new_flow_count++;
    sel_flow->deficit = q->quantum;
    sel_flow->stats.dropped = 0;
    sel_flow->qlen = 0;
    sel_flow->backlog = 0;
}
```
3. static struct sk_buff *fq_pie_qdisc_dequeue(struct Qdisc *sch) : This function dequeues all the queues in a round robin fashion. First priority is given to the list of new flows, which have some byte credits assigned to it.

This segment is the beginning of the actual dequeueing. First, the new flows are checked. If the new flows are empty, we proceed to the old flows. If the old flows are also empty, we return NULL, indicating that there is nothing to dequeue.
```
begin:
	head = &q->new_flows;
	if(list_empty(head)){
		head = &q->old_flows;
		if (list_empty(head)){
			return NULL;
		}
	}
```
This segment check for the byte credits of the selected queue. If the queue has no credits left, it is pushed to the end of old_flows and given credits. It will not be dequeued in this iteration.
```
if (flow-> deficit <= 0) {
    flow->deficit += q->quantum;
    list_move_tail(&flow->flowchain, &q->old_flows);
    goto begin;
}
```
The final stage of the dequeuing is as follows. The selected queue is first checked whether it is empty or not. If the flow is empty and it is a new flow, it is moved to the list of old flows.
```
if (flow->head) {
    skb = dequeue_head(flow);
    sch->qstats.backlog -= qdisc_pkt_len(skb);
    sch->q.qlen--;
}
	
if (!skb) {
    if ((head == &q->new_flows) && !list_empty(&q->old_flows))
        list_move_tail(&flow->flowchain, &q->old_flows);
    else
        list_del_init(&flow->flowchain);
	goto begin;
}
```
**!!! IMPORTANT**
An important aspect of the fair queueing is that packets are consecutively dequeued from the same queue until its credits are over. Once the credits of the queue are over, it is moved to the end of the list of old flows.




[1] -  The FlowQueue-CoDel Packet Scheduler and Active Queue Management Algorithm 		  https://tools.ietf.org/html/draft-ietf-aqm-fq-codel-06

[2]  Proportional Integral Controller Enhanced (PIE): A Lightweight Control Scheme to Address the Bufferbloat Problem
https://tools.ietf.org/html/rfc8033

[3] R. Pan _et al_. "PIE: A lightweight control scheme to address the bufferbloat problem," _2013 IEEE 14th International Conference on High Performance Switching and Routing (HPSR)_, Taipei, 2013, pp. 148-155.  







