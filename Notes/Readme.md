<h1>3rd October 2018</h1>


<h3>Codel (Controlled Delay)</h3>

- Scheduling algorithm for network schedulers. Network schedulers are a part of a network node.

- Used to overcome buffer bloat in routers by limiting delays experience by packets

 - Solves bufferbloat by ensuring minimum delay faced by packets stays below 5ms

- Adapts dynamically to changing link rates

- Simple implementation

```
Algorithm:
	100ms dropping interval set
	Queuing delay is calculated for each packet.
	Lowest delay is maintained
	If lowest delay is greater than 5ms 
		dropping interval is set to 100/root(2) 
```

- Dropping Intervals are set as - 100 , 100/root(2) , 100/root(3) , 100/root(4) ... where 2,3,4,5... signify the number of packets dropped

References:
<ol>
	<li> https://en.wikipedia.org/wiki/CoDel </li>
	<li> https://tools.ietf.org/html/draft-ietf-aqm-codel-10 </li>
	<li> https://ieeexplore.ieee.org/document/6524283 </li>
</ol>

-----------------------------------------------------------------------

<h3>Buffer bloat</h3>

- Buffers are present to ensure smooth communication between a fast network and a slow network. 

- Act like shock absorbers and delay packets in the fast network so that the slow network can keep up with the packets. 

- Affects channel bandwidth.

- Solved by various Active Queue Management algorithms.


References:

<ol>
	<li> https://en.wikipedia.org/wiki/Bufferbloat </li>
</ol>

----------------------------------------------------------------------
<h3>RED (Random Early Detection)</h3>

- Probabilistically drops packets. Probability grows as average queue size grows

- Contains multiple varients : RRED,WRED,ARED

- RED doesnt provide a good way to solve Bufferbloat (checks for average queue length)


<ul>
	<li>
	Contains two sub algorithms
	<ul>
		<li>1. To calculate average queue size</li>
		<li>2. To calculate marking probability</li>
	</ul>
	</li>
</ul>

- Keeps track of a minimum and maximum threshold for queue size. If the  number of packets is below minimum, no packets are marked. If the number of packets is above maximum, all packets are marked. If number of packets is within both the bounds, packets are maked probabilistically. Marked packets are dropped.

References:
<ol>
	<li> https://en.wikipedia.org/wiki/Random_early_detection </li>
	<li> https://pdfs.semanticscholar.org/26a1/af4c2b5f398db1ef7e3f672aae9071c78aea.pdf</li>
	<li> https://sites.google.com/a/ncsu.edu/tail-drop-vs-red/plan-of-work/red-algorithm </li>
</ol>

----------------------------------------------------------------------
<h3>PIE (Proportional Integral Controller Enhanced)</h3>

- Similary to RED, drops packet randomly during enqueuing 

- Drops packets based on queuing latency instead of queue length

- Queue latency is calculated using queue length and dequeue rate

- Drop probability is reduced if queueing latency is below a threshold limit

<ol>
	<li> https://tools.ietf.org/html/draft-ietf-aqm-pie-10 </li>
</ol>
 

__________________________________________________________

## Flow Queue Logic

 Flow: A flow is typically identified by a 5-tuple of source IP, destination IP, source port, destination port, and protocol number. 

The intention of Flow Queue scheduler is to give each _flow_ its own queue.

### Enqueue

When a packet is en-queued, it is first classified into the appropriate queue.  By default, this is done by hashing (using a Jenkins hash function on the 5-tuple of IP protocol, and source and destination IP addresses and port numbers (if they exist) and taking the hash value modulo the number of queues.  

### Dequeue
It consists of three parts: 
- selecting a queue from which to dequeue a packet,
- actually dequeuing it (employing the appropriate algorithm (PIE/CoDel etc) algorithm in the process
 - final bookkeeping.

For the first part, the scheduler first looks at the list of new queues; for the queue at the head of that list, if that queue has a  negative number of credits (i.e., it has already dequeued at least a quantum of bytes), it is given an additional quantum of credits, the queue is put onto _the end of_ the list of old queues, and the routine selects the next queue and starts again.

Otherwise, that queue is selected for dequeue.  If the list of nee queues is empty, the scheduler proceeds down the list of old queues in the same fashion (checking the credits, and either selecting the queue for dequeuing, or adding credits and putting the queue back at the end of the list).

 After having selected a queue from which to dequeue a packet, the underlying algorithm is invoked on that queue.  As a result of this, one or more packets may be discarded from the head of the selected queue, before the packet that should be dequeued is returned (or nothing is returned if the queue is or becomes empty while being handled by the underlying algorithm).

Finally, if the underlying algorithm does not return a packet, then the queue must be empty, and the scheduler does one of two things: if the queue selected for dequeue came from the list of new queues, it is moved to _the end of_ the list of old queues.  If instead it came  from the list of old queues, that queue is removed from the list, to be added back (as a new queue) the next time a packet arrives that hashes to that queue.  Then (since no packet was available for  dequeue), the whole dequeue process is restarted from the beginning.

If, instead, the scheduler _did_ get a packet back from the underlying algorithm, it subtracts the size of the packet from the byte credits for the selected queue and returns the packet as the result of the dequeue operation.

----------------------------------------------------------------------
## FQ-CoDel

### Synopsis
FQ-CoDel aims to control queuing delays while sharing bottleneck capacity relatively evenly among competing flows. FQ-CoDel’s modified DRR (Deficit Round Robin) scheduler manages two lists of queues – old queues and new queues – to provide brief periods of priority to lightweight or short burst flows. FQ-CoDel’s internal, dynamically created queues are controlled by separate instances of CoDel AQM (including separate state variables per queue).

### Parameters
FQ-CoDel has five primary parameters (target, interval, quantum, limit and flows) and one option ([no]ecn) to enable or disable ECN. 
- quantum is number of bytes a queue can be served before being moved to the tail of old queues list. 
- limit is the hard size limit of all queues managed by an instance of the fq_codel scheduler. 
-  flows is number of flow queues that fq_codel creates and manages.

 The other parameters are the same as CoDel parameters.
__________________________________________________________

<h1>17th October 2018</h1>


<h3> Interpretation of Linux PIE Implementation  </h3>

`drop_early()` : Takes a scheduler and packet size as input. 

Returns false if :

- Burst time left
- Drop probability is low
- Queue delay is less than half the target delay
- Lesser than 2 packets present in scheduler

Returns true if a random number generated is lesser than the calculated probability of drop. Where,
`prob=prob/mtu * packet_size`

`pie_qdisc_enqueue()` : Takes in packet control information (type:sk_buff) and scheduler. Returns index of the last item in the scheduler

Enqueue occurs when 
- Packets is not marked to be dropped early
- ECN is turned on and drop probability is 10%

Packet is dropped if scheduler queue length is >= scheduler limit


`pie_process_dequeue()` : Takes in packet control information and scheduler. The functions changes the statistic variables for pie and hence return type is void.

If no packets have been queued and the queue length meets a threshold, then the current time is stored

If packets are ready to be dequeued and queue length is greater than threshold then drain rate is calculated and dequeue count is updated

`drain=drain - (drain>>3 + count>>3)`

Burst time is recalculated to `burst time-dequeue time`

-----------------------

<h3>Linux Kernel Structures Read About</h3>

`qdisc` : Is a scheduler maybe classless or classful. FIFO by default <br/>
`sk_buff` : Doubly linked list containing all control infomation of a packet



References:
<ol>
	<li> http://tldp.org/HOWTO/Traffic-Control-HOWTO/components.html</li>
	<li> https://wiki.linuxfoundation.org/networking/sk_buff</li>
</ol>

