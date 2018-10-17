<h1>3rd October 2018</h1>


<h3>Codel (Controlled Delay)</h3>

- Scheduling algorithm for network schedulers. Network schedulers are a part of a network node.

- Used to overcome buffer bloat in routers by limiting delays experience by packets

 - Solves bufferbloat by ensuring minimum delay faced by packets stays below 5ms

- Has no parameters to set

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
 

----------------------------------------------------------------------

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

