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

[1] : https://en.wikipedia.org/wiki/CoDel
[2] : https://tools.ietf.org/html/draft-ietf-aqm-codel-10
[3] : https://ieeexplore.ieee.org/document/6524283
-----------------------------------------------------------------------
<h3>Buffer bloat</h3>

- Buffers are present to ensure smooth communication between a fast network and a slow network. 

- Act like shock absorbers and delay packets in the fast network so that the slow network can keep up with the packets. 

- Affects channel bandwidth.

- Solved by various Active Queue Management algorithms.


References:

[1] : https://en.wikipedia.org/wiki/Bufferbloat
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

[1] : https://en.wikipedia.org/wiki/Random_early_detection
[2] : https://pdfs.semanticscholar.org/26a1/af4c2b5f398db1ef7e3f672aae9071c78aea.pdf
[3] : https://sites.google.com/a/ncsu.edu/tail-drop-vs-red/plan-of-work/red-algorithm
----------------------------------------------------------------------
<h3>PIE (Proportional Integral Controller Enhanced)</h3>

- Similary to RED, drops packet randomly during enqueuing 

- Drops packets based on queuing latency instead of queue length

- Queue latency is calculated using queue length and dequeue rate

- Drop probability is reduced if queueing latency is below a threshold limit

[1] : https://tools.ietf.org/html/draft-ietf-aqm-pie-10

----------------------------------------------------------------------
