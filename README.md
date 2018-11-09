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


### Steps to reproduce

### Experimentation

### Procedure

### Observations

### References

[1] -  The FlowQueue-CoDel Packet Scheduler and Active Queue Management Algorithm 		  https://tools.ietf.org/html/draft-ietf-aqm-fq-codel-06

[2]  Proportional Integral Controller Enhanced (PIE): A Lightweight Control Scheme to Address the Bufferbloat Problem
https://tools.ietf.org/html/rfc8033

[3] R. Pan _et al_. "PIE: A lightweight control scheme to address the bufferbloat problem," _2013 IEEE 14th International Conference on High Performance Switching and Routing (HPSR)_, Taipei, 2013, pp. 148-155.  







