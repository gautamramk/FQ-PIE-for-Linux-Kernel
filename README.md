# FQ-PIE-for-Linux-Kernel

## Course code - CO300

### Assignment : #23

#### Accompanying webpage - 


#### Overview

Active queue management is an intelligent packet drop technique in side the NIC buffers, before the queue associated with that particular interface is full. It is an alternative to other methods such as using a tail drop queue, which waits until the queue is completely filled, and then the packet dropping starts.

Active queue management solves issues of bufferbloat and TCP global syncronization.

##### Flow queues

Flow: A flow is typically identified by a 5-tuple of source IP, destination IP, source port, destination port, and protocol number.

The intention of Flow Queue scheduler is to give each flow its own queue.

Enqueue
