#!/usr/bin/env python
from scapy.all import *

a=IP()
a.dst='8.8.8.8'
b=ICMP()
#assign a as ip packet with destination as 8.8.8.8
#assign b as ICMP Packet
for x in range(1,11):
 a.ttl=x
 p=a/b
 send(p)

#Set sending windows to i (grow each time by 1) to probe the distance to 8.8.8.8

		
