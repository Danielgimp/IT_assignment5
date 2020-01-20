#!/usr/bin/env python
from scapy.all import *
a=IP()
a.src='128.128.128.128'
a.dst='192.168.1.1'
b=ICMP()
p=a/b
send(p)
