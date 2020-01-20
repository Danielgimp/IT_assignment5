#!/usr/bin/env python
from scapy.all import *
print "Sniffing Packets from subnet 172.217.23.0/24 (Google Israel Domain subnet)"
def print_summary(pkt):
    if IP in pkt:
      ip_dst=pkt[IP].dst 
      ip_src=pkt[IP].src    
      print " Source IP: " + str(ip_src) + " Destination IP: " + str(ip_dst)
sniff(filter="dst net 172.217.23.0/24",prn=print_summary)

