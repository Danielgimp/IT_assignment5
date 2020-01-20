#!/usr/bin/env python
from scapy.all import *
def print_summary(pkt):
    if IP in pkt:
      ip_src=pkt[IP].src
    if TCP in pkt:
      tcp_dport=pkt[TCP].dport     
      print " Source IP: " + str(ip_src) + " TCP Destination Port: " + str(tcp_dport)
sniff(filter="tcp and port 23 and src host 127.0.0.1",prn=print_summary)

