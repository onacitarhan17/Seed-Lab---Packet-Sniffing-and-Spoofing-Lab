#!usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	if pkt[ICMP] is not None:
		print('ICMP PACKET')
		print('from', pkt[IP].src, 'to', pkt[IP].dst)
		print('ICMP type number (0 = echo-reply, 8 = echo-request)', pkt[ICMP].type)
		print('Raw:', pkt[Raw])
		print()

ifaces = ['br-82d5b13c1347', 'enp0s3', 'lo']
pkt = sniff(iface=ifaces, filter='icmp', prn=print_pkt)
