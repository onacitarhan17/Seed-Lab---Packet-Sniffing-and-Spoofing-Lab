#!usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

ifaces = ['br-82d5b13c1347', 'enp0s3', 'lo']
pkt = sniff(iface=ifaces, prn=print_pkt)

