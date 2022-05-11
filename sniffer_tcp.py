#!usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	if pkt[TCP] is not None:
		print('TCP PACKET')
		print('from', pkt[IP].src, 'to', pkt[IP].dst)
		print('Source Port:', pkt[TCP].sport)
		print('Destination Port:', pkt[TCP].dport)
		print()

ifaces = ['br-82d5b13c1347', 'enp0s3', 'lo']
pkt = sniff(iface=ifaces, filter='tcp port 23 and src host 10.9.0.5', prn=print_pkt)
