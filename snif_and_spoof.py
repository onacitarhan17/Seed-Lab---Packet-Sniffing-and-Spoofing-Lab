#!usr/bin/env python3
from scapy.all import *

def get_and_send_pkt(pkt):
	if pkt[ICMP] is not None:
		if pkt[ICMP].type == 8: # if it is echo request
			print('Packet sniffed')
			print('Source:', pkt[IP].src, 'Destination:', pkt[IP].dst) 
			a = IP()
			a.src = pkt[IP].dst # sets source to the X which user pings
			a.dst = pkt[IP].src # sets destination to the user
			# configuring the echo reply with sniffed pkt information
			b = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
			p = a/b/pkt[Raw].load
			send(p, verbose=0)
			print('Reply send to:', pkt[IP].src, 'as:', pkt[IP].dst)
			print('=====')
			
ifaces = ['br-82d5b13c1347', 'enp0s3', 'lo']
pkt = sniff(iface=ifaces, filter='icmp', prn=get_and_send_pkt)
