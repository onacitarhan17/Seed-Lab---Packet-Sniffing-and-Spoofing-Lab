#!usr/bin/env python3
from scapy.all import *
import sys

isReached = False
dst_ip = sys.argv[1] # user can give any ip as an argument
dist = 1
while not isReached:
	a = IP(dst=dst_ip, ttl=dist)
	b = ICMP()
	p = a/b
	rsp = sr1(p, timeout=2, verbose=0)
	if rsp is None:
		print('Current distance:', dist, 'bad response')
	elif not rsp.type:
		print('Distance to the destination:',dist,'Response source:', rsp.src)
		isReached = True
	else:
		print('Current distance:', dist, 'Response source:', rsp.src)
	dist += 1
