#!/usr/bin/env python3
from scapy.all import sniff, send, IP, TCP, Raw
import sys

KEYWORD = b"bangumi"

def handle_packet(pkt):
    if not pkt.haslayer(TCP):
        return
    if not pkt.haslayer(Raw):
        return
    
    payload = pkt[Raw].load
    
    if KEYWORD in payload:
        print(f"[DPI] ALERT! Detected forbidden keyword: {KEYWORD}")
        print(f"[DPI] Action: Sending RST to {pkt[IP].src}")
        
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport,
                  flags="R", seq=pkt[TCP].ack, ack=0)
        
        rst_pkt = ip/tcp
        send(rst_pkt, verbose=0)

print(f"[*] Starting Dummy DPI... Monitoring for '{KEYWORD.decode()}'")
sniff(filter="tcp port 80", prn=handle_packet, iface="wlan0")