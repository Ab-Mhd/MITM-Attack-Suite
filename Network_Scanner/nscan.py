# Usage python -i 192.168.0.1/24

import scapy.all as scapy
import optparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_bc = broadcast / arp_request
    ans_list = scapy.srp(arp_request_bc, timeout=1)[0]

    clients_list = []
    for el in ans_list:
        client_dict = {"ip": el[1].psrc, "mac": el[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip-address", dest="ipaddress",
                      help="Please enter the default gateway to scan the newtwork. eg 192.168.0.1/24")
    (options, arguments) = parser.parse_args()
    return options


def printRes(re_lst):
    print("IP\t\t\t\t\t   MAC Address\n--------------------------------------------")

    for cl in re_lst:
        print(cl["ip"] + " \t\t" + cl["mac"])

    print("--------------------------------------------")


opt = get_args()
res = scan(opt.ipaddress)
printRes(res)
