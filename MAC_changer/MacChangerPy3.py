# Usage: python MachChanger
# Works on linux and MacOS(Excluding Big Surr)
# Script needs to be ran multiple times (at least 5) for Big Surr.
# Usage python3 -i eth0 -m AA:BB:CC:DD:EE:FF

import subprocess
import optparse
import re


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="The Interface with MAC address to be changed.")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC Address Format XX:XX:XX:XX:XX:XX")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please enter a value for the interface. Use --help for more information.")
    elif not options.new_mac:
        parser.error("[-] Please enter a value for a new MAC Address. Use --help for more information.")
    return options


def changeMac(interface, new_mac):
    print("[+] Current MAC address for " + interface + " is " + getMac(interface) + "...")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def getMac(interface):
    ifconfig_res = subprocess.check_output(["ifconfig", interface])
    mac_search = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_res))

    if mac_search:
        return mac_search.group(0)
    else:
        print("[-] Could not read MAC Address, are you should you entered the right interface?")


options = get_args()

mac1 = getMac(options.interface)

changeMac(options.interface, options.new_mac)

mac2 = getMac(options.interface)

if mac1 == mac2:
    print("[-] Operation failed")
else:
    print("[+] Operation Successful: New MAC: " + mac2)
