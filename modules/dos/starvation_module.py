from scapy.all import srp, ARP, Ether, IP, UDP, BOOTP, DHCP, sniff, sendp
from random import randint
import threading
def mac_to_bytes(mac_addr: str) -> bytes:
    # Converts a MAC address string to bytes.
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def generate_random_mac():
    # Genereer een random MAC-adres
    from random import randint
    mac_int = [randint(0x00, 0xff) for i in range(6)]
    mac=":".join(map(lambda x: "%02x" % x, mac_int))
    return mac

def delayed_send(packet, delay):
    # Verstuur een pakket met een delay
    def send_packet(packet):
        sendp(packet)
    threading.Timer(delay, send_packet, [packet]).start()

def packet_callback(packet):
    # Hier kun je aangepaste logica toevoegen voor het verwerken van elk pakket
    print(packet.summary())

def wait_for_dhcp_offer(xid):
    def check_up(packet):
        global dhcp_offer
        if packet.haslayer(DHCP):
            if packet[DHCP].options[0][1] == 2 and packet[BOOTP].xid == xid:
                print("DHCP OFFER received")
                dhcp_offer=packet
                return True
            else:
                return False
    return check_up

def wait_for_dhcp_ack(xid):
    def check_up(packet):
        global dhcp_ack
        if packet.haslayer(DHCP):
            print(f"message-type: {packet[DHCP].options}")
            if packet[DHCP].options[0][1] == 5 and packet[BOOTP].xid == xid:
                print("DHCP ACK received")
                dhcp_ack=packet
                dhcp_leases.append((packet[Ether].src,dhcp_offer[BOOTP].yiaddr))
                return True
            else:
                return False
    return check_up

def send_dhcp_discover():
    ethernet_layer=Ether(dst='ff:ff:ff:ff:ff:ff',src=generate_random_mac())
    IP_layer=IP(src='0.0.0.0',dst='255.255.255.255')
    UDP_layer=UDP(sport=68,dport=67)
    BOOTP_layer=BOOTP(chaddr=mac_to_bytes(ethernet_layer.src), xid=randint(0, 0xffffffff))
    DHCP_layer=DHCP(options=[('message-type','discover'),'end'])
    packet=ethernet_layer/IP_layer/UDP_layer/BOOTP_layer/DHCP_layer

    delayed_send(packet, 0.5)
    sniff(prn=packet_callback, store=0, stop_filter=wait_for_dhcp_offer(BOOTP_layer.xid))

def send_dhcp_request(mac_address, offered_xid, offered_ip, server_identifier):
    ethernet_layer=Ether(dst='ff:ff:ff:ff:ff:ff',src=mac_address)
    IP_layer=IP(src='0.0.0.0',dst='255.255.255.255')
    UDP_layer=UDP(sport=68,dport=67)
    BOOTP_layer=BOOTP(chaddr=mac_to_bytes(mac_address), xid=offered_xid)
    DHCP_layer=DHCP(options=[('message-type','request'),('server_id',server_identifier),('requested_addr',offered_ip),'end'])
    packet=ethernet_layer/IP_layer/UDP_layer/BOOTP_layer/DHCP_layer

    delayed_send(packet, 0.5)
    sniff(prn=packet_callback, store=0, stop_filter=wait_for_dhcp_ack(offered_xid))

if __name__ == "__main__":
    global dhcp_leases
    dhcp_leases=[]

    send_dhcp_discover()
    send_dhcp_request(dhcp_offer[Ether].src, dhcp_offer[BOOTP].xid, dhcp_offer[BOOTP].yiaddr, dhcp_offer[BOOTP].siaddr)

    print(dhcp_leases)
