from scapy.all import srp, ARP, Ether, IP, UDP, BOOTP, DHCP, sniff, sendp
from random import randint
 
def mac_to_bytes(mac_addr: str) -> bytes:
    # Converts a MAC address string to bytes.
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def generate_random_mac():
    # Genereer een random MAC-adres
    from random import randint
    mac_int = [randint(0x00, 0xff) for i in range(6)]
    mac=":".join(map(lambda x: "%02x" % x, mac_int))
    mac_adresses.append(mac)
    print(mac_adresses)
    return mac
def packet_callback(packet):
    # Hier kun je aangepaste logica toevoegen voor het verwerken van elk pakket
    print(packet.summary())

def wait_for_dhcp_offer(packet):
    global dhcp_offer
    if packet.haslayer(DHCP):
        if packet[DHCP].options[0][1] == 2:
            print("DHCP OFFER received")
            dhcp_offer=packet
            return True
        else:
            return False
        
def send_dhcp_discover():   
    ethernet_layer=Ether(dst='ff:ff:ff:ff:ff:ff',src='6c:6a:77:87:0a:69',type=0x800)
    ip_layer=IP(src='0.0.0.0',dst='255.255.255.255')
    udp_layer=UDP(sport=68,dport=67)
    BOOTP_layer=BOOTP(chaddr=mac_to_bytes(generate_random_mac()), ciaddr = '0.0.0.0', xid=randint(0, 0xffffffff), flags=1)
    DHCP_layer=DHCP(options=[('message-type','discover'),'end'])
    packet=ethernet_layer/ip_layer/udp_layer/BOOTP_layer/DHCP_layer

    sendp(packet)
    sniff(prn=packet_callback, store=0, filter='port 67 and port 68)', stop_filter=wait_for_dhcp_offer)
    print(dhcp_offer.display())

if __name__ == "__main__":
    global mac_adresses
    global dhcp_offer
    mac_adresses=[]
    send_dhcp_discover()
