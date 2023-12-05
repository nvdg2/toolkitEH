import scapy.all as scapy
import argparse
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import ARP
import datetime
import os
import json

# Functie om ARP-hostdetectie uit te voeren
def arp_scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    hosts = []
    for element in answered_list:
        host = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        hosts.append(host)
    log_results(hosts, "arp", "arp_scan", ip_range)
    return hosts

# Functie om poortscans uit te voeren
def port_scan(target_ip):
    open_ports = []
    for port in range(1, 1025):  # Scan alle poorten onder 1024
        print(f"scanning poort {port}")
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="S")  # TCP SYN-pakket om de poort te scannen

        response = scapy.sr1(packet, timeout=1, verbose=False)

        if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 18:
            # Poort is open (SYN/ACK ontvangen)
            open_ports.append(port)
    log_results(open_ports, "port", "port_scan", target_ip)
    return open_ports

# Functie voor actieve OS-detectie
def os_detection(target_ip):
    packet = scapy.IP(dst=target_ip)/scapy.ICMP()
    response = scapy.sr1(packet, timeout=1, verbose=False)

    if response:
        if response.haslayer(scapy.ICMP):
            if response[scapy.ICMP].type == 0 and response[scapy.ICMP].code == 0:
                log_results([f"Het doelsysteem op host {target_ip} lijkt een Unix-achtig besturingssysteem te gebruiken."], "OS", "os_scan", target_ip)
                return "Het doelsysteem lijkt een Unix-achtig besturingssysteem te gebruiken."
            
            elif response[scapy.ICMP].type == 3 and response[scapy.ICMP].code in [1, 2, 3, 9, 10, 13]:
                log_results([f"Het doelsysteem op host {target_ip} lijkt een Windows-besturingssysteem te gebruiken."], "OS", "os_scan", target_ip)
                return "Het doelsysteem lijkt een Windows-besturingssysteem te gebruiken."
            
    log_results([f"Besturingssysteem op host {target_ip} kon niet worden geïdentificeerd."], "OS", "os_scan", target_ip)
    return "Besturingssysteem kon niet worden geïdentificeerd."
    
# Functie voor het analyseren van verkeer met behulp van pcap
def pcap_analysis(pcap_file, protocols):
    packets = scapy.rdpcap(pcap_file, protocols)

    results = {"HTTP": 0, "SMTP": 0, "POP3": 0, "IMAP": 0}

    for packet in packets:
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

            if "HTTP" in protocols and (src_port == 80 or dst_port == 80):
                results["HTTP"] += 1

            if "SMTP" in protocols and (src_port == 25 or dst_port == 25):
                results["SMTP"] += 1

            if "POP3" in protocols and (src_port == 110 or dst_port == 110):
                results["POP3"] += 1

            if "IMAP" in protocols and (src_port == 143 or dst_port == 143):
                results["IMAP"] += 1
    log_results(results, "pcap", "pcap_scan",pcap_file)
    return results

def log_results(results, folder, log_file, extra_info=""):
    filename=f"{log_file}_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
    from pathlib import Path
    doelmap = Path(f'logs/scapy/{folder}')
    doelmap.mkdir(parents=True, exist_ok=True)
    os.chown("logs/scapy",1000,1000)
    os.chown(doelmap,1000,1000)
    output={}
    with open(f"{doelmap}/{filename}", "w") as json_file:
        match folder:
            case "OS":
                output["message"]=f"Resultaat OS scan voor ip: {extra_info}"
            case "pcap":
                output["message"]=f"Resultaat pcap scan op pcap file: {extra_info}"
            case "port":
                output["message"]=f"Resultaat port scan op host: {extra_info}"
            case "arp":
                output["message"]=f"Resultaat arp scan op ip range: {extra_info}"
        output["results"]=results
        json.dump(output, json_file)

def main():
    parser = argparse.ArgumentParser(description="Ethical hacking scans met Scapy")
    parser.add_argument("-i", "--ip_range", help="IP-range [IO range scan]")
    parser.add_argument("-p", "--portscan", action="store_true", help="Poortscan uitvoeren [Nmap scan]")
    parser.add_argument("-t", "--target", help="Target ip adres of bestandsnaam [Nmap scan (ip), OS scan (ip), PCAP scan (bestandslocatie)]")
    parser.add_argument("-o", "--os", action="store_true", help="OS-detectie scan uit [OS scan]")
    parser.add_argument("-a", "--analyze", help="Analyseer verkeer (HTTP, SMTP, POP3, IMAP) [PCAP scan]")

    args = parser.parse_args()

    if args.ip_range:
        hosts = arp_scan(args.ip_range)
        for host in hosts:
            print(f"Host gevonden: {host}")

    if args.target:
        if args.portscan:
            open_ports = port_scan(args.target)
            print(f"Open poorten: {open_ports}")
        
        if args.os:
            detected_os = os_detection(args.target)
            print(f"Besturingssysteem gedetecteerd: {detected_os}")
        
        if args.analyze:
            analysis_results = pcap_analysis(args.target, args.analyze)
            print(f"Analyseresultaten: {analysis_results}")

if __name__ == "__main__":
    main()
