import json
import pathlib
from datetime import datetime
import ipaddress
import ssl
import socket
import os
import argparse

targetIp = ""
port_range= ""

class InvalidSubnetPrefixException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class InvalidPortRangeException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

def generate_port_list(port_range):
    port_list = []
    ranges = port_range.split(',')
    
    for r in ranges:
        parts = r.split('-')
        if len(parts) == 1:
            port_list.append(int(parts[0]))
        elif len(parts) == 2:
            start_port = int(parts[0])
            end_port = int(parts[1])
            port_list.extend(range(start_port, end_port + 1))
        else:
            raise ValueError("Ongeldige poortnotatie: {}".format(r))
    return port_list

def scan_ip_hosts(target_ip, prefix):
    import nmap
    ping_results = {}

    try:
        ipaddress.IPv4Address(target_ip)
    except ipaddress.AddressValueError as exception:
        print(f"Er is een fout opgetreden: {str(exception)}")
        return exception
    
    try:
        prefix = int(prefix)
        if 0 <= prefix <= 32:  # Subnet-prefixlengte mag variëren van 0 tot 32 voor IPv4
            pass
        else:
            return InvalidSubnetPrefixException("Ongeldige subnetprefix")
    except ValueError:
        return InvalidSubnetPrefixException("Ongeldige subnetprefix")
    
    print("scanning")
    target_ip_range = f"{target_ip}/{prefix}"
    nm = nmap.PortScanner()
    nm.scan(target_ip_range, arguments='-sn')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print(f"{host}:{status}")
        ping_results[host]=status

    timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    nmap_dir = pathlib.Path("logs/nmap")
    nmap_dir.mkdir(exist_ok=True, parents=True)
    target_ip_range = target_ip_range.replace("/", "_with_range")
    save_location = nmap_dir / f"scan_results_{target_ip_range}_{timestamp}_ping.json"
    with save_location.open("w") as json_file_ping:
        json.dump(ping_results, json_file_ping)
    os.chown(nmap_dir,1000,1000)
    return True


def scan_hosts_for_open_ports(host, port_range):

    import nmap
    host_adress=host
    try:
        ipaddress.IPv4Address(host_adress)
    except ipaddress.AddressValueError as exception:
        print(f"Er is een fout opgetreden: {str(exception)}")
        return exception
        
    print("scanning")
    try:
        port_range=generate_port_list(port_range)
    except Exception:
        return InvalidPortRangeException("Ongeldige poortnotatie")
    scan_results_short={}
    scan_results_raw={}
    
    for port in port_range:
        print(f"Scanning port {port}...")
        try:
            scan=nmap.PortScanner().scan(host_adress,str(port))
            state=scan["scan"][host_adress]["tcp"][port]["state"]
        except KeyError as e:
            print(f"Er is een fout opgetreden: {e}")
            print("Scan gaat verder...")
            continue
        protocol_name=scan["scan"][host_adress]["tcp"][port]["name"]
        reason=scan["scan"][host_adress]["tcp"][port]["reason"]
        version=scan["scan"][host_adress]["tcp"][port]["version"]

        scan_results_short[port]={
            "state": state,
            "protocol_name": protocol_name,
            "reason": reason,
            "version": version
        }
        scan_results_raw[port]= scan["scan"][host_adress]

    timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    nmap_dir = pathlib.Path("logs/nmap")
    nmap_dir.mkdir(exist_ok=True,parents=True)

    save_location=nmap_dir/f"scan_results_{host_adress}_{timestamp}_short.json"
    with save_location.open("w") as json_file_short:
        json.dump(scan_results_short, json_file_short)
    save_location=nmap_dir/f"scan_results_{host_adress}_{timestamp}_raw.json"
    with save_location.open("w") as json_file_raw:
        json.dump(scan_results_raw, json_file_raw)
    
    return True


def scan_domain_for_cert(domain):
    try:
        print(f"Scanning domain {domain} for cert...")
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
                nmap_dir = pathlib.Path("logs/nmap")
                nmap_dir.mkdir(exist_ok=True,parents=True)
                save_location=nmap_dir/f"scan_result_{domain}_{timestamp}_cert.json"
                with save_location.open("w") as json_file_raw:
                    json.dump(cert, json_file_raw)
    
            
    except (ssl.SSLError, socket.error) as exception:
        print(f"Er is een fout opgetreden bij het ophalen van het certificaat voor {domain}: {str(exception)}")
        return exception
    
    return True

def main():
    parser = argparse.ArgumentParser(description="Ethical hacking scans met Nmap")
    parser.add_argument("-i", "--ip_range", help="IP-range scan uitvoeren (netwerk ip opgeven) [IP range scan]")
    parser.add_argument("-s", "--subnetprefix", default=None, help="Subnet prefix van het doelnetwerk [IP range scan]")
    
    parser.add_argument("-p", "--portscan", action="store_true", help="Poortscan uitvoeren [poort scan]")
    parser.add_argument("-t", "--target", default=None, help="Target ip adres of domeinnaam [poort scan (ip), cert scan (domein)]")
    parser.add_argument("-r", "--port_range", default=None, help="Range van poorten die gescand moeten worden (voorbeelde: 1,2,3; 10-30; 10,11,12-15 ) [poort scan]"),

    
    parser.add_argument("-c", "--cert", action="store_true", help="Certificate scan uitvoeren [Cert scan]")

    args = parser.parse_args()

    if args.ip_range:
        if not args.subnetprefix:
            message="Please fill in subnetprefix"
            print(message)
            return message
        scan_ip_hosts(args.ip_range, args.subnetprefix)
    if args.portscan:
        if not args.target or not args.port_range:
            message="Please fill in both target ip and port range"
            print(message)
            return message
        scan_hosts_for_open_ports(args.target, args.port_range)
    if args.cert:
        if not args.target:
            message="Please fill target domain name"
            print(message)
            return message
        scan_domain_for_cert(args.target)

if __name__ == "__main__":
    main()
