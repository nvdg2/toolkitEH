import json
import pathlib
from datetime import datetime
import ipaddress

targetIp = ""
port_range= ""

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

def scan_ip_hosts(target_ip_range):
    import nmap
    ping_results = {}

    nm = nmap.PortScanner()
    nm.scan(target_ip_range, arguments='-sn')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print(f"{host}:{status}")
        ping_results[host]=status


    timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    nmap_dir = pathlib.Path("nmap")
    nmap_dir.mkdir(exist_ok=True, parents=True)
    print(timestamp)
    target_ip_range = target_ip_range.replace("/", "_with_range")
    save_location = nmap_dir / f"scan_results_{target_ip_range}_{timestamp}_ping.json"
    with save_location.open("w") as json_file_ping:
        json.dump(ping_results, json_file_ping)


def scan_hosts_for_open_ports(host, port_range):
    print("scanning")
    import nmap
    host_adress=host
    try:
        ipaddress.IPv4Address(host_adress)
    except ipaddress.AddressValueError:
        exit("Ongeldig ip adres")

    port_range=generate_port_list(port_range)
    scan_results_short={}
    scan_results_raw={}
    
    for port in port_range:
        print(f"Scanning port {port}...")
        scan=nmap.PortScanner().scan(host_adress,str(port))
        state=scan["scan"][host_adress]["tcp"][port]["state"]
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
    nmap_dir = pathlib.Path("nmap")
    nmap_dir.mkdir(exist_ok=True,parents=True)

    save_location=nmap_dir/f"scan_results_{host_adress}_{timestamp}_short.json"
    with save_location.open("w") as json_file_short:
        json.dump(scan_results_short, json_file_short)
    save_location=nmap_dir/f"scan_results_{host_adress}_{timestamp}_raw.json"
    with save_location.open("w") as json_file_raw:
        json.dump(scan_results_raw, json_file_raw)