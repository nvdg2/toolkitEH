from rich.console import Console
from rich.table import Table
from rich.text import Text
import nmap
import json
import pathlib
from datetime import datetime
from advancedTable import AdvancedTable
from ui import navigate, set_value
 
targetIp = ""
port_range= ""
def load():
    navigate(create_nmap_modes_table())

def create_nmap_modes_table():
    title = Text("Pentesting tool - Nmap")
    title.stylize("bold red")
    table = Table(title=title, style="red")

    table.add_column("Mode", justify="left", style="bold white", no_wrap=True)
    table.add_column("Info", style="magenta")

    table.add_row("Port scan", "Een port scan uitvoeren op een specifieke host")
    table.add_row("Ping scan", "Een ping scan uitvoeren op een reeks van hosts")
    
    functions = [
        lambda: navigate(create_scan_hosts_table())
    ]

    advancedTable = AdvancedTable(table, functions)
    return advancedTable

def create_scan_hosts_table(target_ip="empty", port_range="empty"):
    title = Text("Pentesting tool - Nmap - scan host ports")
    title.stylize("bold red")
    table = Table(title=title, style="red")

    table.add_column("Setting", justify="left", style="bold white", no_wrap=True)
    table.add_column("Info", style="magenta")
    table.add_column("value", style="magenta")

    table.add_row("Ip adress", "Het adres van de target host",target_ip)
    table.add_row("Ports", "De range van poorten. Mogelijke layout: '24,25,44-50,8080'",port_range)


    functions = [
        lambda: navigate(create_scan_hosts_table(input("test"),"test"))
    ]

    advancedTable = AdvancedTable(table, functions)
    return advancedTable

def parse_port_range(port_range):
    port_list = []
    ranges = port_range.split(',')
    
    for r in ranges:
        parts = r.split('-')
        print(parts)
        if len(parts) == 1:
            port_list.append(int(parts[0]))
        elif len(parts) == 2:
            start_port = int(parts[0])
            end_port = int(parts[1])
            port_list.extend(range(start_port, end_port + 1))
        else:
            raise ValueError("Ongeldige poortnotatie: {}".format(r))
    return port_list


def scan_hosts_for_open_ports():
    ip_adress="127.0.0.1"
    portlist=[22,23,24,25,26]
    scan_results_short={}
    scan_results_raw={}
    
    for port in portlist:
        scan=nmap.PortScanner().scan(ip_adress,str(port))
        state=scan["scan"][ip_adress]["tcp"][port]["state"]
        protocol_name=scan["scan"][ip_adress]["tcp"][port]["name"]
        reason=scan["scan"][ip_adress]["tcp"][port]["reason"]
        version=scan["scan"][ip_adress]["tcp"][port]["version"]

        scan_results_short[port]={
            "state": state,
            "protocol_name": protocol_name,
            "reason": reason,
            "version": version
        }
        scan_results_raw[port]= scan["scan"][ip_adress]

    timestamp = datetime.now().strftime("%d%m%Y%H%M%S")
    nmap_dir = pathlib.Path("nmap")
    nmap_dir.mkdir(exist_ok=True,parents=True)

    save_location=nmap_dir/f"scan_results_{ip_adress}_{timestamp}_short.json"
    with save_location.open("w") as json_file_short:
        json.dump(scan_results_short, json_file_short)
    save_location=nmap_dir/f"scan_results_{ip_adress}_{timestamp}_raw.json"
    with save_location.open("w") as json_file_raw:
        json.dump(scan_results_raw, json_file_raw)