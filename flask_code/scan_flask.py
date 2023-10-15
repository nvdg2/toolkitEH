from flask import Blueprint, url_for, render_template,request, make_response
from ..modules import nmap_module
from..modules import scapy_module
import subprocess
scan = Blueprint('scan', __name__)

def execute_sudo_scan(command):
    pass_input = [
        "echo",
        request.form['root_password'],
    ]
    ps1 = subprocess.Popen(pass_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    ps2 = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout1, stderr1 = ps1.communicate()
    ps2.stdin.write(stdout1)
    print(ps2.communicate())



# SHOW MODES
@scan.route('/scan')
def show_modes():
    return render_template('scans/scan_modes.html')

# NMAP ROUTES
@scan.route('/scan/nmap/portscan')
def nmap_portscan():
    return render_template('scans/nmap/nmap_portscan.html')

@scan.route('/scan/nmap/pingscan')
def nmap_pingscan():
    return render_template('scans/nmap/nmap_ping_scan.html')

@scan.route('/scan/nmap/certscan')
def nmap_certscan():
    return render_template('scans/nmap/nmap_cert_scan.html')

# SCAPY ROUTES
@scan.route('/scan/scapy/arpscan')
def scapy_arpscan():
    return render_template('scans/scapy/scapy_arp_scan.html')

@scan.route('/scan/scapy/portscan')
def scapy_portscan():
    return render_template('scans/scapy/scapy_portscan.html')

@scan.route('/scan/scapy/osscan')
def scapy_osscan():
    return render_template('scans/scapy/scapy_os_scan.html')

@scan.route('/scan/scapy/pcapscan')
def scapy_pcapscan():
    return render_template('scans/scapy/scapy_pcap_scan.html')

# EXECUTE NMAP SCANS
@scan.route('/scan/nmap/portscan/exec_port_scan', methods=["POST"])
def exec_nmap_port_scan():
    response = nmap_module.scan_hosts_for_open_ports(request.form["target_ip"],request.form["port_range"])
    if response == True:
        return make_response("Scan succesfull",200)
    else:
        return make_response(f"{str(response)}",500)

@scan.route('/scan/nmap/pingscan/exec_ping_scan', methods=["POST"])
def exec_nmap_ping_scan():
    response = nmap_module.scan_ip_hosts(request.form["target_ip"],request.form["subnet_mask"])
    if response == True:
        return make_response("Scan succesfull",200)
    else:
        return make_response(f"{str(response)}",500)

@scan.route('/scan/nmap/certscan/exec_cert_scan', methods=["POST"])
def exec_nmap_cert_scan():
    response = nmap_module.scan_domain_for_cert(request.form["domain"])
    if response == True:
        return make_response("Scan succesfull",200)
    else:
        return make_response(f"{str(response)}",500)

# EXECUTE SCAPY SCANS    
@scan.route('/scan/scapy/arpscan/exec_arp_scan', methods=["POST"])
def exec_scapy_arp_scan():
    ip_range=f"{request.form['target_ip']}/{request.form['subnet_mask']}"
    execute_sudo_scan(["sudo","-S","-k","python","modules/scapy_module.py","-i",ip_range])
    print("ARP SCAN UITGEVOERD, logfiles worden gegenereerd")
    return make_response("Arp scan finished",200)

@scan.route('/scan/scapy/portscan/exec_port_scan', methods=["POST"])
def exec_scapy_port_scan():
    execute_sudo_scan(["sudo","-S","-k","python","modules/scapy_module.py","-t",request.form['target_ip'],"-p"])
    print("PORT SCAN UITGEVOERD, logfiles worden gegenereerd")
    return make_response("Port scan finished",200)

@scan.route('/scan/scapy/osscan/exec_os_scan', methods=["POST"])
def exec_scapy_os_scan():
    execute_sudo_scan(["sudo","-S","-k","python","modules/scapy_module.py","-t",request.form['target_ip'],"-o"])
    print("OS SCAN UITGEVOERD, logfiles worden gegenereerd")
    return make_response("OS scan finished",200)

@scan.route('/scan/scapy/pcapscan/exec_pcap_scan', methods=["POST"])
def exec_scapy_pcap_scan():
    execute_sudo_scan(["sudo","-S","-k","python","modules/scapy_module.py","-a",request.form['pcap_file']])
    return make_response("PCAP scan finished, logfiles worden gegenereerd",200)