from flask import Blueprint, url_for, render_template,request, make_response
from ..modules import nmap_module
nmap = Blueprint('nmap', __name__)

@nmap.route('/nmap')
def show_modes():
    return render_template('nmap/nmap_modes.html')

@nmap.route('/nmap/portscan')
def portscan():
    return render_template('nmap/nmap_portscan.html')

@nmap.route('/nmap/pingscan')
def pingscan():
    return render_template('nmap/nmap_ping_scan.html')

@nmap.route('/nmap/certscan')
def certscan():
    return render_template('nmap/nmap_cert_scan.html')

@nmap.route('/nmap/portscan/exec_port_scan', methods=["POST"])
def exec_port_scan():
    response = nmap_module.scan_hosts_for_open_ports(request.form["target_ip"],request.form["port_range"])
    if response == True:
        return make_response("Scan succesfull",200)
    else:
        return make_response(f"{str(response)}",500)

@nmap.route('/nmap/pingscan/exec_ping_scan', methods=["POST"])
def exec_ping_scan():
    response = nmap_module.scan_ip_hosts(request.form["target_ip"],request.form["subnet_mask"])
    if response == True:
        return make_response("Scan succesfull",200)
    else:
        return make_response(f"{str(response)}",500)

@nmap.route('/nmap/certscan/exec_cert_scan', methods=["POST"])
def exec_cert_scan():
    response = nmap_module.scan_domain_for_cert(request.form["domain"])
    if response == True:
        return make_response("Scan succesfull",200)
    else:
        return make_response(f"{str(response)}",500)