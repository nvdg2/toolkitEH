from flask import Blueprint, url_for, render_template,request, make_response
from . import nmap_module
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

@nmap.route('/nmap/portscan/exec_port_scan', methods=["POST"])
def exec_port_scan():
    nmap_module.scan_hosts_for_open_ports(request.form["target_ip"],request.form["port_range"])
    return make_response("Scan succesfull",200)

@nmap.route('/nmap/pingscan/exec_ping_scan', methods=["POST"])
def exec_ping_scan():
    print(request.form)
    nmap_module.scan_ip_hosts(request.form["target_ip_range"])
    return make_response("Scan succesfull",200)