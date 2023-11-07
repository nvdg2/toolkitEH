from flask import Blueprint, url_for, render_template,request, make_response
mitm = Blueprint('mitm', __name__)
import ipaddress
import subprocess

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
def create_dns_records_file(fake_dns_records):
    with open("resources/mitm/fake_dns_records.txt","w") as f:
        f.write(fake_dns_records)

@mitm.route('/mitm_attack')
def mitm_attack():
    return render_template('mitm/mitm_attack.html')

@mitm.route('/mitm_attack/exec_mitm_attack', methods=["POST"])
def exec_mitm_attack():
    target_ip = request.form["target_ip"]

    if is_valid_ip(target_ip): # Add ip validation to prevent command injection
        if request.form["fake_dns_records"] == "":
            subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/mitm/mitm_module.py {target_ip}"'],shell=True)
        else:
            create_dns_records_file(request.form["fake_dns_records"])
            subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/mitm/mitm_module.py {target_ip} --dnsspoof"'],shell=True)
        return make_response("MITM attack started",200)
    else:
        return make_response("Invalid target ip",400)
