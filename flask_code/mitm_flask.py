from flask import Blueprint, url_for, render_template,request, make_response
mitm = Blueprint('mitm', __name__)
import ipaddress
import subprocess

@mitm.route('/mitm_attack')
def mitm_attack():
    return render_template('mitm/mitm_attack.html')

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

@mitm.route('/mitm_attack/exec_mitm_attack', methods=["POST"])
def exec_mitm_attack():
    target_ip = request.form["target_ip"] 
    if is_valid_ip(target_ip): # Add ip validation to prevent command injection
        subprocess.run([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/mitm/mitm_module.py {target_ip}"'],shell=True)
        return make_response("MITM attack succesfull",200)
    else:
        return make_response("Invalid target ip",400)
