from flask import Blueprint, url_for, render_template,request, make_response
import subprocess
dos = Blueprint('dos', __name__)
import os
@dos.route('/dos')
def show_modes():
    return render_template('dos/dos_modes.html')

@dos.route('/dos/http')
def http():
    return render_template('injection/injection_xss_scan.html')

@dos.route('/dos/deauth')
def deauth():
    return render_template('dos/dos_deauth_attack.html')

@dos.route('/dos/http/exec_http_dos',methods=["POST"])
def exec_http_attack():
    return None

@dos.route('/dos/deauth/exec_deauth_dos',methods=["POST"])
def exec_deauth_attack():
    pass_input = [
        "echo",
        request.form['root_password'],
    ]
    execute_deauth = [
        "sudo",
        "-S",
        "-k",
        "python",
        "modules/dos/deauth_module.py",
        request.form['mac_address_access_point'],
        request.form['mac_address_target_device'],
        request.form['amount_of_deauth_packets']
    ]
    ps1 = subprocess.Popen(pass_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    ps2 = subprocess.Popen(execute_deauth, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout1, stderr1 = ps1.communicate()
    ps2.stdin.write(stdout1)
    print(ps2.communicate())

    return make_response("Deauth attack executed",200)
