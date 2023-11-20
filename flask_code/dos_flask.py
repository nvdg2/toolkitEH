from flask import Blueprint, url_for, render_template,request, make_response
import subprocess
dos = Blueprint('dos', __name__)
import os
@dos.route('/dos')
def show_modes():
    return render_template('dos/dos_modes.html')

@dos.route('/dos/http')
def http():
    return render_template('dos/dos_http_attack.html')

@dos.route('/dos/deauth')
def deauth():
    return render_template('dos/dos_deauth_attack.html')

@dos.route('/dos/starvation')
def starvation():
    return render_template('dos/dos_starvation_attack.html')

@dos.route('/dos/http/exec_http_dos',methods=["POST"])
def exec_http_attack():
    isDistributed = False
    command=[]
    if "distributed_checkbox" in request.form:
        isDistributed = True
        command = [
            "python3",  # Het Python-interpretercommando
            "modules/dos/http_module.py",  # Vervang dit door het daadwerkelijke pad naar je script
            request.form['target_host'],
            request.form['target_port'],
            "--distributed" ,  # Voeg "--distributed" toe als isDistributed waar is
            "--bot_list", request.form['bot_list'],
            "--private_key", request.form['private_key_file_location'],
            "--password", request.form['private_key_file_password']
        ]
    else:
        command=[
            "python3",  # Het Python-interpretercommando
            "modules/dos/http_module.py",  
            request.form['target_host'],
            request.form['target_port'],
        ]
    ps1=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return request.form

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

@dos.route('/dos/starvation/exec_starvation_dos',methods=["POST"])
def exec_starvation_attack():
    interface=request.form["interface"]
    subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/dos/starvation_module.py --interface {interface}"'],shell=True)
    return make_response("Starvation attack started",200)