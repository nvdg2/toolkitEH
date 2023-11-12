from flask import Blueprint, url_for, render_template, request, make_response
other = Blueprint('other', __name__)
import subprocess

@other.route('/other')
def show_modes():
    return render_template('other/other_modes.html')

@other.route('/other/bssid')
def bssid_scan():
    return render_template('other/bssid_scan.html')

@other.route('/other/bssid_scan/exec_bssid_scan', methods=["POST"])
def exec_bssid_scan():
    subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/other/bssid_module.py"'],shell=True)





    # target_ip = request.form["target_ip"]

    # if is_valid_ip(target_ip): # Add ip validation to prevent command injection
    #     if request.form["fake_dns_records"] == "":
    #         subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/mitm/mitm_module.py {target_ip}"'],shell=True)
    #     else:
    #         create_dns_records_file(request.form["fake_dns_records"])
    #         subprocess.Popen([f'xterm -fs 14 -fa DejaVuSansMono -e "source .venv/bin/activate && sudo python3 modules/mitm/mitm_module.py {target_ip} --dnsspoof"'],shell=True)
    #     return make_response("MITM attack started",200)
    # else:
    #     return make_response("Invalid target ip",400)