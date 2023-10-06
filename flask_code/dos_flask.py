from flask import Blueprint, url_for, render_template,request, make_response
from ..modules import xss_module
dos = Blueprint('dos', __name__)

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
    return xss_module.perform_XSS_scan(request.form["target_url"])

@dos.route('/dos/deauth/exec_deauth_dos',methods=["POST"])
def exec_deauth_attack():
    return xss_module.perform_XSS_scan(request.form["target_url"])
