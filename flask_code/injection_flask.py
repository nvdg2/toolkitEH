from flask import Blueprint, url_for, render_template,request, make_response
from ..modules import xss_module
injection = Blueprint('injection', __name__)

@injection.route('/injection')
def show_modes():
    return render_template('injection/injection_modes.html')

@injection.route('/injection/xssscan')
def xssscan():
    return render_template('injection/injection_xss_scan.html')

@injection.route('/injection/xssscan/exec_xss_scan',methods=["POST"])
def exec_xss_scan():
    return xss_module.perform_XSS_scan(request.form["target_url"])

