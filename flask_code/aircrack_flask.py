from flask import Blueprint, url_for, render_template,request, make_response
from ..modules import aircrack_module
aircrack = Blueprint('aircrack', __name__)

@aircrack.route('/aircrack')
def show_modes():
    interfaces=aircrack_module.get_wifi_interfaces()
    return render_template('aircrack/aircrack_modes.html', interfaces=interfaces)

