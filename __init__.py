from flask import Flask
from .main import main as main_blueprint
from .flask_code.scan_flask import scan as scan_blueprint
from .flask_code.aircrack_flask import aircrack as aircrack_blueprint
from .flask_code.injection_flask import injection as injection_blueprint
from .flask_code.dos_flask import dos as dos_blueprint
def create_app():
    app = Flask(__name__)

    app.register_blueprint(main_blueprint)
    app.register_blueprint(scan_blueprint)
    app.register_blueprint(aircrack_blueprint)
    app.register_blueprint(injection_blueprint)
    app.register_blueprint(dos_blueprint)

    return app
    

if __name__ == "__main__":
    create_app()