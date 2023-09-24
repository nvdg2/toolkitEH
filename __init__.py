from flask import Flask
from .main import main as main_blueprint
from .nmap_flask import nmap as nmap_blueprint

def create_app():
    app = Flask(__name__)

    app.register_blueprint(main_blueprint)
    app.register_blueprint(nmap_blueprint)

    return app
    

if __name__ == "__main__":
    create_app()