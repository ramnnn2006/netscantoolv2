from flask import Flask, render_template
from flask_cors import CORS
from api.routes import api_bp
import logging
from config import Config
from dotenv import load_dotenv

load_dotenv()

def create_app():
    application = Flask(__name__)
    application.config.from_object(Config)
    CORS(application)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    application.register_blueprint(api_bp, url_prefix='/api')

    @application.route('/')
    def index():
        return render_template('index.html')

    return application

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
