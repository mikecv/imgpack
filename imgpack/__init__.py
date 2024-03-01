import os

from flask import Flask
from flask_cors import CORS

def create_app(test_config=None):
    # Create and configure the app.
    app = Flask(__name__, static_url_path='/imgpack/static')
    app.config.from_pyfile("config.py")
    # Enable CORS for all origins.
    CORS(app)

    # A simple page that says hello.
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    # Register blueprint for image coding.
    from . import image_pack
    app.register_blueprint(image_pack.bp)
    app.add_url_rule('/', endpoint='index')

    return app
