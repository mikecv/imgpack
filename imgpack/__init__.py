import os

from flask import Flask

def create_app(test_config=None):
    # Create and configure the app.
    app = Flask(__name__)
    app.config.from_pyfile("config.py")

    # A simple page that says hello.
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    # Register blueprint for image coding.
    from . import image_pack
    app.register_blueprint(image_pack.bp)
    app.add_url_rule('/', endpoint='index')

    return app
