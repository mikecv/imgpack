import os
import logging

import dotsi  # type: ignore

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from flask import jsonify
from werkzeug.utils import secure_filename

from imgpack import app_settings
from imgpack.app_logging import setup_logging
from imgpack.steganography import Steganography

bp = Blueprint('images', __name__)

log = logging.getLogger(__name__)

# Load application settings.
settings = dotsi.Dict(app_settings.load("./imgpack/settings.yaml"))

# Set up application logging.
setup_logging(log.name, settings)
log.info(f"Starting application: {settings.app.APP_NAME}, version: {settings.app.APP_VERSION}")

# Instantiate the steganography class to do image procession.
log.info("Instantiation of steganography processing object.")
steg = Steganography(log, settings)

@bp.route('/')
def index():
    return render_template('/index.html')

@bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_n_path = os.path.join("imgpack/static/", settings.imgs.UPLOAD_FOLDER, filename)
        file.save(file_n_path)
        log.info(f"Upload request for image stored at : {file_n_path}")

        # Test that can set the border colour of the thumbnail
        # of the browsed/uploaded image.

        # Test border colour.
        border_color = 'blue'

        return jsonify({'thumbnail_path': url_for('static', filename=f'uploads/{filename}'), 'border_color': border_color})
    else:
        return redirect(request.url)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in settings.imgs.ALLOWED_EXT
