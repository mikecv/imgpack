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

"""
Route for default application icon.
"""
@bp.route("/favicon.ico")
def favicon():
    return url_for('static', filename='favicon.ico')

"""
Route for start home page.
Where user can browse for an image to upload.
"""
@bp.route('/')
def index():
    return render_template('/index.html')

"""
Route for when user selects to uploaded the browseed image.
This sends the image to be checked in the steganography function.
This will result in the image bitmap being redrawn abd
a coloured border added (a different colour if it containes
embedded data).
"""
@bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        log.info(f"Upload request for image filename: {filename}")
        file_n_path = os.path.join("imgpack/static/", settings.imgs.UPLOAD_FOLDER, filename)
        file.save(file_n_path)
        log.info(f"Upload request for image stored at: {file_n_path}")

        # Load the file into steganofraphy object for processing.
        steg.initPicSettings()
        steg.load_image(file_n_path)
 
        # Set border colour of thumbnail according to whether
        # file is encoded or not.
        if steg.pic_coded:
            border_colour = settings.thumb.Border_Col_Code
        else:
            border_colour = settings.thumb.Border_Col_None

        # Return border colour for the thumbnail back to UI handler.
        return jsonify({'thumbnail_path': url_for('static', filename=f'uploads/{filename}'), 'border-color': border_colour})
    else:
        return redirect(request.url)

@bp.route('/check_for_thumbnails', methods=['GET', 'POST'])
def update_thumbnails():
    log.info("Poll from frontend triggered.")

    # Test list of json struncturs.
    images = jsonify({
            "thumbnails": [
                {
                "thumbnail_path": "imgpack/static/uploads/rabbit.png",
                "border-color": "red"
                },
                {
                "thumbnail_path": "imgpack/static/uploads/Genieva.png",
                "border-color": "blue"
                },
                {
                "thumbnail_path": "imgpack/static/uploads/film.png",
                "border-color": "green"
                }
            ]
        }
    )
    return images

"""
Function for checking if browsed image is of allowed type.
"""
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in settings.imgs.ALLOWED_EXT
