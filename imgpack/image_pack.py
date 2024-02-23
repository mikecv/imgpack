from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('images', __name__)

@bp.route('/')
def index():
    return render_template('images/index.html')
