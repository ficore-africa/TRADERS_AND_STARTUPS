from flask import Blueprint

forecasts_bp = Blueprint('forecasts', __name__, template_folder='templates')

from .routes import *
