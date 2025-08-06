from flask import Blueprint

funds_bp = Blueprint('funds', __name__, template_folder='templates')

from .routes import *
