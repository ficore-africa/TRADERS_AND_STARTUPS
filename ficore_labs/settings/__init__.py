from flask import Blueprint

users_bp = Blueprint('settings', __name__, template_folder='templates')

from .routes import *
