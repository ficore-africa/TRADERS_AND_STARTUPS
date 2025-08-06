from flask import Blueprint

users_bp = Blueprint('admin', __name__, template_folder='templates')

from .routes import *
