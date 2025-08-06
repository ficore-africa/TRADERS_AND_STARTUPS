from flask import Blueprint

users_bp = Blueprint('payments', __name__, template_folder='templates')

from .routes import *
