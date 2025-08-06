from flask import Blueprint

users_bp = Blueprint('reports', __name__, template_folder='templates')

from .routes import *
