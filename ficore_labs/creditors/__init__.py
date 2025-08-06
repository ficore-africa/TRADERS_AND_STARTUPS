from flask import Blueprint

users_bp = Blueprint('creditors', __name__, template_folder='templates')

from .routes import *
