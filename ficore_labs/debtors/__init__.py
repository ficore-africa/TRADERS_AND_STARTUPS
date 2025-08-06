from flask import Blueprint

users_bp = Blueprint('debtors', __name__, template_folder='templates')

from .routes import *
