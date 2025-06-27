from flask import Blueprint

users_bp = Blueprint('inventory', __name__, template_folder='templates')

from .routes import *
