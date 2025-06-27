from flask import Blueprint

users_bp = Blueprint('coins', __name__, template_folder='templates')

from .routes import *
