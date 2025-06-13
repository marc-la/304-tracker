from flask import Blueprint

# Initialize the routes blueprint
routes_bp = Blueprint('routes', __name__)

# Import the individual route modules
from .auth import *
from .game import *
from .dashboard import *