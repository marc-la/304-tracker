from flask import Blueprint

# Remove routes_bp and just import blueprints for registration in app/__init__.py
from .auth import auth_bp
from .dashboard import dashboard_bp
from .game import game_bp
from .hero import hero_bp

