from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user

hero_bp = Blueprint('hero', __name__)

@hero_bp.route('/')
def index():
    """Landing page route with conditional redirect for authenticated users"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    return render_template('index.html')

@hero_bp.route('/home')
def home():
    """Home page redirect to landing page"""
    return redirect(url_for('hero.index'))