from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from app.utils import get_player_statistics, get_leaderboard

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')


@dashboard_bp.route('/')
def index():
    return render_template('dashboard.html')


@dashboard_bp.route('/leaderboard')
def leaderboard():
    leaderboard_data = get_leaderboard()
    return render_template('leaderboard.html', leaderboard=leaderboard_data)