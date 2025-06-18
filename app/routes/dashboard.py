from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from app.utils import get_player_statistics, get_leaderboard

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')


@dashboard_bp.route('/')
@login_required
def index():
    return render_template('dashboard.html')


@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = request.args.get('user_id') or current_user.id
    player_stats = get_player_statistics(user_id)
    return render_template('dashboard.html', stats=player_stats)


@dashboard_bp.route('/leaderboard')
@login_required
def leaderboard():
    leaderboard_data = get_leaderboard()
    return render_template('leaderboard.html', leaderboard=leaderboard_data)