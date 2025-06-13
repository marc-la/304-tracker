from flask import Blueprint, render_template, request
from app.models import User, Game, Stone
from app.utils import get_player_statistics, get_leaderboard

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def dashboard():
    user_id = request.args.get('user_id')  # Assuming user_id is passed as a query parameter
    player_stats = get_player_statistics(user_id)
    return render_template('dashboard.html', stats=player_stats)

@dashboard_bp.route('/leaderboard')
def leaderboard():
    leaderboard_data = get_leaderboard()
    return render_template('leaderboard.html', leaderboard=leaderboard_data)