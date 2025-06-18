from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_required
from app.utils import get_player_statistics, get_leaderboard

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    # Get all data needed for the dashboard
    player_stats = get_player_statistics(None)  # Get stats for all players or default
    leaderboard_data = get_leaderboard()
    
    return render_template('dashboard.html', 
                          players=player_stats, 
                          leaderboard=leaderboard_data)

@dashboard_bp.route('/dashboard/leaderboard')
@login_required
def leaderboard():
    leaderboard_data = get_leaderboard()
    return render_template('leaderboard.html', players=leaderboard_data)