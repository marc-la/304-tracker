from flask import Blueprint, request, jsonify, render_template, current_app
from app.models import Game, Stone
from flask_login import login_required, current_user
from app.extensions import db

game_bp = Blueprint('game', __name__)

@game_bp.route('/game/start', methods=['POST'])
@login_required
# Remove the incorrect @csrf.protect decorator - Flask-WTF protects all POST routes automatically
def start_game():
    try:
        data = request.json
        
        # Validate input data
        if not data or 'best_of_stones' not in data:
            return jsonify({'error': 'Missing required field: best_of_stones'}), 400
            
        new_game = Game(created_by=current_user.id, best_of_stones=data['best_of_stones'])
        db.session.add(new_game)
        db.session.commit()
        return jsonify({'message': 'Game started', 'game_id': new_game.id}), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating game: {str(e)}")
        return jsonify({'error': 'Failed to create game'}), 500

@game_bp.route('/game/<int:game_id>/log_stone', methods=['POST'])
@login_required
# Remove the incorrect @csrf.protect decorator
def log_stone(game_id):
    try:
        # Check if game exists and belongs to current user
        game = Game.query.get(game_id)
        if not game:
            return jsonify({'error': 'Game not found'}), 404
        
        data = request.json
        
        # Validate input data
        required_fields = ['stone_number', 'trump_value', 'winning_team']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        new_stone = Stone(
            game_id=game_id,
            stone_number=data['stone_number'],
            trump_value=data['trump_value'],
            bidder_id=current_user.id,
            winning_team=data['winning_team']
        )
        db.session.add(new_stone)
        db.session.commit()
        return jsonify({'message': 'Stone logged', 'stone_id': new_stone.id}), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error logging stone: {str(e)}")
        return jsonify({'error': 'Failed to log stone'}), 500

# Add error handling to all endpoints
@game_bp.route('/game/<int:game_id>/stats', methods=['GET'])
@login_required
def get_game_stats(game_id):
    try:
        game = Game.query.get_or_404(game_id)
        stones = Stone.query.filter_by(game_id=game_id).all()
        
        # Calculate statistics
        team1_stones = sum(1 for stone in stones if stone.winning_team == 1)
        team2_stones = sum(1 for stone in stones if stone.winning_team == 2)
        
        stats = {
            'total_stones': len(stones),
            'team1_stones': team1_stones,
            'team2_stones': team2_stones,
            'winning_team': 1 if team1_stones > team2_stones else 2 if team2_stones > team1_stones else None,
            'stones': [{'stone_number': stone.stone_number, 
                        'trump_value': stone.trump_value, 
                        'bidder': stone.bidder_id,
                        'winning_team': stone.winning_team} for stone in stones]
        }
        return jsonify(stats), 200
    except Exception as e:
        current_app.logger.error(f"Error getting game stats: {str(e)}")
        return jsonify({'error': 'Failed to retrieve game statistics'}), 500

@game_bp.route('/game/<int:game_id>/log', methods=['GET'])
@login_required
def game_log(game_id):
    return render_template('game_log.html', game_id=game_id)

@game_bp.route('/game/log')
def log():
    # logic for general game log
    return render_template('game_log.html')