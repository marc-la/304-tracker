from flask import Blueprint, request, jsonify, render_template
from app.models import Game, Stone, db
from flask_login import login_required, current_user

game_bp = Blueprint('game', __name__)

@game_bp.route('/game/start', methods=['POST'])
@login_required
def start_game():
    data = request.json
    new_game = Game(created_by=current_user.id, best_of_stones=data['best_of_stones'])
    db.session.add(new_game)
    db.session.commit()
    return jsonify({'message': 'Game started', 'game_id': new_game.id}), 201

@game_bp.route('/game/<int:game_id>/log_stone', methods=['POST'])
@login_required
def log_stone(game_id):
    data = request.json
    new_stone = Stone(
        game_id=game_id,  # Fixed 'match_id' to 'game_id'
        stone_number=data['stone_number'],
        trump_value=data['trump_value'],
        bidder_id=current_user.id,
        winning_team=data['winning_team']
    )
    db.session.add(new_stone)
    db.session.commit()
    return jsonify({'message': 'Stone logged', 'stone_id': new_stone.id}), 201

@game_bp.route('/game/<int:game_id>/stats', methods=['GET'])
@login_required
def get_game_stats(game_id):
    game = Game.query.get_or_404(game_id)
    stones = Stone.query.filter_by(game_id=game_id).all()
    stats = {
        'total_stones': len(stones),
        'winning_team': 1,  # Simplified, implement proper logic
        'stones': [{'stone_number': stone.stone_number, 'trump_value': stone.trump_value, 'bidder': stone.bidder_id} for stone in stones]
    }
    return jsonify(stats), 200

@game_bp.route('/game/<int:game_id>/log', methods=['GET'])
@login_required
def game_log(game_id):
    return render_template('game_log.html', game_id=game_id)