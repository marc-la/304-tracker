def validate_email(email):
    import re
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def format_timestamp(timestamp):
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')

def calculate_win_rate(wins, total_games):
    if total_games == 0:
        return 0
    return (wins / total_games) * 100

def generate_leaderboard_data(players):
    leaderboard = sorted(players, key=lambda x: x['win_rate'], reverse=True)
    return leaderboard

def log_game_action(action, player_id, game_id):
    import logging
    logging.basicConfig(level=logging.INFO)
    logging.info(f'Action: {action}, Player ID: {player_id}, Game ID: {game_id}')

def get_player_statistics(player_id=None):
    # Implement actual statistics gathering from database
    # For now, return dummy data to prevent template errors
    return [
        {'name': 'Player 1', 'games_played': 10, 'stones_won': 25, 'average_trump_value': 190, 'win_rate': 65},
        {'name': 'Player 2', 'games_played': 8, 'stones_won': 18, 'average_trump_value': 185, 'win_rate': 58},
        {'name': 'Player 3', 'games_played': 12, 'stones_won': 20, 'average_trump_value': 175, 'win_rate': 42}
    ]

def get_leaderboard():
    # Implement actual leaderboard data retrieval from database
    # For now, return dummy data to prevent template errors
    return [
        {'name': 'Player 1', 'total_points': 350},
        {'name': 'Player 2', 'total_points': 280},
        {'name': 'Player 3', 'total_points': 220}
    ]