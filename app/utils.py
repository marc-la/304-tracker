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

def get_player_statistics(player_id):
    # Implement your logic here
    pass

def get_leaderboard():
    # Implement your logic here
    pass