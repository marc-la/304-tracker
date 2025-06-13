from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='player')
    games = db.relationship('Game', backref='player', lazy=True)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=db.func.current_timestamp())
    best_of_stones = db.Column(db.Integer, nullable=False)
    stones = db.relationship('Stone', backref='game', lazy=True)

class Stone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    stone_number = db.Column(db.Integer, nullable=False)
    trump_value = db.Column(db.Integer, nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    winning_team = db.Column(db.Integer, db.CheckConstraint('winning_team IN (1,2)'), nullable=False)