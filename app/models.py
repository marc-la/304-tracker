from .extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import hashlib
from flask import current_app
from datetime import datetime, timedelta  # Add timedelta import

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)  # Add index for email lookups
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='player', index=True)  # Add index for role-based queries
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    games = db.relationship('Game', backref='player', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        salt = hashlib.sha256((str(self.id) + self.email + 'email-confirm' + current_app.config['SECRET_KEY']).encode()).hexdigest()
        return serializer.dumps(self.email, salt=salt)

    @staticmethod
    def confirm_token(token, expiration=3600):
        from app.models import User
        for user in User.query.all():
            serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            salt = hashlib.sha256((str(user.id) + user.email + 'email-confirm' + current_app.config['SECRET_KEY']).encode()).hexdigest()
            try:
                email = serializer.loads(token, salt=salt, max_age=expiration)
                return email
            except Exception:
                continue
        return None

    def generate_reset_token(self, expires_sec=3600):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        salt = hashlib.sha256((str(self.id) + self.email + 'password-reset' + current_app.config['SECRET_KEY']).encode()).hexdigest()
        return serializer.dumps(self.email, salt=salt)

    @staticmethod
    def verify_reset_token(token, expires_sec=3600):
        from app.models import User
        for user in User.query.all():
            serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            salt = hashlib.sha256((str(user.id) + user.email + 'password-reset' + current_app.config['SECRET_KEY']).encode()).hexdigest()
            try:
                email = serializer.loads(token, salt=salt, max_age=expires_sec)
                return user
            except Exception:
                continue
        return None
    
    def record_login(self, success=True):
        """Record login attempt"""
        if success:
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
            self.account_locked_until = None
        else:
            self.failed_login_attempts += 1
            # Lock account after 5 failed attempts
            if self.failed_login_attempts >= 5:
                self.account_locked_until = datetime.utcnow() + current_app.config.get('ACCOUNT_LOCKOUT_DURATION', 
                                                                                      timedelta(minutes=30))
        db.session.commit()

class Game(db.Model):
    __tablename__ = 'game'
    
    id = db.Column(db.Integer, primary_key=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)  # Add index
    date = db.Column(db.DateTime, default=db.func.current_timestamp(), index=True)  # Add index for date lookups
    best_of_stones = db.Column(db.Integer, nullable=False)
    stones = db.relationship('Stone', backref='game', lazy=True)

class Stone(db.Model):
    __tablename__ = 'stone'
    
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False, index=True)  # Add index
    stone_number = db.Column(db.Integer, nullable=False)
    trump_value = db.Column(db.Integer, nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)  # Add index
    winning_team = db.Column(db.Integer, db.CheckConstraint('winning_team IN (1,2)'), nullable=False)
    
    # Create composite index for faster lookups by game and stone number
    __table_args__ = (db.Index('idx_game_stone', 'game_id', 'stone_number'),)