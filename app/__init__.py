from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address)

def configure_logging(app):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    app.logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    configure_logging(app)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    mail.init_app(app)

    limiter.init_app(app)

    # Import models here, after db is initialized
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.routes.auth import auth_bp
    from app.routes.game import game_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(game_bp)
    app.register_blueprint(dashboard_bp)

    return app