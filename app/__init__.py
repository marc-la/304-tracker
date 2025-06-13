from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)

    from app.routes.auth import auth_bp as auth_blueprint
    from app.routes.game import game_bp as game_blueprint
    from app.routes.dashboard import dashboard_bp as dashboard_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(game_blueprint)
    app.register_blueprint(dashboard_blueprint)

    return app