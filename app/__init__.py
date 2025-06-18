from flask import Flask, jsonify
import logging
from .extensions import db, migrate, login_manager, mail, limiter, csrf

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
    csrf.init_app(app)

    # Import models here, after db is initialized
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            app.logger.error(f"Error loading user: {e}")
            return None

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.game import game_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.hero import hero_bp
    
    app.register_blueprint(hero_bp)  # No url_prefix for hero routes
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(game_bp)  # No prefix since routes include /game
    app.register_blueprint(dashboard_bp)  # No prefix since routes include /dashboard
    
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://code.jquery.com; style-src 'self'"
        return response
    
    # Global error handler
    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error(f"Unhandled exception: {e}")
        return jsonify({"error": "Internal server error"}), 500

    return app