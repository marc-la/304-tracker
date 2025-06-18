import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
    DEBUG = os.environ.get('DEBUG', 'False') == 'True'
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY = True       # Prevent JavaScript access to cookies
    REMEMBER_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # Only send remember-me cookies over HTTPS
    REMEMBER_COOKIE_HTTPONLY = True      # Prevent JavaScript access to remember-me cookies
    SESSION_COOKIE_SAMESITE = 'Lax'      # Helps protect against CSRF