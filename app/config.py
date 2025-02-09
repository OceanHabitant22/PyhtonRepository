# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '9e6694017da11ef128f9ac144bf478da94360b526cfda27c836612ae018faf40'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vault.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    DEBUG = False
    WTF_CSRF_ENABLED = True   # Disable CSRF protection

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
