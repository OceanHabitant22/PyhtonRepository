from flask import Flask
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

AWS_BUCKET_NAME = 'your-bucket-name'
AWS_ACCESS_KEY = 'your-access-key'
AWS_SECRET_KEY = 'your-secret-key'
AWS_REGION = 'your-region'  

class Config:
    SECRET_KEY = 'your-strong-secret-key-here'
    WTF_CSRF_ENABLED = False  # Disable CSRF protection
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vault.db'  # Путь к базе данных
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Отключение отслеживания изменений
    DEBUG = True  # Включить режим отладки

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
