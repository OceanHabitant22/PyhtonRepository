from flask import Flask
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
csrf = CSRFProtect(app)
class Config:
    SECRET_KEY = 'your-strong-secret-key-here'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = 'different-secret-key-for-csrf'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vault.db'  # Путь к базе данных
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Отключение отслеживания изменений
    DEBUG = True  # Включить режим отладки