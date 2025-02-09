# config.py
import os

class Config:
    # Чтение секретного ключа из переменной окружения (.env) или использование значения по умолчанию (для разработки)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'default_secret_key'
    
    # Настройка базы данных
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vault.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Папка для загрузки файлов
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    
    # Ограничение на размер загружаемых файлов
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    
    DEBUG = False
    
    # Настройки для Flask-Mail (используются, например, для сброса пароля)
    MAIL_SERVER = 'smtp.mail.ru'   # если используете Mail.ru; для Gmail: 'smtp.gmail.com'
    MAIL_PORT = 465                # для Mail.ru (SSL)
    MAIL_USE_SSL = True            # для Mail.ru
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'vaultguard@mail.ru'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'your_mail_password'
    
    # Включение CSRF защиты через Flask-WTF
    WTF_CSRF_ENABLED = True

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
