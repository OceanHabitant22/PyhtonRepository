import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from .config import Config

# Инициализация базы данных, миграций и CSRF-защиты
db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'your_secret_key'

    # Настройка конфигурации
    app.config.from_object(Config)

    # Инициализация расширений
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    # Регистрируем Blueprint
    from .routes import main
    app.register_blueprint(main)

    # Логирование ошибок в файл
    if not app.debug:
        handler = RotatingFileHandler('app.log', maxBytes=10240, backupCount=3)
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)

    return app
