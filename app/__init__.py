import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from .config import Config
from .routes import main  # Импортируем main, который является Blueprint

# Инициализация базы данных и миграций
db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # Настройка конфигурации
    app.config.from_object(Config)
    app.config['DEBUG'] = True  # Включаем отладку

    # Логирование ошибок в файл
    if not app.debug:
        # Настройка обработчика для логирования в файл
        handler = RotatingFileHandler('app.log', maxBytes=10240, backupCount=3)  # Пишем в файл app.log
        handler.setLevel(logging.ERROR)  # Записываем только ошибки и более серьезные события
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)

    # Инициализация базы данных и миграций
    db.init_app(app)
    migrate.init_app(app, db)

    # Регистрируем Blueprint
    app.register_blueprint(main)

    return app
