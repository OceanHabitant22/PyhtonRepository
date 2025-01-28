import os
class Config:
    SECRET_KEY = 'your_secret_key'  # Для безопасности (например, сессии, CSRF токены)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'  # Путь к базе данных
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Отключение отслеживания изменений
    DEBUG = True  # Включить режим отладки