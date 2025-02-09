import logging
from dotenv import load_dotenv

# Загрузка переменных окружения из файла .env
load_dotenv()

# Настройка базового логгера: уровень INFO, формат сообщений и запись в файл app.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    filename='app.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

import os
import threading
import time
from flask import Flask
from flask_migrate import Migrate
from app.config import DevelopmentConfig
from app.myextensions import db, login_manager
from app.routes import main as main_blueprint
from configparser import ConfigParser
from flask_jwt_extended import JWTManager
from flask_mail import Mail

# Инициализируем объект Flask-Mail глобально
mail = Mail()

def create_app(config_class=DevelopmentConfig):
    from app.myextensions import db, login_manager
    app = Flask(__name__, template_folder='templates')
    app.config.from_object(config_class)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or '2ba2058a954592843fe32e98393f676c45af73d263dce3a0d7425ce1a044ff3a'
    
    jwt = JWTManager(app)
    mail.init_app(app)  # Инициализация Flask-Mail

    # Убедиться, что папка для загрузки существует
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Инициализация расширений
    db.init_app(app)
    login_manager.init_app(app)

    # Инициализация Flask-Migrate
    migrate = Migrate(app, db)

    # Регистрация blueprints
    app.register_blueprint(main_blueprint)
    logger.info("Registered blueprints: %s", app.blueprints)

    # Создание таблиц базы данных (если их нет)
    with app.app_context():
        db.create_all()

    # Создание сериализатора для токенов сброса пароля с помощью itsdangerous
    from itsdangerous import URLSafeTimedSerializer
    app.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    return app

# Регистрация user_loader для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))

def rotate_keys(app):
    """
    Ротация RSA ключей для всех пользователей с повторным шифрованием файлов новым ключом.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from app.models import User, RSAKey, File
    from app.crypto import generate_rsa_keys

    with app.app_context():
        users = User.query.all()
        for user in users:
            current_key = RSAKey.query.filter_by(user_id=user.id).order_by(RSAKey.created_at.desc()).first()
            old_version = current_key.key_version if current_key else 0

            # Генерация новых RSA ключей
            new_public, new_private = generate_rsa_keys()
            new_version = old_version + 1

            # Сохранение нового ключа
            new_key_record = RSAKey(
                user_id=user.id,
                public_key=new_public,
                private_key=new_private,
                key_version=new_version
            )
            db.session.add(new_key_record)
            db.session.commit()

            # Перешифрование файлов, зашифрованных старым ключом
            if current_key:
                files_to_update = File.query.filter_by(user_id=user.id, key_version=old_version).all()
                for f in files_to_update:
                    try:
                        old_private_key = serialization.load_pem_private_key(
                            current_key.private_key.encode('utf-8'),
                            password=None
                        )
                        decrypted_data = old_private_key.decrypt(
                            f.encrypted_data,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        new_public_key_obj = serialization.load_pem_public_key(new_public.encode('utf-8'))
                        new_encrypted = new_public_key_obj.encrypt(
                            decrypted_data,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        f.encrypted_data = new_encrypted
                        f.key_version = new_version
                    except Exception as e:
                        app.logger.error("Error re-encrypting file %s for user %s: %s", f.filename, user.id, e)
                db.session.commit()
        app.logger.info("Key rotation complete.")

def schedule_key_rotation(app, interval_seconds=86400):
    """Запуск ротации ключей периодически в фоновом потоке."""
    def run():
        while True:
            time.sleep(interval_seconds)
            app.logger.info("Starting scheduled key rotation...")
            rotate_keys(app)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()

if __name__ == '__main__':
    app = create_app()
    schedule_key_rotation(app)  # Запуск фоновой ротации ключей
    # Запуск приложения с SSL (HTTPS)
    app.run(ssl_context=('cert.pem', 'key.pem'))
