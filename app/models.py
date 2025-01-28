from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from . import db

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связь с зашифрованными данными
    encrypted_data = db.relationship('EncryptedData', backref='user', lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # ID записи
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Внешний ключ для связи с пользователем
    public_key = db.Column(db.String(1024), nullable=False)  # Публичный ключ
    private_key = db.Column(db.String(1024), nullable=False)  # Приватный ключ
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Время создания ключей

    user = db.relationship('User', backref=db.backref('keys', lazy=True))

    def __repr__(self):
        return f"Key('{self.user_id}', '{self.timestamp}')"
    
def save_keys_to_db(user_id, private_key, public_key):
    new_key = Key(user_id=user_id, private_key=private_key.decode('utf-8'), public_key=public_key.decode('utf-8'))
    db.session.add(new_key)
    db.session.commit()
    
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # ID файла
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Внешний ключ для связи с пользователем
    file_name = db.Column(db.String(100), nullable=False)  # Имя файла
    encrypted_content = db.Column(db.LargeBinary, nullable=False)  # Зашифрованное содержимое файла

    user = db.relationship('User', backref=db.backref('files', lazy=True))

    def __repr__(self):
        return f"File('{self.file_name}', '{self.user_id}')"

class EncryptedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"EncryptedData('{self.id}', '{self.data[:30]}...')"