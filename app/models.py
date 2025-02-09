import datetime
from .myextensions import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Новое поле email
    password = db.Column(db.String(200), nullable=False)  # Хэшированный пароль

    # Relationships
    rsa_keys = db.relationship('RSAKey', backref='user', lazy=True)
    files = db.relationship('File', backref='user', lazy=True)

class RSAKey(db.Model):
    __tablename__ = 'rsakeys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    key_version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    encrypted_key = db.Column(db.LargeBinary, nullable=False)  # Хранит RSA-шифрованный AES-ключ
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key_version = db.Column(db.Integer, nullable=False)
