from flask import Blueprint, request, send_file, render_template, jsonify, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .forms import RegistrationForm
from .models import User, Key, File
from .rsa_key_manager import generate_rsa_keys
from .encryption import encrypt_data, decrypt_data
from cryptography.hazmat.primitives import serialization
import os

# Создаем объект Blueprint
main = Blueprint('main', __name__)

# Путь для загрузки файлов
UPLOAD_FOLDER = "uploads/"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@main.route('/upload', methods=['GET'])
def upload_form():
    return render_template('upload.html')

@main.route('/')
def main_index():
    files = os.listdir(UPLOAD_FOLDER)
    files = [f for f in files if not f.endswith('.enc')]  # Только оригинальные файлы
    return render_template('index.html', files=files)


@main.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        user_id = request.form.get('user_id')  # Передайте идентификатор пользователя
        user_key = Key.query.filter_by(user_id=user_id).first()

        if not user_key:
            return "Ключи для пользователя не найдены!", 400

        public_key_pem = serialization.load_pem_public_key(user_key.public_key.encode('utf-8'))

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        with open(file_path, 'r', encoding='utf-8') as f:
            data = f.read()

        encrypted_data = encrypt_data(public_key_pem, data)

        with open(file_path + ".enc", 'wb') as f:
            f.write(encrypted_data)

        return "Файл успешно загружен и зашифрован!"
    return "Ошибка при загрузке файла."

@main.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    user_id = request.args.get('user_id')
    user_key = Key.query.filter_by(user_id=user_id).first()

    if not user_key:
        return "Ключи для пользователя не найдены!", 400

    private_key_pem = serialization.load_pem_private_key(
        user_key.private_key.encode('utf-8'),
        password=None,
    )

    encrypted_file_path = os.path.join(UPLOAD_FOLDER, filename + ".enc")
    if os.path.exists(encrypted_file_path):
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_data(private_key_pem, encrypted_data)

        decrypted_file_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(decrypted_file_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)

        return send_file(decrypted_file_path, as_attachment=True)
    return "Файл не найден."


@main.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Проверяем, существует ли пользователь
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'User already exists'}), 400

        # Генерация и хэширование пароля
        hashed_password = generate_password_hash(password)
        private_key, public_key = generate_rsa_keys()

        # Сохранение в БД
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        new_key = Key(user_id=new_user.id, private_key=private_key, public_key=public_key)
        db.session.add(new_key)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    return render_template('register.html')
@main.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)
    files = [f for f in files if not f.endswith('.enc')]  # Только оригинальные файлы
    return render_template('index.html', files=files)

