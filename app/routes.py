import os
from flask import (Blueprint, request, render_template, redirect, url_for, flash, abort, current_app, send_from_directory)
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization

from .myextensions import db
from .models import User, RSAKey, File
from .crypto import generate_rsa_keys, hybrid_encrypt_file_data, hybrid_decrypt_file_data
from .forms import RegistrationForm, LoginForm, UploadForm
import re

def validate_username(username: str) -> bool:
    pattern = r'^[A-Za-z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

main = Blueprint('main', __name__)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/')
@login_required
def index():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', files=user_files)

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        if not validate_username(username):
            flash("Неверный формат имени пользователя", "danger")
            return redirect(url_for('main.register'))
        password = form.password.data.strip()
        # Проверка, существует ли уже пользователь
        if User.query.filter_by(username=username).first():
            flash('User already exists. Please log in.', 'danger')
            return redirect(url_for('main.login'))
        # Создание и сохранение нового пользователя
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Генерация RSA ключей для нового пользователя
        public_key, private_key = generate_rsa_keys()
        key_record = RSAKey(
            user_id=new_user.id,
            public_key=public_key,
            private_key=private_key,
            key_version=1
        )
        db.session.add(key_record)
        db.session.commit()

        # Автоматический вход нового пользователя и перенаправление на главную страницу
        login_user(new_user)
        print("DEBUG: User logged in:", current_user.is_authenticated)
        flash('Registration successful! You are now logged in.', 'success')
        return redirect(url_for('main.index'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('main.index'))
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('User not found. Please register first.', 'danger')
            return redirect(url_for('main.register'))
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    print("DEBUG: logout route accessed")
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('main.login'))

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    print("DEBUG: current_user.is_authenticated =", current_user.is_authenticated)
    form = UploadForm()
    if request.method == 'POST':
        file = request.files.get('file')
        if not (file and allowed_file(file.filename)):
            flash("Invalid file type.", "danger")
            return redirect(url_for('main.upload_file'))
        filename = secure_filename(file.filename)
        file_data = file.read()
        
        # Получение актуальной записи RSA ключа для пользователя
        current_key_record = RSAKey.query.filter_by(user_id=current_user.id)\
                                         .order_by(RSAKey.created_at.desc()).first()
        if not current_key_record:
            flash("No encryption key found for your account.", "danger")
            return redirect(url_for('main.upload_file'))
        
        # Загрузка публичного ключа
        public_key = serialization.load_pem_public_key(
            current_key_record.public_key.encode('utf-8')
        )
        
        # Шифрование данных с использованием гибридного алгоритма
        try:
            encrypted_symmetric_key, encrypted_data = hybrid_encrypt_file_data(public_key, file_data)
        except Exception as e:
            flash("Encryption failed: " + str(e), "danger")
            return redirect(url_for('main.upload_file'))
        
        # Создание записи файла с зашифрованными данными и ключом
        new_file = File(
            filename=filename,
            encrypted_data=encrypted_data,
            encrypted_key=encrypted_symmetric_key,  # Убедитесь, что в модели File есть этот столбец!
            user_id=current_user.id,
            key_version=current_key_record.key_version
        )
        db.session.add(new_file)
        db.session.commit()
        
        flash(f'File "{filename}" successfully uploaded and encrypted!', "success")
        return redirect(url_for('main.index'))
    return render_template('upload.html', form=form)

@main.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get(file_id)
    if not file_record:
        abort(404)
    if file_record.user_id != current_user.id:
        abort(403)
    
    # Получение записи RSA ключа по версии
    key_record = RSAKey.query.filter_by(user_id=current_user.id, key_version=file_record.key_version).first()
    if not key_record:
        flash("Encryption key not found for this file.", "danger")
        return redirect(url_for('main.index'))
    
    try:
        # Загрузка приватного ключа
        private_key = serialization.load_pem_private_key(
            key_record.private_key.encode('utf-8'), 
            password=None
        )
        # Гибридное дешифрование
        decrypted_data = hybrid_decrypt_file_data(
            private_key, 
            file_record.encrypted_key, 
            file_record.encrypted_data
        )
    except Exception as e:
        flash(f"Error decrypting file: {e}", "danger")
        return redirect(url_for('main.index'))
    
    # Сохранение временного файла для скачивания
    temp_filename = f"decrypted_{file_record.filename}"
    temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], temp_filename)
    with open(temp_path, 'wb') as temp_file:
        temp_file.write(decrypted_data)
    
    return send_from_directory(
        current_app.config['UPLOAD_FOLDER'],
        temp_filename,
        as_attachment=True,
        download_name=file_record.filename
    )
