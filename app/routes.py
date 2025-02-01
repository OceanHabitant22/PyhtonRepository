from flask import Blueprint, request, send_file, render_template, jsonify, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db  # Updated import
from .forms import RegistrationForm
from .models import User, Key
from .rsa_key_manager import generate_rsa_keys
from .encryption import encrypt_data, decrypt_data
from cryptography.hazmat.primitives import serialization
from .forms import RegistrationForm
from werkzeug.utils import secure_filename
from app.forms import UploadForm
from .extensions import CSRFProtect
import os

# Создаем объект Blueprint
main = Blueprint('main', __name__)

UPLOAD_FOLDER = 'uploads'  # Папка для загрузки файлов
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Путь для загрузки файлов
UPLOAD_FOLDER = 'uploads'  # Папка для загрузки файлов
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    form = UploadForm()
    file = request.files.get("file")
    if form.validate_on_submit():
        file = form.file.data
        user_id = request.form.get('user_id')  # Получаем идентификатор пользователя

        # Проверка наличия ключей пользователя
        user_key = Key.query.filter_by(user_id=user_id).first()
        if not user_key:
            flash("Ключи для пользователя не найдены!", "error")
            return redirect(url_for('main.upload_file'))
        
        # Загрузка и шифрование файла
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Чтение и шифрование содержимого файла
        with open(file_path, 'r', encoding='utf-8') as f:
            data = f.read()

        public_key_pem = serialization.load_pem_public_key(user_key.public_key.encode('utf-8'))
        encrypted_data = encrypt_data(public_key_pem, data)

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)

        flash(f'Файл "{filename}" успешно загружен и зашифрован!', 'success')
        return redirect(url_for('main.upload_file'))

    return render_template('upload.html', form=form)

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


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Получаем данные ИЗ ФОРМЫ, а не из request.json
        username = form.username.data
        password = form.password.data

        # Проверка существующего пользователя
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'danger')
            return redirect(url_for('main.register'))

        # Создание пользователя
        hashed_password = generate_password_hash(password)
        private_key, public_key = generate_rsa_keys()

        new_user = User(
            username=username,
            password_hash=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()

        # Сохранение ключей
        new_key = Key(
            user_id=new_user.id,
            private_key=private_key.decode('utf-8'),
            public_key=public_key.decode('utf-8')
        )
        db.session.add(new_key)
        db.session.commit()

        flash('Регистрация успешна!', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)


# Проверка разрешённых расширений файлов
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/', methods=['GET', 'POST'])
def index():
    form = UploadForm()
    files = os.listdir(current_app.config['UPLOAD_FOLDER'])
    # Initialize file to a default value
    file = None
    if form.validate_on_submit():
        user_id = form.user_id.data
        uploaded_file = form.file.data
        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(save_path)
            flash(f'Файл "{filename}" успешно загружен пользователем ID {user_id}!')
            
            # Optionally, set file to some value if needed:
            file = filename
            return redirect(url_for('main.index'))
        else:
            flash('Недопустимый формат файла. Пожалуйста, загрузите допустимый файл.')
    
    # Use a variable name that matches what you want to pass. If you meant to pass 'files', use that.
    return render_template('index.html', form=form, file=file, files=files)


@main.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404
