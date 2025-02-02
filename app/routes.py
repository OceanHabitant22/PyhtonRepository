from flask import Blueprint, request, send_file, render_template, jsonify, flash, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db  # Updated import
from .forms import RegistrationForm
from .models import User, Key
from .rsa_key_manager import generate_rsa_keys
from .encryption import encrypt_data, decrypt_data
from cryptography.hazmat.primitives import serialization
from werkzeug.utils import secure_filename
from .forms import UploadForm
from app.rsa_utils import load_public_key
from flask_login import current_user  # if using Flask-Login
from flask import Flask, render_template, request, redirect, url_for, flash, current_app
import os

# Create Blueprint
main = Blueprint('main', __name__)

UPLOAD_FOLDER = 'uploads'  # Upload folder path
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)
# Configuring upload folder (relative path)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')  # Assuming the 'uploads' folder is in the same directory as the app
# SECRET_KEY: It is used for session management and cryptographic operations (for cookies, flash messages, etc.).
app.secret_key = os.urandom(24)  # Secure random key for cryptographic purposes.

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    form = UploadForm(request.form)
    
    # If the user is logged in, prefill the user_id field
    if current_user.is_authenticated:
        form.user_id.data = current_user.id

    if form.validate_on_submit():
        file = form.file.data
        user_id = form.user_id.data
        
        # Check if user_id is provided (should be pre-filled if user is logged in)
        if not user_id:
            flash('User ID is required!', 'error')
            return redirect(url_for('upload_file'))

        # Load public key for the user
        user_key = load_public_key(user_id)
        if not user_key:
            flash('Public key for this user not found!', 'error')
            return redirect(url_for('upload_file'))

        # Validate file selection
        if not file or file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('Invalid file type', 'error')
            return redirect(request.url)

        # Save the file securely
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(file_path)
        except Exception as e:
            flash(f'Error saving file: {str(e)}', 'error')
            return redirect(request.url)

        # Read and encrypt the file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = f.read()
            
            encrypted_data = encrypt_data(user_key, data)
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            
            flash(f'File "{filename}" successfully uploaded and encrypted!', 'success')
        except Exception as e:
            flash(f'Error encrypting file: {str(e)}', 'error')
            return redirect(request.url)
        
        # Redirect to the main page (or file list page) so the file list is updated
        return redirect(url_for('main.index'))

    # On GET or validation error, show the upload form (which may display validation errors)
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
        # Get data from form
        username = form.username.data
        password = form.password.data

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'danger')
            return redirect(url_for('main.register'))

        # Create user
        hashed_password = generate_password_hash(password)
        private_key, public_key = generate_rsa_keys()

        new_user = User(
            username=username,
            password_hash=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()

        # Save keys
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

# Check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/', methods=['GET', 'POST'])
def index():
    form = UploadForm(request.form)
    files = os.listdir(current_app.config['UPLOAD_FOLDER'])
    file = None

    if request.method == 'POST' and form.validate():
        user_id = form.user_id.data
        uploaded_file = request.files.get('file')
        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(save_path)
            flash(f'Файл "{filename}" успешно загружен пользователем ID {user_id}!')
            file = filename
            return redirect(url_for('main.index'))
        else:
            flash('Недопустимый формат файла. Пожалуйста, загрузите допустимый файл.')
    
    return render_template('index.html', form=form, file=file, files=files)

@main.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404
