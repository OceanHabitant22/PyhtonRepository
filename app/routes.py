import os
from flask import (Blueprint, request, render_template, redirect, url_for, flash, abort, current_app, send_from_directory)
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization

from .myextensions import db
from .models import User, RSAKey, File
from .crypto import generate_rsa_keys, encrypt_file_data, decrypt_file_data
from .forms import RegistrationForm, LoginForm, UploadForm

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
        username = form.username.data
        password = form.password.data
        if User.query.filter_by(username=username).first():
            flash('User already exists!', 'danger')
            return redirect(url_for('main.register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Generate RSA keys for the new user
        public_key, private_key = generate_rsa_keys()
        key_record = RSAKey(
            user_id=new_user.id,
            public_key=public_key,
            private_key=private_key,
            key_version=1
        )
        db.session.add(key_record)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('main.login'))

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_data = file.read()

            # Get the latest RSA key for the user
            current_key_record = RSAKey.query.filter_by(user_id=current_user.id).order_by(RSAKey.created_at.desc()).first()
            if not current_key_record:
                flash("No encryption key found for your account.", "danger")
                return redirect(url_for('main.upload_file'))

            public_key = serialization.load_pem_public_key(current_key_record.public_key.encode('utf-8'))
            encrypted_data = encrypt_file_data(public_key, file_data)
            new_file = File(
                filename=filename,
                encrypted_data=encrypted_data,
                user_id=current_user.id,
                key_version=current_key_record.key_version
            )
            db.session.add(new_file)
            db.session.commit()

            flash(f'File "{filename}" successfully uploaded and encrypted!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash("Invalid file type.", "danger")
            return redirect(url_for('main.upload_file'))
    return render_template('upload.html', form=form)

@main.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get(file_id)
    if not file_record:
        abort(404)
    if file_record.user_id != current_user.id:
        abort(403)

    # Get the correct RSA key record based on the file's key_version
    key_record = RSAKey.query.filter_by(user_id=current_user.id, key_version=file_record.key_version).first()
    if not key_record:
        flash("Encryption key not found for this file.", "danger")
        return redirect(url_for('main.index'))

    try:
        private_key = serialization.load_pem_private_key(key_record.private_key.encode('utf-8'), password=None)
        decrypted_data = decrypt_file_data(private_key, file_record.encrypted_data)
    except Exception as e:
        flash(f"Error decrypting file: {e}", "danger")
        return redirect(url_for('main.index'))

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
