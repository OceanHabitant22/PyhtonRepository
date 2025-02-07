import os
import threading
import time
from flask import Flask
from app.config import DevelopmentConfig  # config.py is inside app/ so this works if run as a package
from app.myextensions import db, login_manager
from app.routes import main as main_blueprint
from configparser import ConfigParser

def create_app(config_class=DevelopmentConfig):
    from app.myextensions import db, login_manager  # Local import to avoid circular dependency
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure the upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(main_blueprint)

    # Create database tables if they don’t exist
    with app.app_context():
        db.create_all()

    return app

# Register the user_loader on the single login_manager instance
@login_manager.user_loader
def load_user(user_id):
    from models import User  # local import to avoid circular dependencies
    return User.query.get(int(user_id))

def rotate_keys(app):
    """
    Rotate RSA keys for all users and re-encrypt their files with the new key.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from models import User, RSAKey, File
    from crypto import generate_rsa_keys

    with app.app_context():
        users = User.query.all()
        for user in users:
            current_key = RSAKey.query.filter_by(user_id=user.id).order_by(RSAKey.created_at.desc()).first()
            old_version = current_key.key_version if current_key else 0

            # Generate new RSA keys
            new_public, new_private = generate_rsa_keys()
            new_version = old_version + 1

            # Save new key record
            new_key_record = RSAKey(
                user_id=user.id,
                public_key=new_public,
                private_key=new_private,
                key_version=new_version
            )
            db.session.add(new_key_record)
            db.session.commit()

            # Re-encrypt files that were encrypted with the old key
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
                        app.logger.error(f"Error re-encrypting file {f.filename} for user {user.id}: {e}")
                db.session.commit()
        app.logger.info("Key rotation complete.")

def schedule_key_rotation(app, interval_seconds=86400):
    """Run key rotation periodically in a background thread."""
    def run():
        while True:
            time.sleep(interval_seconds)
            app.logger.info("Starting scheduled key rotation...")
            rotate_keys(app)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()

if __name__ == '__main__':
    app = create_app()
    schedule_key_rotation(app)  # Start the background key rotation thread
    app.run(debug=True)
