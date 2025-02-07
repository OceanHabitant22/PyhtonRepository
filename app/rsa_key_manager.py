from crypto import generate_rsa_keys
from models import RSAKey
from extensions import db

def generate_and_store_rsa_keys(user_id):
    """
    Generate RSA keys for the given user and store them in the database.
    """
    current_key = RSAKey.query.filter_by(user_id=user_id).order_by(RSAKey.created_at.desc()).first()
    new_version = (current_key.key_version + 1) if current_key else 1

    public_key, private_key = generate_rsa_keys()
    new_key = RSAKey(
        user_id=user_id,
        public_key=public_key,
        private_key=private_key,
        key_version=new_version
    )
    db.session.add(new_key)
    db.session.commit()
    return new_key
