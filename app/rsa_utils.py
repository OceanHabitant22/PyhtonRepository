from cryptography.hazmat.primitives import serialization

def load_public_key(pem_str):
    """
    Load a PEM-formatted public key string.
    """
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))

def load_private_key(pem_str, password=None):
    """
    Load a PEM-formatted private key string.
    """
    return serialization.load_pem_private_key(pem_str.encode('utf-8'), password=password)
