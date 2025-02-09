import os
from typing import Tuple
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

logger = logging.getLogger(__name__)

def generate_rsa_keys() -> Tuple[str, str]:
    """
    Generates a new RSA key pair and returns the keys in PEM format as strings.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return public_pem, private_pem

def encrypt_file_data(public_key, data: bytes) -> bytes:
    """
    Encrypts data using the provided RSA public key with OAEP padding.
    (For small messages only.)
    """
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_file_data(private_key, encrypted_data: bytes) -> bytes:
    """
    Decrypts data using the provided RSA private key with OAEP padding.
    """
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def hybrid_encrypt_file_data(public_key, file_data: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypts file_data using a randomly generated AES key (symmetric encryption)
    and then encrypts the AES key with the provided RSA public_key.

    Returns a tuple:
        (encrypted_symmetric_key, combined_encrypted_data)
    where combined_encrypted_data = IV + AES_encrypted_file_data.
    """
    logger.info("Начало гибридного шифрования файла (размер %d байт)", len(file_data))
    
    # Generate a random 256-bit AES key
    symmetric_key = os.urandom(32)  # 32 bytes = 256 bits
    
    # Generate a random IV (AES block size is 16 bytes)
    iv = os.urandom(16)
    
    # Create an AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the file_data so its length is a multiple of 16 bytes (128 bits)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    # Encrypt the padded data with AES
    encrypted_file_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine the IV and encrypted file data (the IV is needed for decryption)
    combined_encrypted_data = iv + encrypted_file_data
    
    # Encrypt the symmetric key using the RSA public key with OAEP padding
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logger.info("Гибридное шифрование завершено")
    return encrypted_symmetric_key, combined_encrypted_data

def hybrid_decrypt_file_data(private_key, encrypted_symmetric_key: bytes, combined_encrypted_data: bytes) -> bytes:
    """
    Decrypts the symmetric key using RSA, then decrypts the file data using AES.

    Expects:
      - encrypted_symmetric_key: RSA-encrypted AES key.
      - combined_encrypted_data: IV concatenated with the AES-encrypted file data.

    Returns the original plaintext file data.
    """
    # Decrypt the AES key using the RSA private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # The first 16 bytes of combined_encrypted_data are the IV
    iv = combined_encrypted_data[:16]
    encrypted_file_data = combined_encrypted_data[16:]
    
    # Create an AES cipher with the decrypted key and IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt the data and then remove padding
    padded_plaintext = decryptor.update(encrypted_file_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext
