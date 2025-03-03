import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import pyotp

def generate_password(length=16, symbols=True):
    chars = string.ascii_letters + string.digits
    if symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(secrets.choice(chars) for _ in range(length))

class CryptoUtils:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
        ciphertext = encryptor.update(padded_data.encode()) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, data):
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = plaintext[-1]
        return plaintext[:-padding_length].decode()

def generate_2fa_secret():
    return pyotp.random_base32()

def get_2fa_uri(username, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Secure Password Manager")