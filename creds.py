from pathlib import Path
from cryptography.fernet import Fernet
import os

KEY_FILE = Path.home() / '.vulnez_key'

def generate_key(path:Path=KEY_FILE):
    key = Fernet.generate_key()
    path.write_bytes(key); os.chmod(path, 0o600); return key

def load_key(path:Path=KEY_FILE):
    if not path.exists(): raise FileNotFoundError(path)
    return path.read_bytes()

def encrypt_credentials(plaintext: bytes, key: bytes):
    f = Fernet(key); return f.encrypt(plaintext)

def decrypt_credentials(token: bytes, key: bytes):
    f = Fernet(key); return f.decrypt(token)
