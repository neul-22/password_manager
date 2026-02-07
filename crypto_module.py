from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


class CryptoManager:
    def __init__(self, master_pasword: str, salt: bytes = None):
        self.salt = salt if salt else os.urandom(16)
        self.key = self._derive_key(master_pasword)
        self.cipher = Fernet(self.key)

    def _derive_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = self.salt,
            iterations = 100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt (self, plaintext: str)-> str:
        encrypted_bytes = self.cipher.decrypt(plaintext.encode())
        return encrypted_bytes.decode()

    def decrypt(self, ciphertext: str)-> str:
        decrypted_bytes = self.cipher.decrypt(ciphertext.encode())
        return decrypted_bytes.decode()
    
    def get_salt(self)-> str:
        return base64.b64encode(self.salt).decode()
    
    @staticmethod
    def salt_from_string(salt_str: str) -> bytes:
        return base64.b64decode(salt_str.encode())
