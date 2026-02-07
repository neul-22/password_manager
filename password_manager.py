import json
from typing import List, Dict
from crypto_module import CryptoManager

class PasswordManager:
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.crypto_manager = CryptoManager(master_password)
        self.credentials: List[Dict[str, str]] = []

    def add_credential(self, service: str, username: str, password: str)-> bool:
        try:
            encrypted_pasword = self.crypto_manager.encrypto(password)

            credential = {
                'service': service,
                'username': username,
                'password': encrypted_pasword,
            }

            self.credential.append(credential)
            return True
        except Exception as e:
            print(f"Error adding credential: {e}")
            return False