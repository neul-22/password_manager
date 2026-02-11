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
    def get_credentials(self)-> List[Dict[str, str]]:
        decrypted_credentials = []
        for cred in self.credentials:
            try:
                decrypted_cre = {
                    'service': cred['service'],
                    'username': cred['username'],
                    'password': self.crypto_manager.decrypt(cred['password'])
                }
                decrypted_credentials.append(decrypted_cre)
            except Exception as e:
                print(f"Error decrypting credential: {e}")

        return decrypted_credentials
    
    def save_to_file(self, filename: str = 'passwords.json')-> bool:
        try:
            data = {
                'salt': self.crypto_manager.get_salt(),
                'credentials': self.credentials
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent = 2)

            return True
        except Exception as e:
            print(f"Error saving to file: {e}")
            return False
    def load_from_file(self, filename: str = 'password.json')-> bool:
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

                salt = CryptoManager.salt_from_string(data['salt'])
                self.crypto_manager = CryptoManager(self.master_password, salt)
                self.credentials = data['credentials']
                return True
        except FileNotFoundError:
            print(f"file {filename} not found")
            return False
        except Exception as e:
            print(f"Error loading from file: {e}")
            return False
    
    def clear_credentials(self):
        self.credentials = []
