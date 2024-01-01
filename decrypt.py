from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def decrypt_data(encryption_password, data):
    salt, encrypted_username, encrypted_password = data.strip().split(b':')
    key = derive_key(encryption_password.encode(), salt)
    decrypted_username = decrypt_data_helper(key, encrypted_username)
    decrypted_password = decrypt_data_helper(key, encrypted_password)
    return decrypted_username, decrypted_password

def decrypt_data_helper(key, encrypted_data):
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()

def decrypt_file(encryption_password, input_file):
    with open(input_file, 'rb') as file:
        lines = file.readlines()
        for line in lines:
            decrypted_username, decrypted_password = decrypt_data(encryption_password, line)
            print(f'Decrypted Username: {decrypted_username}, Decrypted Password: {decrypted_password}')

def main():
    encryption_password = input("Enter the encryption password: ")
    site = input("Wesite name: ")
    input_file = f"{site.replace('.', '_')}.salt"
    decrypt_file(encryption_password, input_file)

if __name__ == "__main__":
    main()
