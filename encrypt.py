from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import os
import random
import string

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

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

def encrypt_data(key, data):
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def save_encrypted_data(username, password, encryption_password, site):
    salt = os.urandom(16)
    key = derive_key(encryption_password, salt)
    encrypted_username = encrypt_data(key, username)
    encrypted_password = encrypt_data(key, password)
    
    # Create a filename based on the username and site
    filename = f"{site.replace('.', '_')}.salt"
    
    with open(filename, 'wb') as file:
        file.write(salt + b':' + encrypted_username + b':' + encrypted_password + b'\n')

def decrypt_data(encryption_password, data):
    salt, encrypted_username, encrypted_password = data.strip().split(b':')
    key = derive_key(encryption_password, salt)
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
    print("Password Generator, Saver, and Encrypter")

    username = input("Enter the username: ")
    site = input("Enter the site: ")
    password_length = int(input("Enter the desired password length (default is 12): ") or 12)

    password = generate_password(password_length)
    print(f'Generated Password: {password}')

    save_option = input("Do you want to save this password? (yes/no): ").lower()

    if save_option == 'yes':
        encryption_password = input("Enter the encryption password: ")
        save_encrypted_data(username, password, encryption_password.encode(), site)
        print("Username and password encrypted and saved successfully.")
    else:
        print("Username and password not saved.")

if __name__ == "__main__":
    main()

os.system("sleep 5")
os.system("clear")