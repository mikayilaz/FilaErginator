import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
from pystyle import Colors, Colorate, Center, Write

SALT_SIZE = 16
KEY_SIZE = 32  # Для AES-256
ITERATIONS = 100_000
BLOCK_SIZE = 16


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path: str, password: str):
    salt = os.urandom(SALT_SIZE)
    key = generate_key(password, salt)

    iv = os.urandom(BLOCK_SIZE)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(ciphertext)
    hmac_digest = hmac.finalize()

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + iv + hmac_digest + ciphertext)

    print(f"✅ Файл {file_path} успешно зашифрован!")
    os.remove(file_path)


def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
    hmac_digest = data[SALT_SIZE + BLOCK_SIZE:SALT_SIZE + BLOCK_SIZE + 32]
    ciphertext = data[SALT_SIZE + BLOCK_SIZE + 32:]

    key = generate_key(password, salt)

    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(ciphertext)
    try:
        hmac.verify(hmac_digest)
    except Exception:
        print("❌ Ошибка: данные повреждены или неверный пароль.")
        return

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    output_file = file_path.replace('.enc', '')
    with open(output_file, 'wb') as file:
        file.write(plaintext)

    print(f"✅ Файл {output_file} успешно расшифрован!")
    os.remove(file_path)


def display_banner():
    banner = r"""
  ______ _ _       ______           _       _             
 |  ____(_) |     |  ____|         (_)     | |            
 | |__   _| | __ _| |__   _ __ __ _ _ _ __ | |_ ___  _ __ 
 |  __| | | |/ _` |  __| | '__/ _` | | '_ \| __/ _ \| '__|
 | |    | | | (_| | |____| | | (_| | | | | | || (_) | |   
 |_|    |_|_|\__,_|______|_|  \__, |_|_| |_|\__\___/|_|   
                                __/ |                    
                               |___/                     
  Создано: wndkx и mikayilaz
    """
    print(Colorate.Horizontal(Colors.blue_to_cyan, banner))


def main():
    display_banner()
    print("1. Зашифровать файл")
    print("2. Расшифровать файл")
    choice = input("Выберите действие (1/2): ").strip()

    if choice not in ['1', '2']:
        print("❌ Некорректный выбор.")
        return

    file_path = input("Введите путь к файлу: ").strip()
    if not os.path.isfile(file_path):
        print("❌ Файл не найден. Проверьте путь.")
        return

    password = input("Введите пароль: ").strip()
    if len(password) < 8:
        print("❌ Пароль должен содержать не менее 8 символов.")
        return

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)


if __name__ == "__main__":
    main()
