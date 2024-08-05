from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from colorama import Fore, Style, init
from tqdm import tqdm
import os
import sys
import base64
import hashlib
import getpass
import zipfile

# Initialize colorama
init(autoreset=True)

# Paths
KEYS_DIR = Path("keys")
INPUT_DIR = Path("input")
OUTPUT_DIR = Path("output")
DECRYPT_OUTPUT_DIR = Path("decrypted_output")

# Ensure directories exist
for directory in [KEYS_DIR, INPUT_DIR, OUTPUT_DIR, DECRYPT_OUTPUT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Function to clear terminal
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to generate a new encryption key
def generate_key():
    try:
        use_password = input(Fore.CYAN + "Do you want to protect the key with a password? (y/n): ").lower() == 'y'
        password = None
        if use_password:
            password = getpass.getpass(Fore.CYAN + "Enter a password (or leave blank to skip): ").encode()
            if not password:
                password = None
        key = Fernet.generate_key()
        if password:
            # Use password to encrypt the key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            derived_key = base64.urlsafe_b64encode(kdf.derive(password))
            key_filename = KEYS_DIR / (f"key_{base64.urlsafe_b64encode(salt).decode('utf-8')[:10]}.key")
            with open(key_filename, "wb") as key_file:
                key_file.write(salt + derived_key)  # Store salt with key
        else:
            key_filename = KEYS_DIR / (f"key_{base64.urlsafe_b64encode(key).decode('utf-8')[:10]}.key")
            with open(key_filename, "wb") as key_file:
                key_file.write(key)
        print(Fore.GREEN + f"Key generated and saved as {key_filename}")
    except Exception as e:
        print(Fore.RED + f"Error generating key: {e}")

# Function to show available keys
def show_keys():
    try:
        print(Fore.CYAN + "Available keys:")
        for key_file in KEYS_DIR.iterdir():
            if key_file.suffix == ".key":
                print(f" - {key_file.name}")
    except Exception as e:
        print(Fore.RED + f"Error showing keys: {e}")

# Function to load a key
def load_key(key_filename):
    try:
        key_path = KEYS_DIR / key_filename
        if not key_path.is_file():
            print(Fore.RED + "Invalid key file")
            return None
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
        if len(key_data) > 32:  # Assume password-protected if longer than 32 bytes
            salt, encrypted_key = key_data[:16], key_data[16:]
            password = getpass.getpass(Fore.CYAN + "Enter the password for the key: ").encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return base64.urlsafe_b64encode(kdf.derive(password))
        return key_data
    except Exception as e:
        print(Fore.RED + f"Error loading key: {e}")
        return None

# Function to calculate file hash for integrity check
def calculate_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception as e:
        print(Fore.RED + f"Error calculating hash for {file_path}: {e}")
        return None

# Function to encrypt a file using Fernet
def encrypt_file_fernet(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        encrypted_file_path = OUTPUT_DIR / (file_path.name + ".enc")
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        print(Fore.GREEN + f"Encrypted {file_path.name} to {encrypted_file_path.name}")
    except Exception as e:
        print(Fore.RED + f"Error encrypting file {file_path}: {e}")

# Function to decrypt a file using Fernet
def decrypt_file_fernet(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        decrypted_file_path = DECRYPT_OUTPUT_DIR / file_path.name.replace(".enc", "")
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        print(Fore.GREEN + f"Decrypted {file_path.name} to {DECRYPT_OUTPUT_DIR}")
    except Exception as e:
        print(Fore.RED + f"Error decrypting file {file_path}: {e}")

# Function to handle encryption of multiple or all files
def encrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to use (from above): ")
        key = load_key(key_filename)
        if key is None:
            return
        
        files_to_encrypt = list(INPUT_DIR.rglob('*'))  # Use rglob for subdirectory traversal
        print(Fore.YELLOW + "Encrypting files...")
        for file_path in tqdm(files_to_encrypt, desc="Encrypting", unit="file"):
            if file_path.is_file():
                original_hash = calculate_hash(file_path)
                encrypt_file_fernet(file_path, key)
                encrypted_file_path = OUTPUT_DIR / (file_path.name + ".enc")
                decrypt_file_fernet(encrypted_file_path, key)  # Decrypt to verify integrity
                decrypted_file_path = DECRYPT_OUTPUT_DIR / file_path.name
                decrypted_hash = calculate_hash(decrypted_file_path)
                if original_hash != decrypted_hash:
                    print(Fore.RED + f"Integrity check failed for {file_path.name}")
                os.remove(decrypted_file_path)  # Remove decrypted file after integrity check
    except Exception as e:
        print(Fore.RED + f"Error encrypting files: {e}")

# Function to handle decryption of multiple or all files
def decrypt_files():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to use (from above): ")
        key = load_key(key_filename)
        if key is None:
            return
        encrypted_files = list(OUTPUT_DIR.rglob('*.enc'))
        print(Fore.YELLOW + "Decrypting files...")
        for file_path in tqdm(encrypted_files, desc="Decrypting", unit="file"):
            if file_path.is_file():
                decrypt_file_fernet(file_path, key)
    except Exception as e:
        print(Fore.RED + f"Error decrypting files: {e}")

# Function to check file integrity
def check_file_integrity():
    try:
        print(Fore.CYAN + "Checking file integrity...")
        files_to_check = list(OUTPUT_DIR.rglob('*.enc')) + list(DECRYPT_OUTPUT_DIR.rglob('*'))
        for file_path in tqdm(files_to_check, desc="Checking", unit="file"):
            if file_path.is_file():
                hash_value = calculate_hash(file_path)
                if hash_value:
                    print(Fore.GREEN + f"Integrity of {file_path.name} is intact.")
                else:
                    print(Fore.RED + f"Failed to calculate hash for {file_path.name}.")
    except Exception as e:
        print(Fore.RED + f"Error checking file integrity: {e}")

# Function to compress files
def compress_files():
    try:
        print(Fore.CYAN + "Compressing files...")
        zip_file_path = OUTPUT_DIR / "files.zip"  # Save ZIP file to OUTPUT_DIR
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in INPUT_DIR.rglob('*'):  # Use rglob to include all files in subdirectories
                if file.is_file():
                    zipf.write(file, file.relative_to(INPUT_DIR))
        print(Fore.GREEN + f"Files compressed to {zip_file_path}")
    except Exception as e:
        print(Fore.RED + f"Error compressing files: {e}")

# Function to add metadata to a key file
def add_key_metadata():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to add metadata to (from above): ")
        key_file_path = KEYS_DIR / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        metadata = input(Fore.CYAN + "Enter metadata to add: ")
        with open(key_file_path, "a") as key_file:
            key_file.write(f"\nMetadata: {metadata}")
        print(Fore.GREEN + f"Metadata added to {key_filename}")
    except Exception as e:
        print(Fore.RED + f"Error adding metadata to key: {e}")

# Function to view metadata of a key file
def view_key_metadata():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to view metadata of (from above): ")
        key_file_path = KEYS_DIR / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        with open(key_file_path, "r") as key_file:
            contents = key_file.read()
        print(Fore.CYAN + f"Contents of {key_filename}:\n{contents}")
    except Exception as e:
        print(Fore.RED + f"Error viewing metadata of key: {e}")

# Function to delete a key
def delete_key():
    try:
        show_keys()
        key_filename = input(Fore.CYAN + "Enter the key filename to delete (from above): ")
        key_file_path = KEYS_DIR / key_filename
        if not key_file_path.is_file():
            print(Fore.RED + "Invalid key file")
            return
        os.remove(key_file_path)
        print(Fore.GREEN + f"Key {key_filename} deleted.")
    except Exception as e:
        print(Fore.RED + f"Error deleting key: {e}")

# Function to display the help section
def display_help():
    clear_terminal()
    print(Fore.YELLOW + """
    ***************************************
    *        Encryption/Decryption Help   *
    ***************************************
    """)
    print(Fore.CYAN + """
    1. Generate New Key: Creates a new encryption key, with an option to protect it with a password.
    2. Show Available Keys: Lists all encryption keys currently saved.
    3. Encrypt Files: Encrypts files from the 'input' directory using the selected key.
    4. Decrypt Files: Decrypts files from the 'output' directory using the selected key.
    5. Check File Integrity: Checks the integrity of encrypted and decrypted files.
    6. Compress Files: Compresses files from the 'input' directory into a ZIP file.
    7. Add Key Metadata: Adds metadata to an encryption key file.
    8. View Key Metadata: Views metadata from an encryption key file.
    9. Delete Key: Deletes an encryption key file.
    0. Exit: Exits the program.
    """)
    input(Fore.CYAN + "Press Enter to return to the main menu...")

# Function to display the menu
def display_menu():
    clear_terminal()
    print(Fore.YELLOW + """

   ╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭╮╱╱╱╭━━━┳━━╮
   ┃╭━━╯╱╱╱╱╱╱╱╱╱╱╱╱╱╭╯╰╮╱╱┃╭━╮┣┫┣╯
   ┃╰━━┳━╮╭━━┳━┳╮╱╭┳━┻╮╭╋━━┫╰━╯┃┃┃
   ┃╭━━┫╭╮┫╭━┫╭┫┃╱┃┃╭╮┃┃┃╭╮┃╭━━╯┃┃
   ┃╰━━┫┃┃┃╰━┫┃┃╰━╯┃╰╯┃╰┫╰╯┃┃╱╱╭┫┣╮
   ╰━━━┻╯╰┻━━┻╯╰━╮╭┫╭━┻━┻━━┻╯╱╱╰━━╯
   ╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃┃┃
   ╱╱╱╱╱╱╱╱╱╱╱╱╰━━╯╰╯
    """)
    print(" EncryptoPI Encryptor - TheJuicePapi ")
    print(Fore.CYAN + """
       1. Generate New Key
       2. Show Available Keys
       3. Encrypt Files
       4. Decrypt Files
       5. Check File Integrity
       6. Compress Files
       7. Add Key Metadata
       8. View Key Metadata
       9. Delete Key
       0. Exit
       h. Help
    """)

# Main menu loop
def main_menu():
    while True:
        display_menu()
        choice = input(Fore.CYAN + " Enter your choice: ")
        if choice == '1':
            generate_key()
        elif choice == '2':
            show_keys()
        elif choice == '3':
            encrypt_files()
        elif choice == '4':
            decrypt_files()
        elif choice == '5':
            check_file_integrity()
        elif choice == '6':
            compress_files()
        elif choice == '7':
            add_key_metadata()
        elif choice == '8':
            view_key_metadata()
        elif choice == '9':
            delete_key()
        elif choice == '0':
            print(Fore.GREEN + "Exiting...")
            break
        elif choice == 'h':
            display_help()
        else:
            print(Fore.RED + "Invalid choice. Please try again.")
        input(Fore.CYAN + "Press Enter to return to the main menu...")

if __name__ == "__main__":
    main_menu()
