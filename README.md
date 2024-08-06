-------------------------------------------------------------------------------------------------------------------------------------------

# EncryptoPI - by TheJuicePapi

-------------------------------------------------------------------------------------------------------------------------------------------

![Screenshot_2024-08-06_16-52-57-5](https://github.com/user-attachments/assets/c94d10f8-e364-4397-8b2e-c09281a3f702)
![Screenshot_2024-08-06_16-54-49](https://github.com/user-attachments/assets/201c7106-4413-4030-b3cf-e1dc8156065a)





---------------------

![Screenshot_2024-08-06_16-54-12-1](https://github.com/user-attachments/assets/d0a77ec3-1641-44eb-bc62-7f90c6be8aa3)
![Screenshot_2024-08-06_16-54-32](https://github.com/user-attachments/assets/974c10aa-ebda-4370-8332-5f2f91cc5ce7)






Overview

Encryptopi is an advanced Python script for encrypting and decrypting files and folders using both Fernet and AES encryption algorithms. It is designed to provide secure file handling with features such as key management, metadata handling, and file integrity checking. 

-------------------------------
KEY FEATURES

* Use either Fernet or AES for encryption/decryption
* Generate Fernet and AES encryption keys
* Encrypt and decrypt all files in a specified directory
* Backup and restore encryption keys
* Attach and view metadata for encryption keys
* Verify file integrity with hashes
* Manage multiple encryption keys
* View existing encryption keys
* Delete existing encryption keys
* Move files and folders between designated directories for operations
* Compress files (optional)
* Provide help and usage instructions

--------------------------------
 
INSTALLATION & USAGE

Git clone installation:

1. 'git clone https://github.com/TheJuicePapi/encryptopi.git'
2. 'cd encryptopi'
3. 'sudo chmod +x install.sh encryptopi.py'
4. 'sudo ./install.sh'
5. Exit and open a new terminal to use 'encryptopi' shortcut 

-------------------------------

DEPENDANCIES

(The install.sh script should auto isntall these dependancies for you)

    cryptography: For Fernet and AES encryption/decryption.
    colorama: For colored terminal output.
    tqdm: For progress bars.
    json, os, sys, base64, hashlib, getpass, zipfile: Standard Python libraries.

-------------------------------

This scipt has been tested on my RPI 4b running a kali linux arm.
Enjoy and use responsibly
