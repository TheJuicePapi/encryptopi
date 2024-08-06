#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Install needed python3,python3-pip, cryptography, colorama, tqdm
echo "Installing python3,cryptography, colorama, tqdm..."
sudo apt-get update
sudo apt-get install -y python3 python3-pip

pip3 install cryptography colorama tqdm

# Create symbolic link for encryptopi
ln -s "$(pwd)/encryptopi.py" /usr/local/bin/encryptopi

clear

echo "Installation complete and shortcut created! Launch a new terminal and you'll be able to run 'encryptopi' from any directory."
