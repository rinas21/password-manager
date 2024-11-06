# Password Manager with Encryption

This is a simple Python-based password manager that allows you to securely store and retrieve your passwords. The passwords are encrypted using the `cryptography` library and can only be accessed with a master password.

## Features

- Add a new password entry with email, username, password, and URL.
- View your stored passwords securely by decrypting them using your master password.
- Uses `Fernet` symmetric encryption to ensure data security.
  
## Requirements

- Python 3.x
- cryptography library

You can install the required dependencies by running:
```bash
pip install cryptography

