from cryptography.fernet import Fernet
import base64
import hashlib
import os

def main():
    print("Starting password manager...")  # Confirm the script is running

    while True:
        print("\n1. Add Password")
        print("2. View Password")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        print(f"Choice entered: {choice}")  # Debugging to check choice

        if choice == "1":
            add_password()
        elif choice == "2":
            view_password()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number (1, 2, or 3).")


# Generate or load a key for encryption (store it safely)
def generate_key(master_password):
    # Hash the master password and use it as the key for encryption
    hashed_password = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(hashed_password)

def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data

def add_password():
    # Input for user data
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    url = input("Enter the URL: ")
    username = input("Enter your username: ")
    master_password = input("Enter your master password: ")

    # Generate key from master password
    key = generate_key(master_password)

    # Encrypt the password and other details
    encrypted_email = encrypt_data(email, key)
    encrypted_password = encrypt_data(password, key)
    encrypted_url = encrypt_data(url, key)
    encrypted_username = encrypt_data(username, key)

    # Save encrypted details to a text file
    with open("passwords.txt", "a") as file:
        file.write(f"{encrypted_email.decode()}|{encrypted_password.decode()}|{encrypted_url.decode()}|{encrypted_username.decode()}\n")
    
    print("Password details saved successfully!")
    # Debugging: print encrypted data to verify it's being saved
    print(f"Encrypted data: {encrypted_email.decode()}|{encrypted_password.decode()}|{encrypted_url.decode()}|{encrypted_username.decode()}")

def view_password():
    master_password = input("Enter your master password: ")
    key = generate_key(master_password)

    # Ensure the passwords.txt file exists
    if not os.path.exists("passwords.txt"):
        print("No password records found.")
        return

    # Read encrypted data from file
    with open("passwords.txt", "r") as file:
        for line in file:
            # Skip empty lines
            if not line.strip():
                continue

            try:
                # Split the line into the expected number of values (4)
                encrypted_email, encrypted_password, encrypted_url, encrypted_username = line.strip().split("|")

                # Decrypt the details
                decrypted_email = decrypt_data(encrypted_email.encode(), key)
                decrypted_password = decrypt_data(encrypted_password.encode(), key)
                decrypted_url = decrypt_data(encrypted_url.encode(), key)
                decrypted_username = decrypt_data(encrypted_username.encode(), key)

                print("\nDecrypted Data:")
                print(f"Email: {decrypted_email}")
                print(f"Username: {decrypted_username}")
                print(f"Password: {decrypted_password}")
                print(f"URL: {decrypted_url}")

            except ValueError:
                print("Error: Invalid line format in the password file.")
                continue

if __name__ == "__main__":
    main()
