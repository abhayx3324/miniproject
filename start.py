import bcrypt
import os
import json
import base64
from encrypt import encrypt_file
from decrypt import decrypt_file
from kyber_py.kyber import Kyber512
import sys

USER_DB = "users.json"

def load_users():
    try:
        if os.path.exists(USER_DB):
            with open(USER_DB, 'r') as f:
                return json.load(f)
        else:
            # Initialize the file if it doesn't exist
            with open(USER_DB, 'w') as f:
                json.dump({}, f, indent=4)
            return {}  # Return an empty dictionary if the file doesn't exist
    except Exception as e:
        print(f"Error loading users: {e}", file=sys.stderr)
        return {}

def save_users(users):
    try:
        with open(USER_DB, 'w') as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        print(f"Error saving users: {e}", file=sys.stderr)

def hash_password(password):
    try:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    except Exception as e:
        print(f"Error hashing password: {e}", file=sys.stderr)
        return None

def check_password(stored_hash, password):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    except Exception as e:
        print(f"Error checking password: {e}", file=sys.stderr)
        return False

def login_user(username, password):
    try:
        users_data = load_users()

        if username not in users_data:
            print("Username does not exist.", file=sys.stderr)
            return None

        stored_hash = users_data[username]["password"]
        if check_password(stored_hash.encode('utf-8'), password):
            public_key_base64 = users_data[username]["public_key"]

            # Decode from base64 back to binary
            public_key = base64.b64decode(public_key_base64)
            print("Login successful.")
            return public_key
        else:
            print("Incorrect password.", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error during login: {e}", file=sys.stderr)
        return None

def register_user(username, password):
    try:
        users = load_users()

        if username in users:
            print("Username already exists.", file=sys.stderr)
            return False

        hashed_pw = hash_password(password)
        if hashed_pw is None:
            print("Error hashing password. Registration failed.", file=sys.stderr)
            return False

        public_key, private_key = Kyber512.keygen()
        public_key_base64 = base64.b64encode(public_key).decode('utf-8')

        private_key_file = username + ".pk"
        with open(private_key_file, 'wb') as key_file:
            key_file.write(private_key)
        print(f"Private key stored at: {private_key_file}")

        users[username] = {
            "password": hashed_pw.decode('utf-8'),
            "public_key": public_key_base64,
            "files": {},
        }
        save_users(users)
        print("User registered successfully.")
        return True
    except Exception as e:
        print(f"Error during registration: {e}", file=sys.stderr)
        return False

def inner_menu(username, public_key):
    while True:
        try:
            print("\n1.Encrypt \n2.Decrypt \n3.Logout")
            ch = int(input("Enter your choice: "))
            if ch == 1:
                encrypt_file(username, public_key)
            elif ch == 2:
                decrypt_file(username)
            elif ch == 3:
                return
            else:
                print("Invalid choice", file=sys.stderr)
        except Exception as e:
            print(f"Error in inner menu: {e}", file=sys.stderr)

def main():
    while True:
        try:
            print("\n1.Login \n2.Register \n3.Exit")
            ch = int(input("Enter your choice: "))
            if ch == 1:
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                pk = login_user(username, password)
                if pk is not None:
                    inner_menu(username, pk)
                else:
                    print("Login was unsuccessful. Try again", file=sys.stderr)
                    continue

            elif ch == 2:
                username = input("Enter username: ")
                password1 = input("Enter password: ")
                password2 = input("Enter password again: ")
                if password1 == password2:
                    if register_user(username, password1):
                        print("Register successful. Now please login")
                        continue
                    else:
                        print("Register was unsuccessful. Try again", file=sys.stderr)
                        continue
                else:
                    print("Passwords do not match. Please try again.", file=sys.stderr)
                    continue
            if ch == 3:
                exit(0)

        except Exception as e:
            print(f"Error in main loop: {e}", file=sys.stderr)

main()
