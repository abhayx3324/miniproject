import bcrypt
import base64
from encrypt import encrypt_and_send
from decrypt import receive_and_decrypt
from kyber_py.kyber import Kyber512
from pymongo import MongoClient
import sys
import getpass
import re

MONGO_URI = "mongodb+srv://abhayv0324:0324Abhay@miniproject.ejdl9.mongodb.net/"
DB_NAME = "users_db"
COLLECTION_NAME = "users"

def get_users_collection():
    try:
        client = MongoClient(MONGO_URI)
        print("Connected successfully!")
        db = client[DB_NAME]
        return db[COLLECTION_NAME]
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        return None

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

def login_user(users_collection, username, password):
    try:
        if users_collection is None:
            print("Error: Users collection could not be retrieved.", file=sys.stderr)
            return None
        print(f"Searching for username: {username}")
        user = users_collection.find_one({"username": username})
        if user is None:
            print("Username does not exist.", file=sys.stderr)
            return None
        stored_hash = user["password"].encode('utf-8')
        if check_password(stored_hash, password):
            public_key_base64 = user["public_key"]
            public_key = base64.b64decode(public_key_base64)
            print("Login successful.")
            return public_key
        else:
            print("Incorrect password.", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error during login: {e}", file=sys.stderr)
        return None

def register_user(users_collection, username, password):
    try:
        if users_collection is None:
            print("Error: Users collection could not be retrieved.", file=sys.stderr)
            return False
        if users_collection.find_one({"username": username}):
            print("Username already exists.", file=sys.stderr)
            return False
        hashed_pw = hash_password(password)
        if not hashed_pw:
            print("Error hashing password. Registration failed.", file=sys.stderr)
            return False
        public_key, private_key = Kyber512.keygen()
        public_key_base64 = base64.b64encode(public_key).decode('utf-8')
        private_key_file = f"{username}.pk"
        with open(private_key_file, 'wb') as key_file:
            key_file.write(private_key)
        print(f"Private key stored at: {private_key_file}")
        user_data = {
            "username": username,
            "password": hashed_pw.decode('utf-8'),
            "public_key": public_key_base64,
            "files": {}
        }
        result = users_collection.insert_one(user_data)
        print(f"Inserted user with ID: {result.inserted_id}")
        print("User registered successfully.")
        return True
    except Exception as e:
        print(f"Error during registration: {e}", file=sys.stderr)
        return False

def inner_menu(users_collection, username, public_key):
    while True:
        try:
            print("\n1. Encrypt and send \n2. Recieve and decrypt \n3. Logout")
            ch = int(input("Enter your choice: "))
            if ch == 1:
                encrypt_and_send(users_collection)
            elif ch == 2:
                receive_and_decrypt(users_collection, username)
            elif ch == 3:
                return
            else:
                print("Invalid choice", file=sys.stderr)
        except Exception as e:
            print(f"Error in inner menu: {e}", file=sys.stderr)

def validate_username(username):
    if len(username) < 3:
        print("Username must be at least 3 characters long.", file=sys.stderr)
        return False
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        print("Username can only contain letters, numbers, and the following special characters: . _ -", file=sys.stderr)
        return False
    return True

def validate_password(password):
    if len(password) < 6:
        print("Password must be at least 6 characters long.", file=sys.stderr)
        return False
    return True

def main():
    users_collection = get_users_collection()
    while True:
        try:
            print("\n1. Login \n2. Register \n3. Exit")
            ch = int(input("Enter your choice: "))
            if ch == 1:
                username = input("Enter your username: ")
                password = getpass.getpass("Enter your password: ")
                public_key = login_user(users_collection, username, password)
                if public_key is not None:
                    inner_menu(users_collection, username, public_key)
                else:
                    print("Login was unsuccessful. Try again.", file=sys.stderr)
            elif ch == 2:
                username = input("Enter username: ")
                if not validate_username(username):
                    continue
                password1 = getpass.getpass("Enter password: ")
                password2 = getpass.getpass("Enter password again: ")
                if password1 != password2:
                    print("Passwords do not match. Please try again.", file=sys.stderr)
                    continue
                if not validate_password(password1):
                    continue
                if register_user(users_collection, username, password1) is not None:
                    print("Register successful. Now please login.")
                else:
                    print("Register was unsuccessful. Try again.", file=sys.stderr)
            elif ch == 3:
                exit(0)
            else:
                print("Invalid choice. Please try again.", file=sys.stderr)
        except Exception as e:
            print(f"Error in main loop: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
