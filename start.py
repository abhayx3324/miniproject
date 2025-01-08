import bcrypt
import os
import base64
from encrypt import encrypt_file
from decrypt import decrypt_file
from kyber_py.kyber import Kyber512
from pymongo import MongoClient
import sys

# MongoDB Configuration
MONGO_URI = "mongodb+srv://abhayv0324:0324Abhay@miniproject.ejdl9.mongodb.net/"  # Replace with your MongoDB URI
DB_NAME = "users_db"
COLLECTION_NAME = "users"

# MongoDB Connection Setup
def get_mongo_client():
    try:
        client = MongoClient(MONGO_URI)
        print("Connected successfully!")
        return client
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        return None

def get_users_collection():
    client = get_mongo_client()
    if client:
        db = client[DB_NAME]
        return db[COLLECTION_NAME]
    return None

# Password Hashing
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

# User Authentication
def login_user(users_collection, username, password):
    try:
        if users_collection is None:  # Explicit comparison with None
            print("Error: Users collection could not be retrieved.", file=sys.stderr)
            return None

        # Fetch the user document
        print(f"Searching for username: {username}")
        user = users_collection.find_one({"username": username})
        if user is None:  # Explicitly check for None
            print("Username does not exist.", file=sys.stderr)
            return None

        # Get the stored password hash
        stored_hash = user["password"].encode('utf-8')

        # Verify the password
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
        if users_collection is None:  # Explicit comparison with None
            print("Error: Users collection could not be retrieved.", file=sys.stderr)
            return False

        # Check if the username already exists
        if users_collection.find_one({"username": username}):
            print("Username already exists.", file=sys.stderr)
            return False

        # Hash the password
        hashed_pw = hash_password(password)
        if not hashed_pw:
            print("Error hashing password. Registration failed.", file=sys.stderr)
            return False

        # Generate public and private keys
        public_key, private_key = Kyber512.keygen()
        public_key_base64 = base64.b64encode(public_key).decode('utf-8')

        # Save the private key to a file
        private_key_file = f"{username}.pk"
        with open(private_key_file, 'wb') as key_file:
            key_file.write(private_key)
        print(f"Private key stored at: {private_key_file}")

        # Prepare user data
        user_data = {
            "username": username,
            "password": hashed_pw.decode('utf-8'),
            "public_key": public_key_base64,
            "files": {}
        }

        # Insert the user data into the collection
        result = users_collection.insert_one(user_data)
        print(f"Inserted user with ID: {result.inserted_id}")
        print("User registered successfully.")
        return True
    except Exception as e:
        print(f"Error during registration: {e}", file=sys.stderr)
        return False

# File Operations
def inner_menu(users_collection, username, public_key):
    while True:
        try:
            print("\n1. Encrypt \n2. Decrypt \n3. Logout")
            ch = int(input("Enter your choice: "))
            if ch == 1:
                encrypt_file(users_collection, username, public_key)
            elif ch == 2:
                decrypt_file(users_collection, username)
            elif ch == 3:
                return
            else:
                print("Invalid choice", file=sys.stderr)
        except Exception as e:
            print(f"Error in inner menu: {e}", file=sys.stderr)

# Main Menu
def main():
    users_collection = get_users_collection();
    while True:
        try:
            print("\n1. Login \n2. Register \n3. Exit")
            ch = int(input("Enter your choice: "))
            if ch == 1:
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                public_key = login_user(users_collection, username, password)
                if public_key is not None:
                    inner_menu(users_collection, username, public_key)
                else:
                    print("Login was unsuccessful. Try again.", file=sys.stderr)
            elif ch == 2:
                username = input("Enter username: ")
                password1 = input("Enter password: ")
                password2 = input("Enter password again: ")
                if password1 == password2:
                    if register_user(users_collection, username, password1) is not None:
                        print("Register successful. Now please login.")
                    else:
                        print("Register was unsuccessful. Try again.", file=sys.stderr)
                else:
                    print("Passwords do not match. Please try again.", file=sys.stderr)
            elif ch == 3:
                exit(0)
            else:
                print("Invalid choice. Please try again.", file=sys.stderr)
        except Exception as e:
            print(f"Error in main loop: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
