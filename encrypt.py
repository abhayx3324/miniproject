import os
import json
import base64
import sys
import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from PIL import Image
from kyber_py.kyber import Kyber512
from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb+srv://abhayv0324:0324Abhay@miniproject.ejdl9.mongodb.net/")  # Replace with your MongoDB URI
db = client["users_db"]  # Database name
users_collection = db["users"]  # Collection name

def load_users():
    try:
        users = {}
        for user in users_collection.find():
            users[user["_id"]] = user
        return users
    except Exception as e:
        print(f"An error occurred while loading users from MongoDB: {e}", file=sys.stderr)
        return {}
    
def save_users(users):
    try:
        for username, data in users.items():
            users_collection.update_one(
                {"_id": username},  # Use `_id` as the unique identifier
                {"$set": data},  # Update the data
                upsert=True  # Insert if not already present
            )
    except Exception as e:
        print(f"An error occurred while saving users to MongoDB: {e}", file=sys.stderr)

def select_file_encryption():
    try:
        root = tk.Tk()
        file_path = filedialog.askopenfilename(
            title="Select a file to be encrypted",
            filetypes=[
                ("Text Files", "*.txt"),
                ("PDF Files", "*.pdf"),
                ("Word Documents", "*.docx"),
                ("Excel Documents", "*.xlsx"),
                ("Image Files", "*.jpg;*.jpeg;*.png;*.bmp"),
                ("Zip Files", "*.zip"),
                ("All Files", "*.*"),
            ]
        )
        root.destroy()
        file_name = os.path.splitext(file_path)[0]
        file_extension = os.path.splitext(file_path)[1]
        print(f"Selected file: {file_path}")
        print(f"File extension: {file_extension}")
        root.quit()

        return file_path, file_name, file_extension
    except Exception as e:
        print(f"An error occurred while selecting the file: {e}", file=sys.stderr)
        return None, None, None


def encrypt_text_file(file_path, aes_key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag, None, None, None
    except Exception as e:
        print(f"An error occurred while encrypting text file: {e}", file=sys.stderr)
        return None, None, None, None, None, None


def encrypt_image_file(file_path, aes_key):
    try:
        with Image.open(file_path) as img:
            width, height = img.size
            img_bytes = img.tobytes()
            mode = img.mode
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(img_bytes)
        return cipher.nonce, ciphertext, tag, width, height, mode
    except Exception as e:
        print(f"An error occurred while encrypting image file: {e}", file=sys.stderr)
        return None, None, None, None, None, None


def encrypt_pdf_file(file_path, aes_key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag, None, None, None
    except Exception as e:
        print(f"An error occurred while encrypting PDF file: {e}", file=sys.stderr)
        return None, None, None, None, None, None


def encrypt_docx_file(file_path, aes_key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()  # Read the entire file as bytes
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag, None, None, None
    except Exception as e:
        print(f"An error occurred while encrypting DOCX file: {e}", file=sys.stderr)
        return None, None, None, None, None, None


def encrypt_xlsx_file(file_path, aes_key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag, None, None, None
    except Exception as e:
        print(f"An error occurred while encrypting XLSX file: {e}", file=sys.stderr)
        return None, None, None, None, None, None


def encrypt_zip_file(file_path, aes_key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag, None, None, None
    except Exception as e:
        print(f"An error occurred while encrypting ZIP file: {e}", file=sys.stderr)
        return None, None, None, None, None, None


def encrypt_file_type(file_path, aes_key, file_extension):
    try:
        if file_extension == '.txt':
            return encrypt_text_file(file_path, aes_key)
        elif file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return encrypt_image_file(file_path, aes_key)
        elif file_extension == '.pdf':
            return encrypt_pdf_file(file_path, aes_key)
        elif file_extension == '.docx':
            return encrypt_docx_file(file_path, aes_key)
        elif file_extension == '.xlsx':
            return encrypt_xlsx_file(file_path, aes_key)
        elif file_extension == '.zip':
            return encrypt_zip_file(file_path, aes_key)
        else:
            print(f"Unsupported file type: {file_extension}", file=sys.stderr)
            return None, None, None, None, None
    except Exception as e:
        print(f"An error occurred while encrypting file type: {e}", file=sys.stderr)
        return None, None, None, None, None


def encrypt_file(username, public_key):
    try:
        aes_key, challenge = Kyber512.encaps(public_key)

        challenge_base64 = base64.b64encode(challenge).decode('utf-8')

        # Get file details
        file_path, file_name, file_extension = select_file_encryption()

        if not file_path or not file_extension:
            print("File does not exist", file=sys.stderr)
            return

        # Encrypt the file
        result = encrypt_file_type(file_path, aes_key, file_extension)
        if not result:
            print("Error during encryption", file=sys.stderr)
            return

        nonce, ciphertext, tag, width, height, mode = result

        # Prepare the encrypted file
        output_file = file_name + '.dat'
        file_extension_bytes = file_extension.encode('utf-8')
        extension_length = len(file_extension_bytes)

        with open(output_file, 'wb') as f:
            f.write(nonce)
            f.write(tag)
            f.write(len(ciphertext).to_bytes(4, 'big'))
            f.write(ciphertext)
            f.write(extension_length.to_bytes(1, 'big'))
            f.write(file_extension_bytes)

            if width and height:
                f.write(width.to_bytes(4, 'big'))
                f.write(height.to_bytes(4, 'big'))
                mode_bytes = mode.encode('utf-8')
                f.write(len(mode_bytes).to_bytes(1, 'big'))
                f.write(mode_bytes)

        print(f"Encrypted file stored at: {output_file}")

        os.remove(file_path)
        print(f"Original file {file_path} deleted after encryption.")

        users_collection.update_one(
            {"_id": username},  # Use `_id` as the unique identifier
            {"$set": {
                f"files.{file_name}": {
                    "file_path": output_file,
                    "challenge": challenge_base64
                }
            }},
            upsert=True  # Insert if the user does not already exist
        )

    except Exception as e:
        print(f"An error occurred during file encryption: {e}", file=sys.stderr)
