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
import requests

def select_file_encryption():
    try:
        root = tk.Tk()
        file_path = filedialog.askopenfilename(
            title="Select a file to be encrypted",
            filetypes=[("Text Files", "*.txt"),
                      ("PDF Files", "*.pdf"),
                      ("Word Documents", "*.docx"),
                      ("Excel Documents", "*.xlsx"),
                      ("Image Files", "*.jpg;*.jpeg;*.png;*.bmp"),
                      ("Zip Files", "*.zip"),
                      ("All Files", "*.*")]
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

def select_user_to_send(users_collection):
    user_list = list(users_collection.find({}, {"username": 1, "public_key": 1, "_id": 0}))
    
    if not user_list:
        print("No users found in the database.", file=sys.stderr)
        return None, None

    print("Select user: ")
    for user in user_list:
        print(user['username'])

    selected_user = input("Enter the username to send the file to: ").strip()

    for user in user_list:
        if user['username'] == selected_user:
            print(f"Selected user: {selected_user}")
            return selected_user, user['public_key']
    
    print("Invalid username selected.", file=sys.stderr)
    return None, None

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
            data = f.read()
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

def encrypted_file_creation(file_path, aes_key, file_extension):
    result = encrypt_file_type(file_path, aes_key, file_extension)
    if not result:
        print("Error during encryption", file=sys.stderr)
        return

    nonce, ciphertext, tag, width, height, mode = result

    file_extension_bytes = file_extension.encode('utf-8')
    extension_length = len(file_extension_bytes)

    encrypted_file = bytearray()
    encrypted_file.extend(nonce)
    encrypted_file.extend(tag)
    encrypted_file.extend(len(ciphertext).to_bytes(4, 'big'))
    encrypted_file.extend(ciphertext)
    encrypted_file.extend(extension_length.to_bytes(1, 'big'))
    encrypted_file.extend(file_extension_bytes)

    if width and height:
        encrypted_file.extend(width.to_bytes(4, 'big'))
        encrypted_file.extend(height.to_bytes(4, 'big'))
        mode_bytes = mode.encode('utf-8')
        encrypted_file.extend(len(mode_bytes).to_bytes(1, 'big'))
        encrypted_file.extend(mode_bytes)
        
    return encrypted_file

def encrypt_and_send(users_collection):
    try:
        username, public_key_base64 = select_user_to_send(users_collection)
        
        public_key = base64.b64decode(public_key_base64)
        
        aes_key, challenge = Kyber512.encaps(public_key)
        challenge_base64 = base64.b64encode(challenge).decode('utf-8')
        
        file_path, file_name, file_extension = select_file_encryption()
        
        file_display_name = os.path.basename(file_name)

        if not file_path or not file_extension:
            print("File does not exist", file=sys.stderr)
            return

        
        encrypted_file = encrypted_file_creation(file_path, aes_key, file_extension)
        
        files = {
            'file': (f"{file_display_name}@{username}.dat", bytes(encrypted_file))
        }
        upload_url = "http://127.0.0.1:5000/upload"
        response = requests.post(upload_url, files=files)

        if response.status_code != 200:
            print(f"Error uploading file: {response.json().get('error', 'Unknown error')}", file=sys.stderr)
            return

        file_url = response.json().get("file_url")
        print(f"Encrypted file uploaded successfully. URL: {file_url}")

        users_collection.update_one(
            {"username": username},
            {"$set": {
                f"files.{file_display_name}": {
                    "file_url": file_url,
                    "challenge": challenge_base64
                }
            }},
            upsert=True
        )
        
    except Exception as e:
        print(f"An error occurred during file encryption: {e}", file=sys.stderr)
