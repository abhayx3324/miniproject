import os
import json
import base64
import sys
from Crypto.Cipher import AES
from PIL import Image
from kyber_py.kyber import Kyber512
import numpy as np
from pymongo import MongoClient

def list_decrypt_files(users_collection, username):
    try:
        user_data = users_collection.find_one({"username": username})  # Query the database for the user
        if not user_data:
            print(f"Error: User '{username}' not found.", file=sys.stderr)
            return []

        user_files = user_data.get("files", {})
        return list(user_files.keys())
    except Exception as e:
        print(f"Error listing files for user '{username}': {str(e)}", file=sys.stderr)
        return []

def decrypt_text_file(aes_key, nonce, tag, ciphertext):
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except Exception as e:
        print(f"Error decrypting text file: {str(e)}", file=sys.stderr)
        return None

def decrypt_image_file(aes_key, nonce, tag, ciphertext, width, height, mode):
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        img_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        if mode == 'RGB':
            img_array = np.frombuffer(img_bytes, dtype=np.uint8).reshape((height, width, 3))
        elif mode == 'L':
            img_array = np.frombuffer(img_bytes, dtype=np.uint8).reshape((height, width))
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        img = Image.fromarray(img_array)
        return img
    except Exception as e:
        print(f"Error decrypting image file: {str(e)}", file=sys.stderr)
        return None

def decrypt_pdf_file(aes_key, nonce, tag, ciphertext):
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except Exception as e:
        print(f"Error decrypting PDF file: {str(e)}", file=sys.stderr)
        return None

def decrypt_docx_file(aes_key, nonce, tag, ciphertext):
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except Exception as e:
        print(f"Error decrypting DOCX file: {str(e)}", file=sys.stderr)
        return None

def decrypt_xlsx_file(aes_key, nonce, tag, ciphertext):
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except Exception as e:
        print(f"Error decrypting XLSX file: {str(e)}", file=sys.stderr)
        return None

def decrypt_zip_file(aes_key, nonce, tag, ciphertext):
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except Exception as e:
        print(f"Error decrypting ZIP file: {str(e)}", file=sys.stderr)
        return None

def decrypt_file_type(aes_key, file_extension, nonce, tag, ciphertext, width, height, mode):
    try:
        if file_extension == '.txt':
            return decrypt_text_file(aes_key, nonce, tag, ciphertext)
        elif file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return decrypt_image_file(aes_key, nonce, tag, ciphertext, width, height, mode)
        elif file_extension == '.pdf':
            return decrypt_pdf_file(aes_key, nonce, tag, ciphertext)
        elif file_extension == '.docx':
            return decrypt_docx_file(aes_key, nonce, tag, ciphertext)
        elif file_extension == '.xlsx':
            return decrypt_xlsx_file(aes_key, nonce, tag, ciphertext)
        elif file_extension == '.zip':
            return decrypt_zip_file(aes_key, nonce, tag, ciphertext)
        else:
            print(f"Unsupported file type: {file_extension}", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error decrypting file of type {file_extension}: {str(e)}", file=sys.stderr)
        return None

def decrypt_file(users_collection, username):
    try:
        if users_collection is None:
            return

        files = list_decrypt_files(users_collection, username)

        if not files:
            print(f"No decrypt files found for user '{username}'.")
            return

        print(f"\nFiles available for decryption by '{username}':")
        for idx, file_name in enumerate(files, 1):
            file_display_name = os.path.basename(file_name)
            print(f"{idx}. {file_display_name}")

        choice = input("\nEnter the number of the file you want to decrypt: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(files)):
            print("Invalid choice.", file=sys.stderr)
            return

        file_name = files[int(choice) - 1]

        user_data = users_collection.find_one({"username": username})  # Query the database for the user
        if not user_data:
            print(f"Error: User '{username}' not found.", file=sys.stderr)
            return

        user_files = user_data.get("files", {})

        file_path = user_files[file_name]["file_path"]

        challenge_base64 = user_files[file_name]["challenge"]

        private_key_file = username + ".pk"
        try:
            with open(private_key_file, 'rb') as key_file:
                private_key = key_file.read()
            print(f"Private key loaded from: {private_key_file}")
        except FileNotFoundError:
            print(f"Private key file {private_key_file} not found", file=sys.stderr)
            return
        except Exception as e:
            print(f"Error reading private key file: {str(e)}", file=sys.stderr)
            return

        challenge = base64.b64decode(challenge_base64)

        aes_key = Kyber512.decaps(private_key, challenge)

        # Read the encrypted file
        with open(file_path, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext_length = int.from_bytes(f.read(4), 'big')
            ciphertext = f.read(ciphertext_length)

            extension_length = int.from_bytes(f.read(1), 'big')
            file_extension = f.read(extension_length).decode('utf-8')

            if file_extension in ['.jpg', '.jpeg', '.png', '.bmp']:
                width = int.from_bytes(f.read(4), 'big')
                height = int.from_bytes(f.read(4), 'big')
                mode_length = int.from_bytes(f.read(1), 'big')
                mode = f.read(mode_length).decode('utf-8')
            else:
                width = height = mode = None

        # Decrypt the file based on its type
        decrypted_data = decrypt_file_type(aes_key, file_extension, nonce, tag, ciphertext, width, height, mode)
        if not decrypted_data:
            print("Decryption failed", file=sys.stderr)
            return

        # Write the decrypted data back to the file
        output_file = os.path.join(file_name + file_extension)
        if file_extension in ['.jpg', '.jpeg', '.png', '.bmp']:
            decrypted_data.save(output_file, format=file_extension.strip('.').upper())
        else:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

        print(f"Decrypted file stored at: {output_file}")

        users_collection.update_one(
                {"username": username},
                {"$unset": {f"files.{file_name}": ""}}
            )

        print(f"File record for '{file_name}' deleted from user data.")

        try:
            os.remove(file_path)
            print(f"File '{file_path}' has been deleted.")
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.", file=sys.stderr)
        except PermissionError:
            print(f"Error: Permission denied while trying to delete '{file_path}'.", file=sys.stderr)
        except Exception as e:
            print(f"Error removing file '{file_path}': {str(e)}", file=sys.stderr)

    except Exception as e:
        print(f"Error during file decryption process: {str(e)}", file=sys.stderr)
