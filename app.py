from flask import Flask, render_template, request, redirect, url_for, jsonify
import bcrypt
import json
import os

app = Flask(__name__)

USER_DB = "users.json"

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_users(users):
    with open(USER_DB, 'w') as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/performlogin', methods=['POST'])
def login_user():
    username = request.form['username']
    password = request.form['password']
    users = load_users()

    if username not in users:
        return jsonify({"message": "Username does not exist."}), 400

    stored_hash = users[username]["password"]
    if check_password(stored_hash.encode('utf-8'), password):
        return jsonify({"message": "Login successful."}), 200
    else:
        return jsonify({"message": "Incorrect password."}), 400

@app.route('/performregister', methods=['POST'])
def register_user():
    username = request.form['username']
    password1 = request.form['password1']
    password2 = request.form['password2']

    if password1 != password2:
        return jsonify({"message": "Passwords do not match."}), 400

    users = load_users()

    if username in users:
        return jsonify({"message": "Username already exists."}), 400

    hashed_pw = hash_password(password1)
    users[username] = {"password": hashed_pw.decode('utf-8')}
    save_users(users)
    return jsonify({"message": "User registered successfully."}), 200

@app.route('/dashboard', methods=['POST'])
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
