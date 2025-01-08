import os
from flask import Flask, request, send_from_directory, jsonify

app = Flask(__name__)

# Configure file storage path
UPLOAD_FOLDER = 'encrypted_files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Save the file to the server
        file.save(file_path)

        file_url = f"http://127.0.0.1:5000/retrieve/{filename}"

        return jsonify({"message": "File uploaded successfully", "file_url": file_url}), 200


@app.route('/retrieve/<filename>', methods=['GET'])
def retrieve_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        return jsonify({"error": f"File {filename} not found"}), 404

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)  # Create the upload folder if it doesn't exist
    app.run(debug=True)
