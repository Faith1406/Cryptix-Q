from flask import Flask, request, render_template, redirect, url_for
from werkzeug.utils import secure_filename
import os
from normal_encryption import generate_rsa_keys, rsa_encrypt_message, rsa_decrypt_message

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)

private_key, public_key = generate_rsa_keys()

@app.route("/")
def home():
    encrypted_files = os.listdir(app.config['ENCRYPTED_FOLDER'])
    return render_template("index.html", encrypted_files=encrypted_files)

@app.route("/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return "No file provided", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    with open(file_path, "r") as f:
        file_content = f.read()
    
    encrypted_data = rsa_encrypt_message(public_key, file_content)
    encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], f"{filename}.enc")
    
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)
    
    return redirect(url_for("home"))

@app.route("/view-encrypted/<filename>")
def view_encrypted(filename):
    encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
    if not os.path.exists(encrypted_file_path):
        return "Encrypted file not found", 404
    
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    
    return render_template("view_encrypted.html", encrypted_data=encrypted_data, filename=filename)

@app.route("/decrypt/<filename>")
def decrypt_file(filename):
    encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
    if not os.path.exists(encrypted_file_path):
        return "Encrypted file not found", 404
    
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()
    
    try:
        decrypted_data = rsa_decrypt_message(private_key, encrypted_data)
    except Exception as e:
        return f"Failed to decrypt file: {e}", 500
    
    return render_template("decrypted.html", decrypted_data=decrypted_data, filename=filename)

if __name__ == "__main__":
    app.run(debug=True)
