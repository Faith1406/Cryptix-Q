from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'enc', 'txt.enc', 'aes.enc', 'rsa.enc'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'your_secret_key'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html', message=request.args.get('message', ''))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index', message='No file part in request.'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index', message='No file selected.'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            decrypted_content = attempt_decrypt(filepath)
            message = f"Decryption successful! Content: {decrypted_content}"
        except Exception as e:
            message = f"Decryption failed: {str(e)}"

        flash(message)
        return redirect(url_for('index', message=message))
    else:
        flash('Invalid file type. Allowed types: .enc, .txt.enc, etc.')
        return redirect(url_for('index', message='Invalid file type.'))

def attempt_decrypt(filepath):
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted_data = try_rsa_decrypt(encrypted_data)
        if decrypted_data:
            return decrypted_data
    except Exception as e:
        pass

    try:
        decrypted_data = try_aes_decrypt(encrypted_data)
        if decrypted_data:
            return decrypted_data
    except Exception as e:
        pass

    raise ValueError("Decryption failed for all known methods.")

def try_rsa_decrypt(encrypted_data):
    private_key = load_rsa_private_key()
    try:
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError("RSA decryption failed: " + str(e))

def load_rsa_private_key():
    with open('path_to_private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def try_aes_decrypt(encrypted_data):
    aes_key = load_aes_key()
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError("AES decryption failed: " + str(e))

def load_aes_key():
    return b'32_byte_aes_key_for_testing___'

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
