import numpy as np
from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory
from web3 import Web3
import os
import base64
from functools import wraps
from lwe import keygen, encrypt  # Import lattice encryption functions from the custom module
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Web3 connection setup
ganache_url = os.getenv('GANACHE_URL')  # Ganache's RPC URL
w3 = Web3(Web3.HTTPProvider(ganache_url))

# Check if connected to Ganache
if not w3.is_connected():
    raise Exception("Could not connect to Ganache.")

# Directory to store files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

AUTHORIZED_USERS = {
    os.getenv('ADMIN_USERNAME'): os.getenv('ADMIN_PASSWORD')
}

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in AUTHORIZED_USERS and AUTHORIZED_USERS[username] == password:
            session['username'] = username
            return redirect(url_for('home'))
        return "Invalid username or password", 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part in the request", 400
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400

        # Save the file temporarily
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        # Read file contents
        with open(filepath, 'rb') as f:
            plaintext = f.read()

        # Use the lattice-based encryption to encrypt the data
        pk, sk = keygen()  # Generate public and secret keys using LWE
        bit = 1  # Encrypt a fixed bit (can be adjusted based on the use case)
        encrypted_data = encrypt(pk, bit)

        # Convert encrypted data into a byte array (c1, c2)
        c1, c2 = encrypted_data
        c1_bytes = np.array(c1, dtype=np.uint16).tobytes()  # Convert c1 to bytes
        c2_bytes = np.array([c2], dtype=np.uint16).tobytes()  # Convert c2 to bytes

        # Combine c1 and c2 into a single byte array
        combined_encrypted_data = c1_bytes + c2_bytes

        # Save the encrypted data to a file
        encrypted_filename = f"encrypted_{file.filename}"
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        with open(encrypted_filepath, 'wb') as encrypted_file:
            encrypted_file.write(combined_encrypted_data)

        # Get the account address to send the transaction
        user_account = w3.eth.accounts[0]  # Use the first account in Ganache
        nonce = w3.eth.get_transaction_count(user_account)

        # Build the transaction to send encrypted data
        tx = {
            'from': user_account,
            'to': user_account,  # Sending to the same account or modify as needed
            'data': '0x' + combined_encrypted_data.hex(),  # Hex-encoded data
            'gas': 2000000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': nonce
        }

        # Sign the transaction (ensure you have the private key of the account)
        private_key = os.getenv('PRIVATE_KEY')  # Retrieve private key from .env
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Wait for transaction receipt
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # After sending the data, show the user confirmation
        return render_template('encrypt.html',
                               uploaded_filename=file.filename,
                               encrypted_filename=encrypted_filename,
                               encrypted_filepath=encrypted_filepath,
                               tx_receipt=tx_receipt)

    return render_template('encrypt.html')

@app.route('/download/<filename>')
@login_required
def send_file_from_server(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
