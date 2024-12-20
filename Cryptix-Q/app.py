import numpy as np
from flask import Flask, request, render_template, session, redirect, url_for, send_from_directory
from web3 import Web3
import os
import base64
from functools import wraps
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Lattice Parameters
n = 16  # Lattice dimension
m = 32  # Lattice dimension (usually m > n)
q = 257  # Modulus for the ring
half_q = q // 2  # Half the modulus, used for binary field elements

# Utility Functions
def mod_q(x):
    return np.mod(x, q)

def small_error_vector(size):
    return np.random.choice([-1, 0, 1], size=size)

def bit_to_field_element(bit):
    return 0 if bit == 0 else half_q

def field_element_to_bit(x):
    return 0 if x < half_q else 1

def bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        byte = 0
        for j, bit in enumerate(byte_bits):
            byte |= bit << j
        bytes_data.append(byte)
    return bytes(bytes_data)

def keygen():
    s = np.random.randint(low=0, high=q, size=n)  # Secret key
    A = np.random.randint(low=0, high=q, size=(m, n))  # Public matrix A
    e = small_error_vector(m)  # Small error vector
    b = mod_q(A.dot(s) + e)  # Public key vector b
    return (A, b), s  # Public key and secret key

def encrypt(pk, bit):
    A, b = pk  # Public key
    mu = bit_to_field_element(bit)  # Convert the bit to a field element
    r = small_error_vector(m)  # Random error vector r
    c1 = mod_q(A.T.dot(r))  # First part of the ciphertext
    c2 = mod_q(b.dot(r) + mu)  # Second part of the ciphertext
    return (c1.tolist(), int(c2))  # Return the ciphertext as a tuple

def decrypt(sk, ct):
    c1, c2 = ct  # Ciphertext parts
    c1 = np.array(c1)
    x = mod_q(c2 - sk.dot(c1))  # Decryption
    return field_element_to_bit(x)  # Convert back to bit

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Web3 connection setup
ganache_url = os.getenv('GANACHE_URL')
w3 = Web3(Web3.HTTPProvider(ganache_url))

if not w3.is_connected():
    raise Exception("Could not connect to Ganache.")

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

        # Read file contents and convert to bits
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        plaintext_bits = bytes_to_bits(plaintext)

        # Generate keys
        pk, sk = keygen()
        
        # Encrypt each bit
        encrypted_bits = []
        for bit in plaintext_bits:
            encrypted_bit = encrypt(pk, bit)
            encrypted_bits.append(encrypted_bit)

        # Serialize encrypted data
        serialized_data = {
            'public_key': {'A': pk[0].tolist(), 'b': pk[1].tolist()},
            'secret_key': sk.tolist(),
            'encrypted_bits': encrypted_bits
        }
        
        # Convert to bytes for blockchain storage
        encrypted_data = str(serialized_data).encode()

        # Save the encrypted data to a file
        encrypted_filename = f"encrypted_{file.filename}"
        encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        with open(encrypted_filepath, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Get the account address to send the transaction
        user_account = w3.eth.accounts[0]
        nonce = w3.eth.get_transaction_count(user_account)

        # Build the transaction
        tx = {
            'from': user_account,
            'to': user_account,
            'data': '0x' + encrypted_data.hex(),
            'gas': 2000000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': nonce
        }

        # Sign and send the transaction
        private_key = os.getenv('PRIVATE_KEY')
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

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