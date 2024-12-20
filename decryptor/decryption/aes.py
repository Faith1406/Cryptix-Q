from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def load_aes_key(path):
    """
    Load the AES key from a file (or any other method).
    """
    with open(path, 'rb') as key_file:
        aes_key = key_file.read()  
    return aes_key

def decrypt_aes(encrypted_data, aes_key_path):
    
    aes_key = load_aes_key(aes_key_path)
    iv = encrypted_data[:16]  
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data.decode('utf-8')
