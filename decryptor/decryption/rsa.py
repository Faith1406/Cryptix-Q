from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def load_public_key(public_pem):
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key

def decrypt_rsa_with_public_key(public_key, ciphertext):
    try:
        decrypted_message = public_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def crack_rsa_encrypted_file(public_pem, encrypted_file_path):
    with open(encrypted_file_path, 'rb') as f:
        ciphertext = f.read()

    public_key = load_public_key(public_pem)
    
    decrypted_message = decrypt_rsa_with_public_key(public_key, ciphertext)
    
    return decrypted_message

if __name__ == "__main__":
    public_pem = b"""-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7B0BzFvO+/TQLx+dI/N7
    lGyZkC8wd5chY/3gH1ZmAtcdhTymEWSMxdNKZ2nBDQFZazdmbZIJ6GGH0+ocOa91
    i4nIGcEab5IH38G2l8O1lktx2unHkZ7t6pHpQ8LzQkJv4vyyJ9jlbcVVrfTdrJ19
    1aIuJvV6zG4vgsWhkEktcmDox14V8m4wURkFvHCG/Uu6b9BQnMHI2GVJ6HkTHjYa
    /lfL7Y7w6WqP5hAqU5fYwzTw73f5dq8UtZgsxtROSE7V3yMi4yTkm0CllAh2g7FD
    w/EeQ2qbE88jknMREbkZ5x3yZKv2F6Tu6A7YTrZrAfOrsqTu3yogF2Uq8VgnD0rI
    qfwFgDE+gmwTeYXXdLU4xyyVnkNDXeyxalR2VTeq9Y5zNJ34m8oW2+kZ4v5Mfwc=
    -----END PUBLIC KEY-----"""

    encrypted_file_path = 'path_to_your_encrypted_file.txt.enc'

    decrypted_message = crack_rsa_encrypted_file(public_pem, encrypted_file_path)
    print("Decrypted Message:", decrypted_message)
