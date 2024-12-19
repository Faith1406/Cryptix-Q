from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Step 1: Generate RSA Keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Encrypt Message with Public Key
def rsa_encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Step 3: Decrypt Message with Private Key
def rsa_decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Main for Demo
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()
    
    # Serialize keys for demonstration (optional)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print("Public Key:\n", public_pem.decode())
    print("Private Key:\n", private_pem.decode())
    
    # Encrypt and decrypt a message
    message = "This is a secure message using RSA!"
    print("\nOriginal Message:", message)
    
    encrypted_message = rsa_encrypt_message(public_key, message)
    print("Encrypted Message:", encrypted_message)
    
    decrypted_message = rsa_decrypt_message(private_key, encrypted_message)
    print("Decrypted Message:", decrypted_message)
