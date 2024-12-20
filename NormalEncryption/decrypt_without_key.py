import itertools
import base64
from normal_encryption import decrypt_message
from Crypto.Cipher import AES

def brute_force_decrypt(encrypted_data):
    possible_key_characters = range(256)
    key_length = 16

    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])

    print("Starting brute force attack... This could take a while.")

    for key in itertools.product(possible_key_characters, repeat=key_length):
        key_bytes = bytes(key)
        try:
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
            decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
            print("Decryption successful!")
            print("Key:", key_bytes)
            print("Decrypted Message:", decrypted_message.decode())
            return
        except Exception:
            continue

    print("Brute force attack failed: No valid key found.")

if __name__ == "__main__":
    encrypted_file_path = input("Enter the path of the encrypted file: ")

    try:
        with open(encrypted_file_path, "r") as f:
            import ast
            encrypted_data = ast.literal_eval(f.read())
    except FileNotFoundError:
        print("Encrypted file not found.")
        exit(1)
    except Exception as e:
        print(f"Error reading encrypted file: {e}")
        exit(1)

    brute_force_decrypt(encrypted_data)