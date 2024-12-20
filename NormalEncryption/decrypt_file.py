from normal_encryption import decrypt_message, key_exchange
import ast

shared_key = key_exchange()

def decrypt_file(encrypted_file_path):
    try:
        with open(encrypted_file_path, "r") as f:
            encrypted_data = ast.literal_eval(f.read())
        
        decrypted_message = decrypt_message(shared_key, encrypted_data)
        print("Decrypted Message:", decrypted_message)
    except Exception as e:
        print("Decryption failed:", str(e))

if __name__ == "__main__":
    encrypted_file_path = input("Enter the path of the encrypted file: ")
    decrypt_file(encrypted_file_path)
