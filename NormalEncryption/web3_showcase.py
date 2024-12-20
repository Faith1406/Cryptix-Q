from web3 import Web3
import json
from normal_encryption import key_exchange, encrypt_message

ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

if web3.is_connected():
    print("Connected to Ganache!")
else:
    raise ConnectionError("Unable to connect to Ganache.")

sender_address = "0x0793b2B73A224665982515f22166F0FfFea604f5"
private_key = "0x6f72ae1b6f74a02971d1f41539a8de2212e89b77401dd03396f66a1c187e91c9"

shared_key = key_exchange()
message = "This is a blockchain showcase!"
encrypted_data = encrypt_message(shared_key, message)
encrypted_message = json.dumps(encrypted_data)

print("\nEncrypted Message for Blockchain:", encrypted_message)

nonce = web3.eth.get_transaction_count(sender_address)
transaction = {
    'to': sender_address,
    'value': web3.to_wei(0, 'ether'),
    'gas': 2000000,
    'gasPrice': web3.to_wei('20', 'gwei'),
    'nonce': nonce,
    'data': encrypted_message.encode().hex()
}

signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

print("Transaction Hash:", web3.to_hex(tx_hash))