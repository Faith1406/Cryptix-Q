def check_rsa_signature(data):
    return b'RSA' in data

def check_aes_signature(data):

    return b'AES' in data
