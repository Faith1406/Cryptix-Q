import numpy as np

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

# Lattice-based Encryption Functions
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

def bytes_to_bits(data):
    # Convert a bytes object into a list of bits (0/1)
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits
