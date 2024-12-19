import numpy as np

n = 16  
m = 32  
q = 257  
half_q = q // 2  

def mod_q(x):
    return np.mod(x, q)

def small_error_vector(size):
    return np.random.choice([-1, 0, 1], size=size)

def bit_to_field_element(bit):
    return 0 if bit == 0 else half_q

def field_element_to_bit(x):
    return 0 if x < half_q else 1


def keygen():
    s = np.random.randint(low=0, high=q, size=n)  
    A = np.random.randint(low=0, high=q, size=(m, n))  
    e = small_error_vector(m) 
    b = mod_q(A.dot(s) + e)  
    return (A, b), s 
def encrypt(pk, bit):
    A, b = pk  
    mu = bit_to_field_element(bit) 
    r = small_error_vector(m) 
    c1 = mod_q(A.T.dot(r)) 
    c2 = mod_q(b.dot(r) + mu)  
    return (c1.tolist(), int(c2)) 

def decrypt(sk, ct):
    c1, c2 = ct  
    c1 = np.array(c1)
    x = mod_q(c2 - sk.dot(c1))  
    return field_element_to_bit(x)  

def bytes_to_bits(data):
    
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits
