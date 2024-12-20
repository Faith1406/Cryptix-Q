def bytes_to_bits(data):
    # Convert a bytes object into a list of bits (0/1)
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits
