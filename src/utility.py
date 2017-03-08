def ones_complement(num, bits=16):
    return num if num < (1 << bits) else (num + 1) % (1 << bits)
