#!/usr/bin/env python3

def XOR(A, B):
    length = len(A) if len(A) < len(B) else len(B)

    X = []

    for i in range(length):
        X.append(A[i] ^ B[i])

    return bytes(X)

def CTR_mode_encrypt(alg, block_size, PT, KEY):
    CTR = 0
    CT = b""

    if type(bytes(b"A")) != type(PT):
        TEXT = PT.encode("UTF-8")
    else:
        TEXT = bytes(PT)

    while TEXT:
        text = TEXT[:block_size]
        TEXT = TEXT[block_size:]

        ctr = CTR.to_bytes(block_size, byteorder="little")
        tmp = alg(ctr, KEY)
        text = XOR(text, tmp)

        CT += text
        CTR += 1

    return CT

def CTR_mode_decrypt(alg, block_size, CT, KEY):
    return CTR_mode_encrypt(alg, block_size, CT, KEY)
