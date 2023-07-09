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

def block_encrypt(alg, hash_alg, block_size, PT, KEY):
    if type(bytes(b"A")) != type(PT):
        PT = PT.encode("UTF-8")
    else:
        PT = bytes(PT)

    if type(bytes(b"A")) != type(KEY):
        KEY = KEY.encode("UTF-8")
    else:
        KEY = bytes(KEY)

    IV0 = bytes([x for x in range(len(KEY))])
    IV1 = bytes([x for x in range(len(KEY), -1, -1)])

    KEY0 = XOR(KEY, IV0)
    KEY1 = XOR(KEY, IV1)

    HMAC = hash_alg(KEY1 + hash_alg(KEY0 + PT + KEY0) + KEY1)
    TEXT = HMAC + PT
    CT = CTR_mode_encrypt(alg, block_size, TEXT, KEY)

    return CT

def block_decrypt(alg, hash_alg, block_size, CT, KEY):
    hash_size = len(hash_alg("A"))

    if type(bytes(b"A")) != type(CT):
        CT = CT.encode("UTF-8")
    else:
        CT = bytes(CT)

    if type(bytes(b"A")) != type(KEY):
        KEY = KEY.encode("UTF-8")
    else:
        KEY = bytes(KEY)

    IV0 = bytes([x for x in range(len(KEY))])
    IV1 = bytes([x for x in range(len(KEY), -1, -1)])

    KEY0 = XOR(KEY, IV0)
    KEY1 = XOR(KEY, IV1)

    TEXT = CTR_mode_encrypt(alg, block_size, CT, KEY)
    HMAC = TEXT[:hash_size]
    PT = TEXT[hash_size:]
    if HMAC != hash_alg(KEY1 + hash_alg(KEY0 + PT + KEY0) + KEY1):
        return False

    return PT
