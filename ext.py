#!/usr/bin/env python3

import base64

def ADD(A, B):
    if len(A) != len(B):
        return False

    X = []

    for i in range(len(A)):
        X.append((A[i] + B[i]) % 256)

    return X

def ROTATE(X, R):
    R = R % len(X)

    X = list(X)
    Y = []

    for _ in range(R):
        Y.append(X.pop())
    Y.reverse()

    Y = Y + X

    return Y

def XOR(A, B):
    if len(A) != len(B):
        return False

    X = []

    for i in range(len(A)):
        X.append(A[i] ^ B[i])

    return X

def F(R, k):
    k0 = k[:32]
    k1 = k[32:64]
    k2 = k[64:96]
    k3 = k[96:]

    X = R

    X = ADD(X, k0)
    X = XOR(X, k1)

    X = ADD(X, k2)
    X = XOR(X, k3)

    X0 = ROTATE(X, 1)
    X1 = ROTATE(X, 2)
    X2 = ROTATE(X, 3)
    X3 = ROTATE(X, 4)

    X4 = ADD(X0, X1)
    X5 = ADD(X2, X3)

    X = XOR(X4, X5)

    return X

def ext_block_encrypt(PT, KEY):
    # Block cipher (64bit PT, 128bit KEY)
    if len(PT) != 64 or len(KEY) != 128:
        return False

    PT = list(PT)
    KEY = list(KEY)

    # Feistel cipher

    L = PT[:32]
    R = PT[32:]

    k = KEY

    for _ in range(16):
        CT = XOR(L, F(R, k))
        L = R
        R = CT

    CT = L + R
    CT = bytes(CT)

    return CT

def ext_block_decrypt(CT, KEY):
    # Block cipher (64bit PT, 128bit KEY)
    if len(CT) != 64 or len(KEY) != 128:
        return False

    CT = list(CT)
    KEY = list(KEY)

    # Feistel cipher

    R = CT[:32]
    L = CT[32:]

    k = KEY

    for _ in range(16):
        PT = XOR(L, F(R, k))
        L = R
        R = PT

    PT = R + L
    PT = bytes(PT)

    return PT

def ext_hash(TEXT):
    if type(bytes(b"A")) != type(TEXT):
        TEXT = TEXT.encode("UTF-8")

    IV = [x for x in range(0, 128)]
    IV = bytes(IV)

    text = bytes(TEXT)
    while text:
        PT = text[:64]
        text = text[64:]

        PT += b"A" * (64 - len(PT))

        HASH = ext_block_encrypt(PT, IV)

        IV = HASH + IV[:64]

    HASH0 = HASH

    IV = [x for x in range(127, -1, -1)]
    IV = bytes(IV)

    text = bytes(TEXT)
    while text:
        PT = text[:64]
        text = text[64:]

        PT = b"r" * (64 - len(PT)) + PT

        HASH = ext_block_encrypt(PT, IV)

        IV = IV[:64] + HASH

    HASH1 = HASH

    HASH = HASH0 + HASH1
    HASH = bytes(HASH)

    return HASH

def main():
    print("= Choose a mode (ENC/DEC)")
    MODE = input()

    if MODE == "ENC":
        print("= Plain text")
        PT = input()
        PT = base64.b64decode(PT)

        print("= Cryptographic key")
        KEY = input()
        KEY = base64.b64decode(KEY)

        print("= Cipher text")
        CT = ext_block_encrypt(PT, KEY)
        CT = base64.b64encode(CT).decode()
    
        print(CT)
    elif MODE == "DEC":
        print("= Cipher text")
        CT = input()
        CT = base64.b64decode(CT)

        print("= Cryptographic key")
        KEY = input()
        KEY = base64.b64decode(KEY)

        print("= Plain text")
        PT = ext_block_decrypt(CT, KEY)
        PT = base64.b64encode(PT).decode()

        print(PT)
    else:
        return 1

if __name__ == "__main__":
    exit(main())
