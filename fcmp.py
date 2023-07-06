#!/usr/bin/env python3

# Fast Cipher Message Protocol 1.0

import os

from base64 import b64encode, b64decode

from ext import ext_block_encrypt, ext_block_decrypt, ext_hash
from block import block_encrypt, block_decrypt
from dh import dh_keygen, dh_getkey

BLOCK_CIPHER_ALG = ext_block_encrypt
HASH_ALG = ext_hash
BLOCK_SIZE = 64

BEGIN_FCMP_MESSAGE = "-----BEGIN FCMP MESSAGE-----"
END_FCMP_MESSAGE = "-----END FCMP MESSAGE-----"
BEGIN_FCMP_PUBLIC_KEY_BLOCK = "-----BEGIN FCMP PUBLIC KEY BLOCK-----"
END_FCMP_PUBLIC_KEY_BLOCK = "-----END FCMP PUBLIC KEY BLOCK-----"
BEGIN_FCMP_PRIVATE_KEY_BLOCK = "-----BEGIN FCMP PRIVATE KEY BLOCK-----"
END_FCMP_PRIVATE_KEY_BLOCK = "-----END FCMP PRIVATE KEY BLOCK-----"

def fcmp_keygen():
    return dh_keygen()

def fcmp_encrypt(sender_private, sender_public, receiver_public, msg):
    KEY = HASH_ALG(dh_getkey(sender_private, receiver_public))
    CT = block_encrypt(BLOCK_CIPHER_ALG, HASH_ALG, BLOCK_SIZE, msg, KEY)
    
    res = ""
    
    res += BEGIN_FCMP_MESSAGE + "\n\n"
    res += b64encode(CT).decode() + "\n"
    res += END_FCMP_MESSAGE + "\n\n"

    public_key = sender_public.to_bytes(256, byteorder="little")

    res += BEGIN_FCMP_PUBLIC_KEY_BLOCK + "\n\n"
    res += b64encode(public_key).decode() + "\n"
    res += END_FCMP_PUBLIC_KEY_BLOCK + "\n\n"

    return res

def fcmp_decrypt(receiver_private, msg):
    msg = msg.split("\n")    
    msg = [i for i in msg if i not in {""}]

    CT_index = msg.index(BEGIN_FCMP_MESSAGE) + 1
    public_index = msg.index(BEGIN_FCMP_PUBLIC_KEY_BLOCK) + 1

    CT = msg[CT_index]
    sender_public = msg[public_index]
    
    CT = b64decode(CT)
    sender_public = b64decode(sender_public)

    sender_public = int.from_bytes(sender_public, "little")

    KEY = HASH_ALG(dh_getkey(receiver_private, sender_public))
    PT = block_decrypt(BLOCK_CIPHER_ALG, HASH_ALG, BLOCK_SIZE, CT, KEY)

    return PT

def fcmp_to_private(private):
    private_key = private.to_bytes(256, byteorder="little")

    res = ""

    res += BEGIN_FCMP_PRIVATE_KEY_BLOCK + "\n\n"
    res += b64encode(private_key).decode() + "\n"
    res += END_FCMP_PRIVATE_KEY_BLOCK + "\n\n"

    return res

def fcmp_from_private(msg):
    msg = msg.split("\n")
    msg = [i for i in msg if i not in {""}]

    private_index = msg.index(BEGIN_FCMP_PRIVATE_KEY_BLOCK) + 1
    private = msg[private_index]
    private = b64decode(private)
    private = int.from_bytes(private, "little")

    return private

def fcmp_to_public(public):
    public_key = public.to_bytes(256, byteorder="little")

    res = ""

    res += BEGIN_FCMP_PUBLIC_KEY_BLOCK + "\n\n"
    res += b64encode(public_key).decode() + "\n"
    res += END_FCMP_PUBLIC_KEY_BLOCK + "\n\n"

    return res

def fcmp_from_public(msg):
    msg = msg.split("\n")
    msg = [i for i in msg if i not in {""}]

    public_index = msg.index(BEGIN_FCMP_PUBLIC_KEY_BLOCK) + 1
    public = msg[public_index]
    public = b64decode(public)
    public = int.from_bytes(public, "little")

    return public

def fcmp_keygen_file(private_filename, public_filename):
    private, public = fcmp_keygen()

    pvt = fcmp_to_private(private)
    pub = fcmp_to_public(public)

    with open(private_filename, "wt") as fp:
        fp.write(pvt)

    with open(public_filename, "wt") as fp:
        fp.write(pub)

    os.chmod(private_filename, 0o600)
    os.chmod(public_filename, 0o600)

    return pvt + pub

def fcmp_getkey(private_filename, public_filename):
    with open(private_filename, "rt") as fp:
        private = fp.read()

    with open(public_filename, "rt") as fp:
        public = fp.read()

    private = fcmp_from_private(private)
    public = fcmp_from_public(public)

    return private, public

def fcmp_encrypt_file(sender_private, sender_public, receiver_public, filename):
    with open(filename, "rb") as fp:
        msg = fp.read()
    res = fcmp_encrypt(sender_private, sender_public, receiver_public, msg)
    return res

def fcmp_decrypt_file(receiver_private, filename):
    with open(filename, "rt") as fp:
        msg = fp.read()
    res = fcmp_decrypt(receiver_private, msg)
    return res
