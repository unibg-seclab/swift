#!/usr/bin/env python

import base64
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Cipher import AES

KEY_SIZE = 16
BLOCK_SIZE = 16


def generate_random_key(key_size=KEY_SIZE):
    """
    Generate a random AES key (the BEL key)
    """
    return Random.get_random_bytes(key_size)

def encrypt_object(plaintext, key, encode=False, block_size=BLOCK_SIZE):
    """
    Encrypt a message using AES CTR
    """
    cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(block_size * 8))
    ciphertext = cipher.encrypt(plaintext)
    # Encoding base32 to avoid paths (names containing slashes /)
    return base64.b32encode(ciphertext) if not encode else ciphertext
