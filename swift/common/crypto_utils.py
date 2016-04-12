#!/usr/bin/env python

import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random


BLOCK_SIZE = 16


class CryptoService:

    def generate_token(self):
        """
        Generate a random AES key (the BEL key)
        """
        random_bytes = Random.get_random_bytes(BLOCK_SIZE)
        secret = base64.b64encode(random_bytes)
        return secret

    def encrypt_object(self, plaintext, key, file_name=False):
        """
        Encrypt a message using AES CTR
        """
        cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(BLOCK_SIZE * 8))
        encoded = cipher.encrypt(plaintext)
        # Encoding base32 to avoid paths (names containing slashes /)
        if file_name:
            encoded = base64.b32encode(encoded)
        return encoded
