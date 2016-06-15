#!/usr/bin/env python

import ast
import base64
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Cipher import AES
from swift.common.GenCipher import GenAES

KEY_SIZE = 16
BLOCK_SIZE = 16


def generate_random_key(key_size=KEY_SIZE):
    """
    Generate a random AES key (the BEL key)
    """
    #return Random.get_random_bytes(key_size)
    random_bytes = Random.get_random_bytes(key_size)
    return random_bytes


def encrypt_object(plaintext, key, encode=False, block_size=BLOCK_SIZE, **kwargs):
    """
    Encrypt a message using AES CTR
    """
    cipher = GenAES.new(key, AES.MODE_CTR, counter=Counter.new(block_size * 8), **kwargs)
    ciphertext = cipher.encrypt(plaintext)
    # Encoding base32 to avoid paths (names containing slashes /)
    #return base64.b32encode(ciphertext) if not encode else ciphertext
    return ciphertext


def decrypt_object(ciphertext, key, file_name=False, block_size=BLOCK_SIZE, **kwargs):
    """
    Decrypt a message using AES CTR
    """
    if file_name:
        ciphertext = base64.b32decode(ciphertext)
    cipher = GenAES.new(key, AES.MODE_CTR, counter=Counter.new(block_size * 8), **kwargs)
    #cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(block_size * 8))
    decoded = cipher.decrypt(ciphertext)
    return decoded


def revoking_users(actual_header, new_header):
    actual_acl = extractACL(actual_header, ('read_acl', 'write_acl'))
    new_acl = extractACL(new_header, ('X-Container-Read', 'X-Container-Write'))
    if new_acl:
        removed_users = filter(lambda x: x not in new_acl, actual_acl)
    else:
        removed_users = []
    return len(removed_users) > 0


def extractACL(headers, acl_tags):
    """
    """
    # Get ACLs from the headers
    try:
        acl = ast.literal_eval(headers.get(acl_tags[0], '{}'))
        acl = reduce(lambda x, y: x + y, acl.values(), [])
    except:
        acl = None
    if acl is not None:
        acl = map(lambda x: x.replace('AUTH_', ''), acl)
    return acl
