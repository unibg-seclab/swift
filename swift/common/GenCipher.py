from Crypto.Cipher import AES
from swift.common.generator import generator_of


class GenAES():
    """Do the same as AES but do it in a generator-like way."""

    @staticmethod
    def new(*args, **kwargs):
        cipher = AES.new(*args, **kwargs)
        # determine the size of the chunks and remove the keyword if present
        cipher._chunk_size = kwargs.pop('chunk_size', 65536)
        # the cipher that is used to encrypt
        cipher.encrypt = generator_of(cipher._chunk_size)(cipher.encrypt)
        # the decorated encrypt function
        cipher.decrypt = generator_of(cipher._chunk_size)(cipher.decrypt)
        return cipher
