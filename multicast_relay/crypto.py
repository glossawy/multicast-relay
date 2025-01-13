import binascii
import hashlib

import Crypto.Cipher.AES
import Crypto.Random
import Crypto.Util.Counter


class Cipher:
    def __init__(self, key: str):
        self.key = None
        if not key:
            return

        self.blockSize = Crypto.Cipher.AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    @staticmethod
    def strToInt(s: bytes) -> int:
        return int(binascii.hexlify(s), 16)

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.key:
            return plaintext

        iv = Crypto.Random.new().read(self.blockSize)
        ctr = Crypto.Util.Counter.new(128, initial_value=self.strToInt(iv))
        aes = Crypto.Cipher.AES.new(
            self.key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        return iv + aes.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.key:
            return ciphertext

        iv = ciphertext[: self.blockSize]
        ctr = Crypto.Util.Counter.new(128, initial_value=self.strToInt(iv))
        aes = Crypto.Cipher.AES.new(
            self.key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        return aes.decrypt(ciphertext[self.blockSize:])
