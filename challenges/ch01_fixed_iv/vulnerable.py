"""Intentionally vulnerable teaching example: never deploy."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FIXED_IV = bytes(16)


def encrypt(key: bytes, message: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(FIXED_IV)).encryptor()
    return encryptor.update(message) + encryptor.finalize()
