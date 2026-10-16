"""CH03 수정 코드. 개인키는 호출자가 보관한다."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def new_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None,
    )


def encrypt(public_key, message: bytes) -> bytes:
    return public_key.encrypt(message, oaep())


def decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, oaep())
