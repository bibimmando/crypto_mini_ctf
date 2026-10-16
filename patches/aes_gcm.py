"""CH01과 CH02 수정 코드. 키는 호출자가 보관한다."""
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def new_key() -> bytes:
    return secrets.token_bytes(32)


def encrypt(key: bytes, message: bytes) -> dict:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, message, None)
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


def decrypt(key: bytes, packet: dict) -> bytes:
    nonce = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise ValueError("Invalid encrypted packet")
    return AESGCM(key).decrypt(nonce, ciphertext, None)
