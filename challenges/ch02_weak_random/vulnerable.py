"""Intentionally vulnerable teaching example: never deploy."""
import random
import secrets
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(message: bytes, issued_at: int | None = None) -> dict:
    seed = int(time.time()) if issued_at is None else issued_at
    rng = random.Random(seed)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, message, None)
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
