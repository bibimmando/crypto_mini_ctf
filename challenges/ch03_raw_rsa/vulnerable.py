"""Intentionally vulnerable textbook RSA: never deploy."""


def encrypt(public_key, message: bytes) -> int:
    numbers = public_key.public_numbers()
    m = int.from_bytes(message, "big")
    if m >= numbers.n:
        raise ValueError("Message too large")
    return pow(m, numbers.e, numbers.n)
