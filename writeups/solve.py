"""세 문제의 풀이."""
import json
import random
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PUBLIC = Path(__file__).resolve().parents[1] / "challenges"


def solve_ch01(data: dict) -> bytes:
    known = data["known_plaintext"].encode()
    c1 = bytes.fromhex(data["known_ciphertext"])
    c2 = bytes.fromhex(data["flag_ciphertext"])
    if len(known) != len(c1) or len(known) < len(c2):
        raise ValueError("Known plaintext does not cover the target")
    return bytes(a ^ b ^ c for a, b, c in zip(c1, c2, known))


def solve_ch02(data: dict) -> tuple[int, bytes, int] | None:
    center = data["approx_unix_time"]
    window = data["search_window_seconds"]
    nonce = bytes.fromhex(data["nonce"])
    ciphertext = bytes.fromhex(data["ciphertext"])
    for attempt, seed in enumerate(range(center - window, center + window + 1), 1):
        rng = random.Random(seed)
        key = bytes(rng.getrandbits(8) for _ in range(32))
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            continue
        return seed, plaintext, attempt
    return None


def integer_cuberoot(value: int) -> int:
    if value < 0:
        raise ValueError("Expected a non-negative integer")
    lo, hi = 0, 1 << ((value.bit_length() + 2) // 3)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** 3 <= value:
            lo = mid
        else:
            hi = mid
    return lo


def solve_ch03(data: dict) -> bytes:
    ciphertext = int(data["c"])
    if data["e"] != 3 or not 0 <= ciphertext < int(data["n"]):
        raise ValueError("Expected an e=3 textbook RSA challenge")
    root = integer_cuberoot(ciphertext)
    if root ** 3 != ciphertext:
        raise ValueError("Ciphertext is not an exact cube")
    return root.to_bytes(max(1, (root.bit_length() + 7) // 8), "big")


def main():
    data1 = json.loads((PUBLIC / "ch01_fixed_iv/challenge.json").read_text(encoding="utf-8"))
    data2 = json.loads((PUBLIC / "ch02_weak_random/challenge.json").read_text(encoding="utf-8"))
    data3 = json.loads((PUBLIC / "ch03_raw_rsa/challenge.json").read_text(encoding="utf-8"))
    print("CH01:", solve_ch01(data1).decode())
    answer = solve_ch02(data2)
    if answer is None:
        raise SystemExit("CH02: no matching seed")
    seed, flag, attempts = answer
    print(f"CH02: {flag.decode()} (seed={seed}, attempts={attempts}/121)")
    print("CH03:", solve_ch03(data3).decode())


if __name__ == "__main__":
    main()
