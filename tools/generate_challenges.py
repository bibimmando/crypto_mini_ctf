"""문제 암호문과 정답 해시를 다시 만든다."""
import hashlib
import importlib.util
import json
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
FLAGS = {
    "ch01": b"flag{never_reuse_ctr_iv}",
    "ch02": b"flag{use_secrets_not_random}",
    "ch03": b"flag{rsa_needs_oaep_padding}",
}

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "challenges"


def load_example(folder):
    path = PUBLIC / folder / "vulnerable.py"
    spec = importlib.util.spec_from_file_location(folder, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    ch1 = load_example("ch01_fixed_iv")
    key = secrets.token_bytes(32)
    known = b"club-demo-known-message:" + b"A" * 41
    write_json(PUBLIC / "ch01_fixed_iv" / "challenge.json", {
        "mode": "AES-256-CTR", "iv": ch1.FIXED_IV.hex(),
        "known_plaintext": known.decode(),
        "known_ciphertext": ch1.encrypt(key, known).hex(),
        "flag_ciphertext": ch1.encrypt(key, FLAGS["ch01"]).hex(),
    })
    ch2 = load_example("ch02_weak_random")
    # A fixed fictional event time keeps this exercise reproducible.
    kst = timezone(timedelta(hours=9))
    center = int(datetime(2026, 10, 16, 12, 0, tzinfo=kst).timestamp())
    packet = ch2.encrypt(FLAGS["ch02"], issued_at=center + 37)
    write_json(PUBLIC / "ch02_weak_random" / "challenge.json", {
        "mode": "AES-256-GCM", "approx_unix_time": center,
        "search_window_seconds": 60, **packet,
    })
    ch3 = load_example("ch03_raw_rsa")
    # The weak exponent and missing padding deliberately expose this short flag.
    private_key = rsa.generate_private_key(public_exponent=3, key_size=2048)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    m = int.from_bytes(FLAGS["ch03"], "big")
    if m ** 3 >= numbers.n:
        raise ValueError("CH03 requires a short message with m**3 < n")
    write_json(PUBLIC / "ch03_raw_rsa" / "challenge.json", {
        "mode": "textbook RSA without padding",
        "n": str(numbers.n), "e": numbers.e,
        "c": str(ch3.encrypt(public_key, FLAGS["ch03"])),
        "encoding": "big-endian bytes",
    })
    write_json(PUBLIC / "flag_hashes.json", {
        name: hashlib.sha256(flag).hexdigest() for name, flag in FLAGS.items()
    })
    print("Generated CH01, CH02, CH03 and SHA-256 flag checks (no secret keys exported).")


if __name__ == "__main__":
    main()
