"""Offline flag checker. Answers are stored only as SHA-256 hashes."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge", choices=["ch01", "ch02", "ch03"])
    args = parser.parse_args()
    hashes = json.loads(Path(__file__).with_name("flag_hashes.json").read_text(encoding="utf-8"))
    answer = input("flag> ").strip().encode()
    ok = hmac.compare_digest(hashlib.sha256(answer).hexdigest(), hashes[args.challenge])
    print("Correct!" if ok else "Try again.")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
