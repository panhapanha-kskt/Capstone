#!/usr/bin/env python3
"""Create local SOC usernames and password hashes without storing plaintext in Git."""

import hashlib
import json
import os
import secrets
import string
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
HASHES = DATA / "gateway-password-credentials.json"
INITIAL = DATA / "gateway-initial-passwords.json"
ACCESS = DATA / "gateway-access-tokens.json"
SYMBOLS = "!@#$%^&*_-+="
ALPHABET = string.ascii_letters + string.digits + SYMBOLS
ITERATIONS = 600_000


def private_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def password():
    chars = [secrets.choice(string.ascii_letters), secrets.choice(string.digits), secrets.choice(SYMBOLS)]
    chars.extend(secrets.choice(ALPHABET) for _ in range(21))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA, 0o700)
    if HASHES.exists() or INITIAL.exists() or ACCESS.exists():
        raise SystemExit("Gateway credentials already exist; refusing to overwrite them")
    analysts = DATA / "analysts.json"
    if analysts.exists():
        ids = [row["id"] for row in json.loads(analysts.read_text(encoding="utf-8"))["records"]]
    else:
        ids = ["analyst-1", "analyst-2", "senior-1", "ir-lead"]
    records = []
    initial = {}
    access_tokens = {}
    for username in ids:
        secret = password()
        access_token = secrets.token_hex(32)
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, ITERATIONS, dklen=32)
        records.append({"username": username, "analyst": username, "salt_hex": salt.hex(),
                        "hash_hex": digest.hex(), "token_sha256": hashlib.sha256(access_token.encode()).hexdigest(),
                        "iterations": ITERATIONS})
        initial[username] = secret
        access_tokens[username] = access_token
    private_write(HASHES, json.dumps(records, indent=2) + "\n")
    private_write(INITIAL, json.dumps(initial, indent=2) + "\n")
    private_write(ACCESS, json.dumps(access_tokens, indent=2) + "\n")
    print(f"Created {len(ids)} accounts. Read passwords from {INITIAL} and tokens from {ACCESS} (mode 600).")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError) as exc:
        sys.exit(str(exc))
