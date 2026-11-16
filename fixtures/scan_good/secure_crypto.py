"""Secure crypto patterns — must produce zero findings."""

import hashlib
import os
import secrets

from Crypto.Cipher import AES


def hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return dk.hex()


def checksum_file(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def encrypt_gcm(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.encrypt(data)


def random_token() -> str:
    # Random seed is never fixed; os.urandom is the source of entropy.
    return secrets.token_hex(32)
