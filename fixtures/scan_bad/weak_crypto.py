"""Deliberately insecure crypto code used to validate detection accuracy."""

import hashlib
import os

from Crypto.Cipher import AES, DES


def hash_password(password: str) -> str:
    """Hash a password the wrong way."""
    salt = os.urandom(16)
    digest = hashlib.md5(salt + password.encode()).hexdigest()
    return digest


def checksum_file(path: str) -> str:
    sha = hashlib.sha1()
    with open(path, "rb") as fh:
        sha.update(fh.read())
    return sha.hexdigest()


def new_weak_hasher():
    return hashlib.new("md5")


def hmac_md5(data: bytes, key: bytes) -> bytes:
    import hmac
    return hmac.new(key, data, "md5").digest()


def hmac_sha1(data: bytes, key: bytes) -> bytes:
    import hmac
    return hmac.HMAC(key, data, "sha1").digest()


def encrypt_des(data: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


def encrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=b"0123456789abcdef")
    return cipher.encrypt(data)


def fixed_seed():
    import random
    random.seed(12345)
    return random.random()
