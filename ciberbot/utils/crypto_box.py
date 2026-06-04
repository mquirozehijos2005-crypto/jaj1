"""Cifrado AES-GCM con clave derivada (scrypt) para notas privadas."""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(passphrase: str, plaintext: str) -> tuple[bytes, bytes, bytes]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return ct, salt, nonce


def decrypt(passphrase: str, ciphertext: bytes, salt: bytes, nonce: bytes) -> str:
    key = _derive(passphrase, salt)
    pt = AESGCM(key).decrypt(nonce, ciphertext, None)
    return pt.decode("utf-8")
