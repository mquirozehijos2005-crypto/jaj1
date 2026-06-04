"""Cálculo e identificación de hashes."""
from __future__ import annotations

import hashlib
from typing import BinaryIO

from ..utils.validate import HASH_RE

ALGOS = ("md5", "sha1", "sha256", "sha512")


def hash_text(text: str) -> dict[str, str]:
    data = text.encode("utf-8")
    return {a: hashlib.new(a, data).hexdigest() for a in ALGOS}


def hash_file(stream: BinaryIO) -> dict[str, str]:
    hs = {a: hashlib.new(a) for a in ALGOS}
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        for h in hs.values():
            h.update(chunk)
    return {a: h.hexdigest() for a, h in hs.items()}


def identify(value: str) -> list[str]:
    v = value.strip()
    matches: list[str] = []
    for name, regex in HASH_RE.items():
        if regex.match(v):
            matches.append(name)
    return matches


# Sugerencias de hashcat por tipo
HASHCAT_HINTS: dict[str, str] = {
    "md5": "0",
    "sha1": "100",
    "sha224": "1300",
    "sha256": "1400",
    "sha384": "10800",
    "sha512": "1700",
    "ntlm": "1000",
    "bcrypt": "3200",
    "argon2": "(argon2: usar argon2-cracker, no nativo en hashcat)",
}


def hashcat_hint(name: str) -> str:
    code = HASHCAT_HINTS.get(name, "?")
    return f"hashcat -m {code} hash.txt wordlist.txt"
