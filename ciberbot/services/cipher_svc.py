"""Solver básico de cifrados clásicos para CTF."""
from __future__ import annotations

import string
from collections import Counter
from itertools import cycle

# Frecuencia de letras inglesa (aprox.)
ENG_FREQ = {
    "a": 0.0817, "b": 0.0149, "c": 0.0278, "d": 0.0425, "e": 0.1270,
    "f": 0.0223, "g": 0.0202, "h": 0.0609, "i": 0.0697, "j": 0.0015,
    "k": 0.0077, "l": 0.0403, "m": 0.0241, "n": 0.0675, "o": 0.0751,
    "p": 0.0193, "q": 0.0010, "r": 0.0599, "s": 0.0633, "t": 0.0906,
    "u": 0.0276, "v": 0.0098, "w": 0.0236, "x": 0.0015, "y": 0.0197,
    "z": 0.0007,
}


def _score_english(text: str) -> float:
    text = text.lower()
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    counts = Counter(letters)
    total = len(letters)
    score = 0.0
    for ch in string.ascii_lowercase:
        observed = counts.get(ch, 0) / total
        score += min(observed, ENG_FREQ[ch])
    common_words = (" the ", " and ", " of ", " to ", " is ", " in ", " for ")
    bonus = sum(0.02 for w in common_words if w in (" " + text.lower() + " "))
    return score + bonus


def caesar_brute(text: str, top: int = 5) -> list[tuple[int, str, float]]:
    out: list[tuple[int, str, float]] = []
    for shift in range(26):
        decoded = "".join(
            chr((ord(c) - base + shift) % 26 + base)
            if (base := 97 if c.islower() else 65) and c.isalpha()
            else c
            for c in text
        )
        out.append((shift, decoded, _score_english(decoded)))
    out.sort(key=lambda x: -x[2])
    return out[:top]


def vigenere_decrypt(text: str, key: str) -> str:
    key = "".join(c for c in key.lower() if c.isalpha())
    if not key:
        return text
    out: list[str] = []
    k = cycle(key)
    for c in text:
        if c.isalpha():
            base = 97 if c.islower() else 65
            shift = ord(next(k)) - 97
            out.append(chr((ord(c) - base - shift) % 26 + base))
        else:
            out.append(c)
    return "".join(out)


def vigenere_dictionary_attack(
    text: str, words: list[str], top: int = 5
) -> list[tuple[str, str, float]]:
    results = []
    for w in words:
        decoded = vigenere_decrypt(text, w)
        results.append((w, decoded, _score_english(decoded)))
    results.sort(key=lambda x: -x[2])
    return results[:top]


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_single_byte_brute(data: bytes, top: int = 5) -> list[tuple[int, str, float]]:
    out: list[tuple[int, str, float]] = []
    for k in range(256):
        dec = xor_decrypt(data, bytes([k]))
        try:
            text = dec.decode("utf-8")
        except UnicodeDecodeError:
            text = dec.decode("latin-1", errors="replace")
        out.append((k, text, _score_english(text)))
    out.sort(key=lambda x: -x[2])
    return out[:top]


_DEFAULT_WORDS = (
    "secret", "password", "key", "ctf", "flag", "hello", "test",
    "admin", "love", "letmein", "qwerty", "dragon", "monkey",
    "sunshine", "iloveyou", "shadow", "ninja", "matrix", "starwars",
)


def default_dictionary() -> list[str]:
    return list(_DEFAULT_WORDS)
