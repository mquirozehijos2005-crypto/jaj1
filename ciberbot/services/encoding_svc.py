"""Encoders/decoders y ‘magic decoder’ tipo CyberChef."""
from __future__ import annotations

import base64
import binascii
import codecs
import urllib.parse as up
import zlib


def b64e(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def b64d(s: str) -> str:
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", errors="replace")


def b32e(s: str) -> str:
    return base64.b32encode(s.encode("utf-8")).decode("ascii")


def b32d(s: str) -> str:
    return base64.b32decode(s + "=" * (-len(s) % 8)).decode("utf-8", errors="replace")


def hexe(s: str) -> str:
    return s.encode("utf-8").hex()


def hexd(s: str) -> str:
    return bytes.fromhex(s.replace(" ", "")).decode("utf-8", errors="replace")


def urle(s: str) -> str:
    return up.quote(s, safe="")


def urld(s: str) -> str:
    return up.unquote_plus(s)


def rot(n: int, s: str) -> str:
    n = n % 26
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def atbash(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


# ---------------- Magic decoder ----------------

_PRINTABLE_OK = set(range(32, 127)) | {9, 10, 13}


def _is_textlike(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if x in _PRINTABLE_OK)
    return ok / len(b)


def _try_decode(data: bytes, op: str) -> bytes | None:
    try:
        if op == "b64":
            s = data.decode("ascii", errors="strict").strip()
            return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        if op == "b32":
            s = data.decode("ascii", errors="strict").strip().upper()
            return base64.b32decode(s + "=" * (-len(s) % 8))
        if op == "hex":
            s = data.decode("ascii", errors="strict").strip().replace(" ", "")
            return bytes.fromhex(s)
        if op == "url":
            s = data.decode("utf-8", errors="strict")
            return up.unquote_plus(s).encode("utf-8")
        if op == "zlib":
            return zlib.decompress(data)
        if op == "gzip":
            import gzip
            return gzip.decompress(data)
        if op == "rot13":
            return codecs.encode(data.decode("utf-8"), "rot_13").encode("utf-8")
    except (binascii.Error, ValueError, zlib.error, OSError, UnicodeDecodeError):
        return None
    return None


def magic(text: str, max_depth: int = 6) -> list[tuple[list[str], str]]:
    """Intenta decodificar en cadena. Devuelve los caminos que producen texto legible."""
    seed = text.encode("utf-8")
    results: list[tuple[list[str], bytes, float]] = []
    seen: set[bytes] = set()

    def walk(buf: bytes, path: list[str], depth: int) -> None:
        if depth > max_depth or buf in seen:
            return
        seen.add(buf)
        score = _is_textlike(buf)
        if score >= 0.9 and path:
            results.append((path, buf, score))
        for op in ("b64", "b32", "hex", "url", "zlib", "gzip", "rot13"):
            nxt = _try_decode(buf, op)
            if nxt and nxt != buf:
                walk(nxt, path + [op], depth + 1)

    walk(seed, [], 0)
    results.sort(key=lambda x: (-len(x[0]) > 0, -x[2]))
    out: list[tuple[list[str], str]] = []
    for path, buf, _ in results[:5]:
        out.append((path, buf.decode("utf-8", errors="replace")))
    return out
