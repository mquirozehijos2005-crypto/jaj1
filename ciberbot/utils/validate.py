"""Validadores y normalizadores."""
from __future__ import annotations

import ipaddress
import re

import idna

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
HASH_RE = {
    "md5": re.compile(r"^[a-f0-9]{32}$", re.I),
    "sha1": re.compile(r"^[a-f0-9]{40}$", re.I),
    "sha224": re.compile(r"^[a-f0-9]{56}$", re.I),
    "sha256": re.compile(r"^[a-f0-9]{64}$", re.I),
    "sha384": re.compile(r"^[a-f0-9]{96}$", re.I),
    "sha512": re.compile(r"^[a-f0-9]{128}$", re.I),
    "crc32": re.compile(r"^[a-f0-9]{8}$", re.I),
    "ntlm": re.compile(r"^[a-f0-9]{32}$", re.I),
    "bcrypt": re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
    "argon2": re.compile(r"^\$argon2(id|i|d)\$"),
}


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_domain(s: str) -> bool:
    s = s.strip().rstrip(".")
    if not s or "/" in s or " " in s:
        return False
    try:
        ascii_ = idna.encode(s).decode("ascii")
    except idna.IDNAError:
        ascii_ = s
    return bool(DOMAIN_RE.match(ascii_))


def is_url(s: str) -> bool:
    return bool(URL_RE.match(s.strip()))


def normalize_domain(s: str) -> str:
    s = s.strip().lower().rstrip(".")
    try:
        return idna.encode(s).decode("ascii")
    except idna.IDNAError:
        return s


def ensure_url(s: str) -> str:
    s = s.strip()
    if is_url(s):
        return s
    return "https://" + s
