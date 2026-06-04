"""Passwords: fuerza, generador y HIBP por k-anonimato."""
from __future__ import annotations

import hashlib
import secrets
import string

from zxcvbn import zxcvbn

from ..utils.http import make_client

ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{},.;:?"


def generate(length: int = 20, with_symbols: bool = True) -> str:
    chars = string.ascii_letters + string.digits + ("!@#$%^&*()-_=+" if with_symbols else "")
    return "".join(secrets.choice(chars) for _ in range(max(8, length)))


def passphrase(words: int = 5) -> str:
    """Diceware-light usando una lista mínima embebida."""
    base = (
        "atom bear cake duck echo frog gold hawk iron jade kiwi lion mint nova "
        "oak pine quartz ruby silk teak ultra vine wolf xray yak zebra moss "
        "amber raven cosmic tiger lemon comet harbor maple nimbus orchid silver"
    ).split()
    return "-".join(secrets.choice(base) for _ in range(max(3, words)))


def strength(pw: str) -> dict:
    res = zxcvbn(pw)
    return {
        "score": res["score"],  # 0..4
        "guesses_log10": res["guesses_log10"],
        "crack_times": res["crack_times_display"],
        "warning": res["feedback"]["warning"],
        "suggestions": res["feedback"]["suggestions"],
    }


async def pwned(pw: str) -> int:
    """Consulta HIBP por k-anonimato. Devuelve nº de apariciones."""
    digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    async with make_client() as cli:
        r = await cli.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
        r.raise_for_status()
    for line in r.text.splitlines():
        h, _, c = line.partition(":")
        if h.strip() == suffix:
            return int(c.strip())
    return 0
