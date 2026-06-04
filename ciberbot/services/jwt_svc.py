"""Decodificación JWT y check de algoritmos débiles."""
from __future__ import annotations

import base64
import json

import jwt as pyjwt

WEAK_ALGS = {"none", "HS256"}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Token JWT inválido")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    alg = (header.get("alg") or "").upper()
    warnings: list[str] = []
    if alg.lower() == "none":
        warnings.append("alg=none: vulnerable a JWT alg-confusion (CVE-2015-9235)")
    if alg == "HS256":
        warnings.append("HS256: si la clave es débil puedes intentar bruteforce con jwt_tool")
    if "kid" in header:
        warnings.append("`kid` presente: revisa SQLi/Path Traversal en kid (PortSwigger)")
    return {"header": header, "payload": payload, "warnings": warnings}


def try_verify(token: str, secret: str) -> bool:
    try:
        pyjwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
        return True
    except pyjwt.PyJWTError:
        return False
