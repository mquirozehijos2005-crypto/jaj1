"""Información TLS de un dominio: cert, SAN, expiración, protocolos."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from ..utils.validate import normalize_domain

_PROTOCOLS = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
]


def _peer_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
    return {"cert": cert, "cipher": cipher, "version": version}


def _try_proto(host: str, port: int, version: ssl.TLSVersion, timeout: float = 5.0) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


async def cert_info(host: str, port: int = 443) -> dict:
    host = normalize_domain(host)
    info = await asyncio.to_thread(_peer_cert, host, port)
    cert = info["cert"]
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    parse = lambda s: datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if s else None
    nb_dt = parse(nb)
    na_dt = parse(na)
    days_left = (na_dt - datetime.now(timezone.utc)).days if na_dt else None
    san = [
        v for k, v in cert.get("subjectAltName", []) if k.lower() == "dns"
    ]
    return {
        "host": host,
        "port": port,
        "tls_version": info["version"],
        "cipher": info["cipher"][0] if info["cipher"] else None,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "not_before": nb_dt.isoformat() if nb_dt else None,
        "not_after": na_dt.isoformat() if na_dt else None,
        "days_left": days_left,
        "san": san,
        "serial": cert.get("serialNumber"),
    }


async def supported_protocols(host: str, port: int = 443) -> dict[str, bool]:
    host = normalize_domain(host)
    out: dict[str, bool] = {}
    for label, ver in _PROTOCOLS:
        ok = await asyncio.to_thread(_try_proto, host, port, ver)
        out[label] = ok
    return out
