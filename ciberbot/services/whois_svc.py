"""WHOIS dominio + RDAP IP."""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from ..utils.http import make_client
from ..utils.validate import normalize_domain


def _safe(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


async def domain_whois(domain: str) -> dict:
    """Wrapper python-whois (parsea WHOIS estándar). Sync → thread."""
    import whois  # type: ignore

    domain = normalize_domain(domain)
    data = await asyncio.to_thread(whois.whois, domain)
    if not data or not data.get("domain_name"):
        return {"raw": str(data)}
    return {
        "domain": _safe(data.get("domain_name")),
        "registrar": _safe(data.get("registrar")),
        "creation_date": _safe(data.get("creation_date")),
        "expiration_date": _safe(data.get("expiration_date")),
        "updated_date": _safe(data.get("updated_date")),
        "name_servers": _safe(data.get("name_servers")),
        "status": _safe(data.get("status")),
        "emails": _safe(data.get("emails")),
        "country": _safe(data.get("country")),
        "org": _safe(data.get("org")),
    }


async def ip_rdap(ip: str) -> dict:
    """RDAP de una IP vía rdap.org (sin key)."""
    async with make_client() as cli:
        r = await cli.get(f"https://rdap.org/ip/{ip}")
        r.raise_for_status()
        data = r.json()
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": data.get("country"),
        "start": data.get("startAddress"),
        "end": data.get("endAddress"),
        "type": data.get("type"),
        "events": [
            f"{e.get('eventAction')}: {e.get('eventDate')}"
            for e in data.get("events", [])
        ],
    }
