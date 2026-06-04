"""Subdominios vía CT logs (crt.sh)."""
from __future__ import annotations

from ..utils.http import make_client
from ..utils.validate import normalize_domain


async def from_crtsh(domain: str, limit: int = 200) -> list[str]:
    domain = normalize_domain(domain)
    url = "https://crt.sh/"
    async with make_client(timeout=30.0) as cli:
        r = await cli.get(url, params={"q": f"%.{domain}", "output": "json"})
        if r.status_code != 200 or not r.text.strip():
            return []
        try:
            rows = r.json()
        except ValueError:
            return []
    seen: set[str] = set()
    for row in rows:
        names = (row.get("name_value") or "").splitlines()
        for n in names:
            n = n.strip().lower()
            if n.endswith(domain) and "*" not in n:
                seen.add(n)
        if len(seen) >= limit:
            break
    return sorted(seen)


async def cached_from_crtsh(storage, domain: str, limit: int = 200, ttl: int = 3600) -> list[str]:
    """Versión cacheada en SQLite (TTL 1h por defecto)."""
    import json
    key = f"crtsh:{domain}:{limit}"
    cached = storage.cache_get(key)
    if cached:
        try:
            return json.loads(cached)
        except ValueError:
            pass
    out = await from_crtsh(domain, limit)
    storage.cache_set(key, json.dumps(out), ttl)
    return out
