"""CVE lookup vía cve.circl.lu (público, sin key) y fallback NVD JSON."""
from __future__ import annotations

import re

from ..utils.http import make_client

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


async def by_id(cve_id: str) -> dict | None:
    cve_id = cve_id.strip().upper()
    if not CVE_RE.match(cve_id):
        return None
    async with make_client() as cli:
        r = await cli.get(f"https://cve.circl.lu/api/cve/{cve_id}")
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except ValueError:
            return None
    if not data:
        return None
    return {
        "id": data.get("id") or cve_id,
        "summary": data.get("summary"),
        "cvss": data.get("cvss"),
        "published": data.get("Published"),
        "modified": data.get("Modified"),
        "references": (data.get("references") or [])[:8],
        "vendors": list((data.get("vulnerable_product") or [])[:10]),
    }


async def search(keyword: str, limit: int = 5) -> list[dict]:
    async with make_client(timeout=20.0) as cli:
        r = await cli.get(f"https://cve.circl.lu/api/search/{keyword}")
        if r.status_code != 200:
            return []
        try:
            data = r.json()
        except ValueError:
            return []
    items = data.get("data") if isinstance(data, dict) else data
    if not items:
        return []
    out = []
    for it in items[:limit]:
        out.append({
            "id": it.get("id"),
            "summary": (it.get("summary") or "")[:280],
            "cvss": it.get("cvss"),
        })
    return out
