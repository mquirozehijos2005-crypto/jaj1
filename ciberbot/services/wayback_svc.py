"""Wayback Machine — snapshots históricos."""
from __future__ import annotations

from ..utils.http import make_client


async def snapshots(url: str, limit: int = 10) -> list[dict]:
    api = "https://web.archive.org/cdx/search/cdx"
    async with make_client(timeout=30.0) as cli:
        r = await cli.get(
            api,
            params={
                "url": url,
                "output": "json",
                "limit": str(limit),
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "from": "2000",
            },
        )
        r.raise_for_status()
        rows = r.json()
    if not rows or len(rows) <= 1:
        return []
    headers, *items = rows
    out = []
    for row in items:
        item = dict(zip(headers, row))
        ts = item.get("timestamp")
        original = item.get("original")
        out.append({
            "timestamp": ts,
            "url": original,
            "snapshot": f"https://web.archive.org/web/{ts}/{original}",
        })
    return out
