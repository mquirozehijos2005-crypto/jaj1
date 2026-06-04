"""Cliente HTTP compartido con timeouts y user-agent neutro."""
from __future__ import annotations

import httpx

USER_AGENT = "CiberBot/1.0 (+https://github.com/) defensive-osint"

_DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)


def make_client(follow_redirects: bool = True, timeout: float | None = None) -> httpx.AsyncClient:
    t = httpx.Timeout(timeout, connect=10.0) if timeout else _DEFAULT_TIMEOUT
    return httpx.AsyncClient(
        timeout=t,
        follow_redirects=follow_redirects,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
