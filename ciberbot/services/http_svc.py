"""Análisis HTTP: headers de seguridad, redirecciones, fingerprinting básico."""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from ..utils.http import make_client
from ..utils.validate import ensure_url

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "X-XSS-Protection",
]

# Reglas mínimas de fingerprinting (sin Wappalyzer)
TECH_RULES = [
    ("WordPress", [r"wp-content", r"wp-includes", r"x-pingback"]),
    ("Drupal", [r"X-Generator:\s*Drupal", r"Drupal\.settings"]),
    ("Joomla", [r"<meta name=\"generator\" content=\"Joomla"]),
    ("Cloudflare", [r"server:\s*cloudflare", r"cf-ray:"]),
    ("nginx", [r"server:\s*nginx"]),
    ("Apache", [r"server:\s*apache"]),
    ("IIS", [r"server:\s*microsoft-iis"]),
    ("Express", [r"x-powered-by:\s*express"]),
    ("PHP", [r"x-powered-by:\s*PHP"]),
    ("ASP.NET", [r"x-powered-by:\s*ASP\.NET"]),
    ("Next.js", [r"x-powered-by:\s*Next\.js"]),
    ("Django", [r"csrftoken=", r"X-Frame-Options:\s*DENY.*csrftoken"]),
    ("React", [r"<div id=\"__next\">", r"data-reactroot"]),
    ("Vue", [r"<div id=\"app\"", r"data-v-"]),
    ("jQuery", [r"jquery(\.min)?\.js"]),
    ("Bootstrap", [r"bootstrap(\.min)?\.css"]),
]


async def fetch_headers(url: str) -> dict:
    url = ensure_url(url)
    async with make_client(follow_redirects=False) as cli:
        r = await cli.get(url)
    headers = dict(r.headers)
    sec = {h: headers.get(h) or headers.get(h.lower()) for h in SECURITY_HEADERS}
    missing = [k for k, v in sec.items() if not v]
    return {
        "url": url,
        "status": r.status_code,
        "server": headers.get("server"),
        "content_type": headers.get("content-type"),
        "security": sec,
        "missing": missing,
        "all_headers": headers,
    }


async def redirect_chain(url: str, max_hops: int = 10) -> list[dict]:
    url = ensure_url(url)
    chain: list[dict] = []
    async with make_client(follow_redirects=False) as cli:
        current = url
        for _ in range(max_hops):
            try:
                r = await cli.get(current)
            except httpx.HTTPError as exc:
                chain.append({"url": current, "error": str(exc)})
                break
            chain.append({
                "url": current,
                "status": r.status_code,
                "location": r.headers.get("location"),
            })
            if r.is_redirect and r.headers.get("location"):
                current = httpx.URL(current).join(r.headers["location"]).human_repr()
                continue
            break
    return chain


async def fingerprint(url: str) -> dict:
    url = ensure_url(url)
    async with make_client() as cli:
        r = await cli.get(url)
    body = r.text[:200_000]
    blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n" + body
    detected: list[str] = []
    for tech, patterns in TECH_RULES:
        if any(re.search(p, blob, re.I) for p in patterns):
            detected.append(tech)
    title_match = re.search(r"<title>([^<]{1,200})</title>", body, re.I | re.S)
    return {
        "url": str(r.url),
        "status": r.status_code,
        "server": r.headers.get("server"),
        "title": title_match.group(1).strip() if title_match else None,
        "tech": detected,
    }


async def fetch_text(url: str, max_bytes: int = 200_000) -> tuple[int, str]:
    async with make_client() as cli:
        r = await cli.get(url)
    return r.status_code, r.text[:max_bytes]


async def robots_and_friends(domain: str) -> dict:
    """Descarga robots.txt, sitemap.xml, .well-known/security.txt"""
    base = f"https://{urlparse(ensure_url(domain)).hostname or domain}"
    targets = {
        "robots.txt": f"{base}/robots.txt",
        "sitemap.xml": f"{base}/sitemap.xml",
        "security.txt": f"{base}/.well-known/security.txt",
    }
    out: dict[str, dict] = {}
    async with make_client() as cli:
        for label, u in targets.items():
            try:
                r = await cli.get(u)
                out[label] = {
                    "status": r.status_code,
                    "preview": r.text[:1500] if r.status_code == 200 else None,
                }
            except httpx.HTTPError as exc:
                out[label] = {"error": str(exc)}
    return out
