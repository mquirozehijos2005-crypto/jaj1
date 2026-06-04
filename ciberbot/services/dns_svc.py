"""Resolución DNS estándar y DoH (Cloudflare)."""
from __future__ import annotations

import asyncio
import socket
from typing import Iterable

import dns.asyncresolver
import dns.exception
import httpx

from ..utils.http import make_client
from ..utils.validate import normalize_domain

RECORDS = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")


async def lookup(domain: str, types: Iterable[str] = RECORDS) -> dict[str, list[str]]:
    domain = normalize_domain(domain)
    out: dict[str, list[str]] = {}
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    resolver.timeout = 4.0
    for t in types:
        try:
            ans = await resolver.resolve(domain, t)
            out[t] = sorted({r.to_text() for r in ans})
        except dns.exception.DNSException:
            out[t] = []
    return out


async def reverse(ip: str) -> str | None:
    try:
        host, *_ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return host
    except OSError:
        return None


async def doh_query(name: str, qtype: str = "A") -> list[str]:
    """Resolución DNS-over-HTTPS vía Cloudflare (1.1.1.1)."""
    name = normalize_domain(name)
    url = "https://cloudflare-dns.com/dns-query"
    async with make_client() as cli:
        try:
            r = await cli.get(
                url,
                params={"name": name, "type": qtype},
                headers={"accept": "application/dns-json"},
            )
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError:
            return []
    return [a["data"] for a in data.get("Answer", []) if "data" in a]


async def dnssec_check(domain: str) -> dict:
    """Comprueba si el dominio tiene DNSSEC visible (registros DNSKEY/DS)."""
    domain = normalize_domain(domain)
    out: dict[str, list[str]] = {"DNSKEY": [], "DS": [], "RRSIG_A": []}
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    for t in ("DNSKEY", "DS"):
        try:
            ans = await resolver.resolve(domain, t)
            out[t] = [r.to_text() for r in ans]
        except dns.exception.DNSException:
            pass
    try:
        ans = await resolver.resolve(domain, "A", raise_on_no_answer=False)
        if ans.response.find_rrset(
            ans.response.answer, ans.qname, ans.rdclass, 46  # RRSIG
        ):
            out["RRSIG_A"] = ["present"]
    except (dns.exception.DNSException, KeyError):
        pass
    return {
        "dnssec": bool(out["DNSKEY"] or out["DS"]),
        **out,
    }


def detect_mail_provider(mx_records: list[str]) -> str | None:
    joined = " ".join(r.lower() for r in mx_records)
    if not joined:
        return None
    matches = [
        ("Google Workspace", ("google.com", "googlemail.com", "aspmx")),
        ("Microsoft 365", ("outlook.com", "protection.outlook")),
        ("Zoho", ("zoho.com",)),
        ("ProtonMail", ("protonmail.ch", "proton.me")),
        ("Yandex", ("yandex",)),
        ("Fastmail", ("messagingengine.com",)),
        ("Mailgun", ("mailgun",)),
        ("SendGrid", ("sendgrid",)),
        ("Amazon SES", ("amazonses",)),
        ("Mimecast", ("mimecast",)),
    ]
    for name, needles in matches:
        if any(n in joined for n in needles):
            return name
    return None
