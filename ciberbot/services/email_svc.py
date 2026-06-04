"""Email validation, MX, SPF/DKIM/DMARC y header analyzer."""
from __future__ import annotations

import re
from email import message_from_string
from email.utils import parseaddr

import dns.asyncresolver
import dns.exception
from email_validator import EmailNotValidError, validate_email

from ..utils.validate import normalize_domain


async def validate(addr: str) -> dict:
    try:
        info = validate_email(addr, check_deliverability=False)
    except EmailNotValidError as exc:
        return {"valid": False, "error": str(exc)}
    return {
        "valid": True,
        "normalized": info.normalized,
        "local": info.local_part,
        "domain": info.domain,
        "ascii_email": info.ascii_email,
    }


async def mx_records(domain: str) -> list[str]:
    domain = normalize_domain(domain)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    try:
        ans = await resolver.resolve(domain, "MX")
    except dns.exception.DNSException:
        return []
    return sorted(f"{r.preference} {r.exchange.to_text()}" for r in ans)


async def spf_dkim_dmarc(domain: str) -> dict:
    domain = normalize_domain(domain)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0

    async def txt(name: str) -> list[str]:
        try:
            ans = await resolver.resolve(name, "TXT")
            return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
        except dns.exception.DNSException:
            return []

    spf = [r for r in await txt(domain) if r.lower().startswith("v=spf1")]
    dmarc = await txt(f"_dmarc.{domain}")
    dkim_default = await txt(f"default._domainkey.{domain}")
    return {
        "spf": spf,
        "dmarc": dmarc,
        "dkim_default": dkim_default,
    }


_RECEIVED_RE = re.compile(r"from\s+([^\s]+)\s.*?\(([^)]+)\)", re.I | re.S)


def analyze_headers(raw: str) -> dict:
    msg = message_from_string(raw)
    received = msg.get_all("Received") or []
    hops = []
    for r in reversed(received):
        m = _RECEIVED_RE.search(r)
        if m:
            hops.append({"from": m.group(1), "details": m.group(2)})
        else:
            hops.append({"raw": r[:200]})
    return {
        "from": parseaddr(msg.get("From", ""))[1],
        "to": parseaddr(msg.get("To", ""))[1],
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
        "spf": msg.get("Received-SPF"),
        "auth_results": msg.get("Authentication-Results"),
        "hops": hops[:10],
        "x_mailer": msg.get("X-Mailer"),
        "return_path": msg.get("Return-Path"),
    }
