"""Extracción de IOCs y defang/refang."""
from __future__ import annotations

import re

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+", re.I)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}\b",
    re.I,
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
HASH_RE = re.compile(r"\b[a-f0-9]{32,128}\b", re.I)
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def extract(text: str) -> dict[str, list[str]]:
    refanged = refang(text)
    out = {
        "ipv4": sorted(set(IPV4_RE.findall(refanged))),
        "ipv6": sorted(set(IPV6_RE.findall(refanged))),
        "urls": sorted(set(URL_RE.findall(refanged))),
        "domains": [],
        "emails": sorted(set(EMAIL_RE.findall(refanged))),
        "hashes": sorted(set(HASH_RE.findall(refanged))),
        "btc": sorted(set(BTC_RE.findall(refanged))),
        "cves": sorted({c.upper() for c in CVE_RE.findall(refanged)}),
    }
    # dominios excluyendo los que son parte de URLs/emails ya extraídos
    domains = set(DOMAIN_RE.findall(refanged))
    inside = " ".join(out["urls"] + out["emails"])
    out["domains"] = sorted(d for d in domains if d not in inside and "." in d)
    return out


def defang(text: str) -> str:
    text = re.sub(r"\.", "[.]", text)
    text = re.sub(r"https?://", lambda m: m.group(0).replace(":", "[:]"), text)
    return text.replace("@", "[@]")


def refang(text: str) -> str:
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("[@]", "@")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )
