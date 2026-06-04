"""Información de IPs: GeoIP, ASN, Tor exit, BGP, scan suave."""
from __future__ import annotations

import asyncio
import socket
from contextlib import suppress

import httpx

from ..utils.http import make_client

TOR_EXIT_LIST = "https://check.torproject.org/torbulkexitlist"


async def geoip(ip: str) -> dict:
    async with make_client() as cli:
        r = await cli.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query,proxy,hosting,mobile"},
        )
        r.raise_for_status()
        return r.json()


async def reverse_dns(ip: str) -> str | None:
    try:
        host, *_ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return host
    except OSError:
        return None


async def is_tor_exit(ip: str) -> bool:
    async with make_client() as cli:
        try:
            r = await cli.get(TOR_EXIT_LIST)
            r.raise_for_status()
        except httpx.HTTPError:
            return False
    return ip.strip() in {line.strip() for line in r.text.splitlines() if line.strip()}


async def bgp_info(ip_or_asn: str) -> dict:
    """bgpview.io endpoint público."""
    target = ip_or_asn.strip()
    base = "https://api.bgpview.io"
    if target.upper().startswith("AS"):
        url = f"{base}/asn/{target[2:]}"
    elif target.isdigit():
        url = f"{base}/asn/{target}"
    else:
        url = f"{base}/ip/{target}"
    async with make_client() as cli:
        r = await cli.get(url)
        r.raise_for_status()
        return r.json().get("data", {})


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 1723, 2049, 2375, 2376, 3306, 3389,
    5432, 5900, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9200, 9300, 11211, 27017, 50070,
]


async def _check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan_ports(host: str, ports: list[int] | None = None, concurrency: int = 50) -> list[int]:
    targets = ports or COMMON_PORTS
    sem = asyncio.Semaphore(concurrency)

    async def worker(p: int) -> int | None:
        async with sem:
            return p if await _check_port(host, p) else None

    results = await asyncio.gather(*(worker(p) for p in targets))
    return sorted(p for p in results if p is not None)


async def banner(host: str, port: int, timeout: float = 3.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
        return data.decode("latin-1", errors="replace").strip() or None
    except (OSError, asyncio.TimeoutError):
        return None
