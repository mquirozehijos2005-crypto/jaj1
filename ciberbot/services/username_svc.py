"""OSINT de username en plataformas públicas (estilo Sherlock light)."""
from __future__ import annotations

import asyncio

import httpx

from ..utils.http import make_client

PLATFORMS = [
    ("GitHub", "https://github.com/{u}", 200),
    ("GitLab", "https://gitlab.com/{u}", 200),
    ("Twitter/X", "https://twitter.com/{u}", 200),
    ("Instagram", "https://www.instagram.com/{u}/", 200),
    ("Reddit", "https://www.reddit.com/user/{u}", 200),
    ("Medium", "https://medium.com/@{u}", 200),
    ("StackOverflow", "https://stackoverflow.com/users/{u}", 200),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", 200),
    ("Pastebin", "https://pastebin.com/u/{u}", 200),
    ("DEV.to", "https://dev.to/{u}", 200),
    ("Telegram", "https://t.me/{u}", 200),
    ("Keybase", "https://keybase.io/{u}", 200),
    ("Twitch", "https://www.twitch.tv/{u}", 200),
    ("Vimeo", "https://vimeo.com/{u}", 200),
    ("SoundCloud", "https://soundcloud.com/{u}", 200),
    ("HackTheBox", "https://app.hackthebox.com/users/{u}", 200),
    ("TryHackMe", "https://tryhackme.com/p/{u}", 200),
    ("DockerHub", "https://hub.docker.com/u/{u}", 200),
]


async def _check(cli: httpx.AsyncClient, name: str, url: str, ok_status: int) -> tuple[str, bool, str]:
    try:
        r = await cli.get(url)
        found = r.status_code == ok_status
        # Reddit/twitter devuelven 200 incluso si no existe; añade heurística por longitud
        if found and r.status_code == 200 and "page not found" in r.text.lower()[:5000]:
            found = False
        return name, found, url
    except httpx.HTTPError:
        return name, False, url


async def search(username: str, concurrency: int = 10) -> list[tuple[str, bool, str]]:
    sem = asyncio.Semaphore(concurrency)
    async with make_client(timeout=10.0) as cli:
        async def runner(p):
            async with sem:
                return await _check(cli, p[0], p[1].format(u=username), p[2])

        results = await asyncio.gather(*(runner(p) for p in PLATFORMS))
    return results
