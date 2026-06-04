"""Misceláneos: identidades falsas, GitHub OSINT, EPSS, etc."""
from __future__ import annotations

from faker import Faker

from ..utils.http import make_client


def fake_identity(locale: str = "es_ES") -> dict:
    fake = Faker(locale)
    return {
        "nombre": fake.name(),
        "email": fake.free_email(),
        "telefono": fake.phone_number(),
        "direccion": fake.address().replace("\n", ", "),
        "fecha_nac": fake.date_of_birth(minimum_age=18, maximum_age=70).isoformat(),
        "usuario": fake.user_name(),
        "password_demo": fake.password(length=14, special_chars=True),
        "tarjeta_demo": fake.credit_card_number(),
        "iban_demo": fake.iban(),
        "user_agent": fake.user_agent(),
    }


async def github_user(username: str) -> dict | None:
    async with make_client() as cli:
        r = await cli.get(f"https://api.github.com/users/{username}")
        if r.status_code != 200:
            return None
        u = r.json()
    return {
        "login": u.get("login"),
        "name": u.get("name"),
        "bio": u.get("bio"),
        "company": u.get("company"),
        "location": u.get("location"),
        "blog": u.get("blog"),
        "twitter": u.get("twitter_username"),
        "public_repos": u.get("public_repos"),
        "followers": u.get("followers"),
        "created": u.get("created_at"),
        "url": u.get("html_url"),
    }


async def epss(cve_id: str) -> dict | None:
    """Probabilidad EPSS de explotación (api.first.org)."""
    async with make_client() as cli:
        r = await cli.get("https://api.first.org/data/v1/epss", params={"cve": cve_id})
        if r.status_code != 200:
            return None
        data = r.json().get("data", [])
    if not data:
        return None
    item = data[0]
    return {"cve": item.get("cve"), "epss": item.get("epss"), "percentile": item.get("percentile")}
