"""Teclados inline para el menú interactivo."""
from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from ..i18n import t


def main_menu(lang: str = "es") -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(t("cat_domain", lang), callback_data="m:domain"),
         InlineKeyboardButton(t("cat_ip", lang), callback_data="m:ip")],
        [InlineKeyboardButton(t("cat_hash", lang), callback_data="m:hash"),
         InlineKeyboardButton(t("cat_jwt", lang), callback_data="m:jwt")],
        [InlineKeyboardButton(t("cat_pw", lang), callback_data="m:pw"),
         InlineKeyboardButton(t("cat_ioc", lang), callback_data="m:ioc")],
        [InlineKeyboardButton(t("cat_user", lang), callback_data="m:user"),
         InlineKeyboardButton(t("cat_file", lang), callback_data="m:file")],
        [InlineKeyboardButton(t("cat_crypto", lang), callback_data="m:crypto"),
         InlineKeyboardButton(t("cat_watch", lang), callback_data="m:watch")],
        [InlineKeyboardButton(t("cat_misc", lang), callback_data="m:misc")],
    ]
    return InlineKeyboardMarkup(rows)


def back_button(lang: str = "es") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(t("back", lang), callback_data="m:home")]]
    )


SUBMENUS: dict[str, list[tuple[str, str]]] = {
    "domain": [
        ("/dns ejemplo.com", "DNS records"),
        ("/whois ejemplo.com", "WHOIS"),
        ("/ssl ejemplo.com", "Certificado TLS"),
        ("/tlsscan ejemplo.com", "Protocolos TLS soportados"),
        ("/headers https://ejemplo.com", "Security headers"),
        ("/redirects https://ejemplo.com", "Redirecciones"),
        ("/fingerprint https://ejemplo.com", "Tech fingerprint"),
        ("/subs ejemplo.com", "Subdominios (crt.sh)"),
        ("/recon ejemplo.com", "robots/sitemap/security.txt"),
        ("/dnssec ejemplo.com", "DNSSEC"),
        ("/wayback ejemplo.com", "Wayback snapshots"),
    ],
    "ip": [
        ("/ip 8.8.8.8", "GeoIP + ASN + reverse"),
        ("/rdap 8.8.8.8", "RDAP"),
        ("/bgp 8.8.8.8", "BGP"),
        ("/tor 8.8.8.8", "¿Tor exit?"),
        ("/scan host 22,80,443", "Scan TCP suave"),
        ("/banner host 22", "Banner grabbing"),
    ],
    "hash": [
        ("/hash texto", "MD5/SHA1/SHA256/SHA512 de texto"),
        ("/hashid <hash>", "Identifica tipo de hash"),
        ("/b64e texto", "Base64 encode"),
        ("/b64d <b64>", "Base64 decode"),
        ("/hexe texto", "Hex encode"),
        ("/hexd <hex>", "Hex decode"),
        ("/urle texto", "URL encode"),
        ("/urld texto", "URL decode"),
        ("/rot 13 texto", "ROT-N"),
        ("/atbash texto", "Atbash"),
        ("/magic <texto>", "Magic decoder"),
    ],
    "jwt": [
        ("/jwt <token>", "Decodifica JWT"),
        ("/jwtcrack <token> <secret>", "Verifica HS256 con secreto"),
    ],
    "pw": [
        ("/pwgen 20", "Genera password"),
        ("/passphrase 5", "Genera passphrase"),
        ("/pwstrength <pw>", "Fuerza con zxcvbn"),
        ("/pwned <pw>", "HIBP por k-anonimato"),
    ],
    "ioc": [
        ("/iocs <texto>", "Extrae IOCs"),
        ("/defang <texto>", "Defang"),
        ("/refang <texto>", "Refang"),
        ("/email user@dominio.com", "Validación + MX"),
        ("/spfdkim ejemplo.com", "SPF/DKIM/DMARC"),
        ("/mailheaders <reply with raw>", "Analiza cabeceras"),
    ],
    "user": [
        ("/user <username>", "OSINT en plataformas"),
        ("/gh <username>", "GitHub user"),
    ],
    "file": [
        ("Envía un documento o imagen", "Hashes/magic/strings/EXIF/QR"),
        ("/yara <reply al archivo>", "Escaneo YARA"),
    ],
    "crypto": [
        ("/caesar <texto>", "Brute Caesar"),
        ("/vigenere <key> <texto>", "Vigenère decrypt"),
        ("/vbrute <texto>", "Vigenère diccionario"),
        ("/xorbrute <hex>", "XOR 1-byte brute"),
        ("/qr <texto>", "Genera QR"),
        ("/lsb (reply imagen)", "Stego LSB extract"),
    ],
    "watch": [
        ("/watch domain ejemplo.com", "Añadir"),
        ("/watchlist", "Listar"),
        ("/unwatch <id>", "Quitar"),
    ],
    "misc": [
        ("/cve CVE-2024-1234", "CVE lookup"),
        ("/cvesearch keyword", "CVE search"),
        ("/epss CVE-2024-1234", "EPSS"),
        ("/fakeid es", "Identidad falsa (test)"),
        ("/note save <título> <pass> | texto", "Nota cifrada"),
        ("/note list", "Listar notas"),
        ("/note open <id> <pass>", "Leer nota"),
        ("/note del <id>", "Borrar nota"),
        ("/lang es|en", "Idioma"),
        ("/report <md|pdf>", "Reporte del último resultado"),
    ],
}


def submenu(category: str, lang: str = "es") -> str:
    items = SUBMENUS.get(category, [])
    body = "\n".join(f"`{cmd}` — {desc}" for cmd, desc in items)
    return body or t("no_results", lang)
