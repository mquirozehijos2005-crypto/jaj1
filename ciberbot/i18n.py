"""Traducciones simples ES/EN."""
from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    "es": {
        "welcome": (
            "👋 *CiberBot* — toolkit de ciberseguridad / OSINT / CTF.\n\n"
            "Pulsa /menu para el menú interactivo o /help para comandos.\n"
            "⚠️ Uso ético: solo contra activos autorizados."
        ),
        "menu_title": "🛠 *Menú principal* — elige una categoría:",
        "cat_domain": "🌐 Dominio / URL",
        "cat_ip": "🛰 IP / Red",
        "cat_hash": "🔐 Hash / Encoding",
        "cat_jwt": "🎫 JWT",
        "cat_pw": "🔑 Passwords",
        "cat_ioc": "🚩 IOCs / Email",
        "cat_user": "👤 OSINT username",
        "cat_file": "📁 Archivos / Malware",
        "cat_crypto": "🧪 Cripto / CTF",
        "cat_watch": "👁 Watchlist",
        "cat_misc": "✨ Extras",
        "back": "⬅️ Volver",
        "denied": "🚫 No tienes permiso para usar este bot.",
        "rate_limit": "⏳ Demasiadas peticiones. Espera un momento.",
        "usage": "Uso: ",
        "error": "❌ Error: ",
        "working": "⏳ Procesando...",
        "no_results": "Sin resultados.",
        "ethics": (
            "⚠️ Esta herramienta es defensiva / educativa. "
            "No la uses contra sistemas o personas sin autorización."
        ),
    },
    "en": {
        "welcome": (
            "👋 *CiberBot* — cybersecurity / OSINT / CTF toolkit.\n\n"
            "Tap /menu for the interactive menu or /help for commands.\n"
            "⚠️ Ethical use: only against authorized assets."
        ),
        "menu_title": "🛠 *Main menu* — pick a category:",
        "cat_domain": "🌐 Domain / URL",
        "cat_ip": "🛰 IP / Net",
        "cat_hash": "🔐 Hash / Encoding",
        "cat_jwt": "🎫 JWT",
        "cat_pw": "🔑 Passwords",
        "cat_ioc": "🚩 IOCs / Email",
        "cat_user": "👤 Username OSINT",
        "cat_file": "📁 Files / Malware",
        "cat_crypto": "🧪 Crypto / CTF",
        "cat_watch": "👁 Watchlist",
        "cat_misc": "✨ Extras",
        "back": "⬅️ Back",
        "denied": "🚫 You are not allowed to use this bot.",
        "rate_limit": "⏳ Too many requests. Slow down.",
        "usage": "Usage: ",
        "error": "❌ Error: ",
        "working": "⏳ Working...",
        "no_results": "No results.",
        "ethics": (
            "⚠️ Defensive / educational tool. "
            "Do not use against systems or people without authorization."
        ),
    },
}


def t(key: str, lang: str = "es") -> str:
    lang = lang if lang in STRINGS else "es"
    return STRINGS[lang].get(key, STRINGS["es"].get(key, key))
