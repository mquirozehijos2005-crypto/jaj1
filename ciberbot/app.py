"""Wiring del bot: registra handlers y arranca."""
from __future__ import annotations

import asyncio
import logging

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    InlineQueryHandler,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

from .config import Settings, load_settings
from .handlers import callbacks, commands, files, inline
from .healthserver import start as start_health
from .metrics import setup_metrics
from .rate_limit import RateLimiter
from .storage import Storage
from .watchlist_worker import run_once

log = logging.getLogger(__name__)


def _build_request() -> HTTPXRequest:
    # HF Spaces a veces tarda en establecer la primera conexión TLS;
    # subimos timeouts para evitar TimedOut en initialize().
    return HTTPXRequest(
        connect_timeout=30.0,
        read_timeout=30.0,
        write_timeout=30.0,
        pool_timeout=30.0,
    )


# Comandos para el menú nativo de Telegram (autocomplete al escribir "/")
TELEGRAM_COMMANDS = [
    ("start", "Bienvenida"),
    ("menu", "Menú interactivo"),
    ("help", "Lista de comandos"),
    ("about", "Acerca del bot"),
    ("dns", "DNS de un dominio"),
    ("whois", "WHOIS"),
    ("ssl", "Certificado TLS"),
    ("headers", "Security headers"),
    ("subs", "Subdominios (crt.sh)"),
    ("ip", "GeoIP + ASN"),
    ("hash", "Hashes de un texto"),
    ("hashid", "Identificar hash"),
    ("b64e", "Base64 encode"),
    ("b64d", "Base64 decode"),
    ("magic", "Magic decoder"),
    ("jwt", "Decodificar JWT"),
    ("pwgen", "Generar password"),
    ("pwned", "HIBP check"),
    ("iocs", "Extraer IOCs"),
    ("user", "OSINT username"),
    ("cve", "CVE lookup"),
    ("watchlist", "Mi watchlist"),
    ("note", "Notas cifradas"),
    ("lang", "Cambiar idioma"),
]


async def _on_post_init(app: Application) -> None:
    from telegram import BotCommand
    try:
        await app.bot.set_my_commands(
            [BotCommand(c, d) for c, d in TELEGRAM_COMMANDS]
        )
        log.info("Comandos registrados en Telegram (%d)", len(TELEGRAM_COMMANDS))
    except Exception as exc:  # noqa: BLE001
        log.warning("No se pudo set_my_commands: %s", exc)


def build_app(settings: Settings) -> Application:
    app = (
        Application.builder()
        .token(settings.token)
        .request(_build_request())
        .get_updates_request(_build_request())
        .post_init(_on_post_init)
        .build()
    )

    storage = Storage(settings.db_path)
    limiter = RateLimiter(settings.rate_limit_per_min)
    app.bot_data["settings"] = settings
    app.bot_data["storage"] = storage
    app.bot_data["limiter"] = limiter

    # Comandos
    cmd_pairs = [
        ("start", commands.cmd_start),
        ("menu", commands.cmd_menu),
        ("help", commands.cmd_help),
        ("about", commands.cmd_about),
        ("lang", commands.cmd_lang),
        ("dns", commands.cmd_dns),
        ("whois", commands.cmd_whois),
        ("ssl", commands.cmd_ssl),
        ("tlsscan", commands.cmd_tlsscan),
        ("headers", commands.cmd_headers),
        ("redirects", commands.cmd_redirects),
        ("fingerprint", commands.cmd_fingerprint),
        ("subs", commands.cmd_subs),
        ("recon", commands.cmd_recon),
        ("dnssec", commands.cmd_dnssec),
        ("wayback", commands.cmd_wayback),
        ("ip", commands.cmd_ip),
        ("rdap", commands.cmd_rdap),
        ("bgp", commands.cmd_bgp),
        ("tor", commands.cmd_tor),
        ("scan", commands.cmd_scan),
        ("banner", commands.cmd_banner),
        ("hash", commands.cmd_hash),
        ("hashid", commands.cmd_hashid),
        ("b64e", commands.cmd_b64e),
        ("b64d", commands.cmd_b64d),
        ("hexe", commands.cmd_hexe),
        ("hexd", commands.cmd_hexd),
        ("urle", commands.cmd_urle),
        ("urld", commands.cmd_urld),
        ("rot", commands.cmd_rot),
        ("atbash", commands.cmd_atbash),
        ("magic", commands.cmd_magic),
        ("jwt", commands.cmd_jwt),
        ("jwtcrack", commands.cmd_jwtcrack),
        ("pwgen", commands.cmd_pwgen),
        ("passphrase", commands.cmd_passphrase),
        ("pwstrength", commands.cmd_pwstrength),
        ("pwned", commands.cmd_pwned),
        ("iocs", commands.cmd_iocs),
        ("defang", commands.cmd_defang),
        ("refang", commands.cmd_refang),
        ("email", commands.cmd_email),
        ("spfdkim", commands.cmd_spfdkim),
        ("mailheaders", commands.cmd_mailheaders),
        ("user", commands.cmd_user),
        ("gh", commands.cmd_gh),
        ("caesar", commands.cmd_caesar),
        ("vigenere", commands.cmd_vigenere),
        ("vbrute", commands.cmd_vbrute),
        ("xorbrute", commands.cmd_xorbrute),
        ("qr", commands.cmd_qr),
        ("lsb", commands.cmd_lsb),
        ("cve", commands.cmd_cve),
        ("cvesearch", commands.cmd_cvesearch),
        ("epss", commands.cmd_epss),
        ("fakeid", commands.cmd_fakeid),
        ("watch", commands.cmd_watch),
        ("watchlist", commands.cmd_watchlist),
        ("unwatch", commands.cmd_unwatch),
        ("note", commands.cmd_note),
        ("report", commands.cmd_report),
        ("yara", commands.cmd_yara),
    ]
    for name, fn in cmd_pairs:
        app.add_handler(CommandHandler(name, fn))

    app.add_handler(MessageHandler(filters.Document.ALL, files.on_document))
    app.add_handler(MessageHandler(filters.PHOTO, files.on_photo))
    app.add_handler(CallbackQueryHandler(callbacks.on_callback))
    app.add_handler(InlineQueryHandler(inline.on_inline))

    # Error handler global
    async def on_error(update, context):
        log.exception("Excepción no capturada", exc_info=context.error)
        try:
            if isinstance(update, Update) and update.effective_message:
                await update.effective_message.reply_text(
                    "❌ Ups, fallo interno. Lo registré en logs."
                )
        except Exception:  # noqa: BLE001
            pass

    app.add_error_handler(on_error)

    # Worker periódico de watchlist (cada 30 min)
    async def watch_job(_ctx):
        try:
            await run_once(app.bot, storage)
        except Exception:  # noqa: BLE001
            log.exception("watchlist worker falló")

    app.job_queue.run_repeating(watch_job, interval=1800, first=120)
    return app


def main() -> None:
    settings = load_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    setup_metrics(settings.metrics_enabled, settings.metrics_port)
    # HF Spaces / contenedores: exponer un puerto HTTP de salud (default 7860).
    import os
    health_port = int(os.environ.get("PORT", "7860"))
    start_health(health_port)
    app = build_app(settings)
    log.info("CiberBot iniciado.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
