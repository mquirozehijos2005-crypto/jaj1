"""Modo inline: @bot dns ejemplo.com, @bot b64e hola, etc."""
from __future__ import annotations

from uuid import uuid4

from telegram import InlineQueryResultArticle, InputTextMessageContent, Update
from telegram.ext import ContextTypes

from ..services import dns_svc, encoding_svc, hash_svc
from ..utils.format import code
from ..utils.validate import is_domain


async def on_inline(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.inline_query
    if not q:
        return
    text = (q.query or "").strip()
    if not text:
        await q.answer([])
        return

    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    results = []

    try:
        if cmd == "b64e" and arg:
            results.append(_article("Base64 encode", encoding_svc.b64e(arg)))
        elif cmd == "b64d" and arg:
            results.append(_article("Base64 decode", encoding_svc.b64d(arg)))
        elif cmd == "hexe" and arg:
            results.append(_article("Hex encode", encoding_svc.hexe(arg)))
        elif cmd == "hexd" and arg:
            results.append(_article("Hex decode", encoding_svc.hexd(arg)))
        elif cmd == "rot13" and arg:
            results.append(_article("ROT13", encoding_svc.rot(13, arg)))
        elif cmd == "hash" and arg:
            h = hash_svc.hash_text(arg)
            results.append(_article(
                "Hashes",
                "\n".join(f"{k.upper()}: {v}" for k, v in h.items()),
            ))
        elif cmd == "dns" and arg and is_domain(arg):
            data = await dns_svc.lookup(arg, ("A", "AAAA", "MX"))
            body = "\n".join(f"{k}: {', '.join(v) or '-'}" for k, v in data.items())
            results.append(_article(f"DNS {arg}", body))
    except Exception:  # noqa: BLE001
        results = []

    await q.answer(results, cache_time=10)


def _article(title: str, text: str) -> InlineQueryResultArticle:
    return InlineQueryResultArticle(
        id=str(uuid4()),
        title=title,
        description=text[:80],
        input_message_content=InputTextMessageContent(code(text[:3500])),
    )
