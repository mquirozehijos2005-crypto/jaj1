"""Middleware de autorización + rate limit aplicado por handler."""
from __future__ import annotations

import functools
import logging
import time
from typing import Awaitable, Callable

from telegram import Update
from telegram.ext import ContextTypes

from ..i18n import t
from ..metrics import CMD_COUNTER, CMD_LATENCY, ERRORS

log = logging.getLogger(__name__)

Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]


def guarded(name: str) -> Callable[[Handler], Handler]:
    def decorator(fn: Handler) -> Handler:
        @functools.wraps(fn)
        async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
            settings = ctx.bot_data["settings"]
            user = update.effective_user
            user_id = user.id if user else 0
            lang = ctx.bot_data["storage"].get_lang(user_id, settings.default_lang)

            if settings.access_restricted and user_id not in settings.allowed_user_ids:
                if update.effective_message:
                    await update.effective_message.reply_text(t("denied", lang))
                return

            limiter = ctx.bot_data["limiter"]
            if not limiter.hit(user_id):
                if update.effective_message:
                    await update.effective_message.reply_text(t("rate_limit", lang))
                return

            CMD_COUNTER.labels(command=name).inc()
            start = time.monotonic()
            try:
                await fn(update, ctx)
            except Exception:  # noqa: BLE001
                ERRORS.labels(command=name).inc()
                log.exception("Error en handler %s", name)
                if update.effective_message:
                    await update.effective_message.reply_text(
                        t("error", lang) + "interno, revisa logs."
                    )
            finally:
                CMD_LATENCY.labels(command=name).observe(time.monotonic() - start)

        return wrapper

    return decorator
