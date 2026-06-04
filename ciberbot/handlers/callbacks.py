"""Callbacks de los botones inline."""
from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from ..i18n import t
from .keyboards import back_button, main_menu, submenu


async def on_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q:
        return
    await q.answer()
    user_id = q.from_user.id
    lang = ctx.bot_data["storage"].get_lang(
        user_id, ctx.bot_data["settings"].default_lang
    )
    data = q.data or ""
    if data == "m:home":
        await q.edit_message_text(
            t("menu_title", lang),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_menu(lang),
        )
        return
    if data.startswith("m:"):
        cat = data[2:]
        text = submenu(cat, lang)
        await q.edit_message_text(
            text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_button(lang),
        )
