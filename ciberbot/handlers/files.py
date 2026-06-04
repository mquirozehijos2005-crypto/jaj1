"""Handler para documentos/imágenes enviados al bot."""
from __future__ import annotations

import json
import logging
import tempfile
from io import BytesIO
from pathlib import Path

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from ..services import file_svc, image_svc
from ..utils.format import code, kv_table
from .auth import guarded

log = logging.getLogger(__name__)


async def _download(file_obj) -> Path:
    bio = BytesIO()
    await file_obj.download_to_memory(bio)
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(bio.getvalue())
    tmp.close()
    return Path(tmp.name)


@guarded("file")
async def on_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    settings = ctx.bot_data["settings"]
    doc = update.message.document
    if not doc:
        return
    if doc.file_size and doc.file_size > settings.max_file_mb * 1024 * 1024:
        await update.message.reply_text(f"Archivo demasiado grande (>{settings.max_file_mb}MB).")
        return
    f = await doc.get_file()
    path = await _download(f)
    try:
        report = file_svc.basic_report(path)
        report["filename_reported"] = doc.file_name
        body_lines = [
            ("Nombre", doc.file_name or report["name"]),
            ("Tamaño", f"{report['size']:,} bytes"),
            ("Magic", report["magic"]),
            ("Entropía", str(report["entropy"])),
        ]
        for k, v in report["hashes"].items():
            body_lines.append((k.upper(), v))
        text = "*Archivo*\n" + code(kv_table(body_lines, pad=10))

        # PE
        pe = file_svc.pe_info(path)
        if pe:
            text += "\n*PE*\n" + code(json.dumps(pe, indent=2, ensure_ascii=False)[:1500])
        # ELF
        elf = file_svc.elf_info(path)
        if elf:
            text += "\n*ELF*\n" + code(json.dumps(elf, indent=2))
        # PDF
        pdf = file_svc.pdf_info(path) if (doc.file_name or "").lower().endswith(".pdf") else None
        if pdf:
            text += "\n*PDF*\n" + code(json.dumps(pdf, indent=2, ensure_ascii=False))
        # OLE / docx
        if (doc.file_name or "").lower().endswith((".doc", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptx")):
            ole = file_svc.ole_macros(path)
            if ole:
                text += "\n*VBA*\n" + code(json.dumps(ole, indent=2, ensure_ascii=False)[:1500])
        # YARA
        matches = file_svc.yara_scan(path, settings.yara_rules_dir)
        if matches:
            text += "\n*YARA*\n" + code("\n".join(matches))
        # strings
        head = path.read_bytes()[:64_000]
        s = file_svc.strings_ascii(head, min_len=6, limit=30)
        if s:
            text += "\n*Strings*\n" + code("\n".join(s)[:1500])

        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
    finally:
        path.unlink(missing_ok=True)


@guarded("photo")
async def on_photo(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    photo = update.message.photo[-1]
    f = await photo.get_file()
    path = await _download(f)
    try:
        report = file_svc.basic_report(path)
        exif = image_svc.exif_info(path)
        qr = image_svc.read_qr(path)
        body = [
            f"*Imagen* `{report['name']}`",
            code(f"size={report['size']}  entropy={report['entropy']}"),
            "*EXIF*\n" + code(json.dumps(exif, indent=2, ensure_ascii=False)[:1500] or "(vacío)"),
        ]
        if qr:
            body.append("*QR*\n" + code("\n".join(qr)))
        await update.message.reply_text("\n".join(body), parse_mode=ParseMode.MARKDOWN)
    finally:
        path.unlink(missing_ok=True)
