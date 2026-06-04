"""Helpers de formateo Markdown / texto seguro para Telegram."""
from __future__ import annotations

MD_ESCAPE = "_*[]()~`>#+-=|{}.!\\"
TG_LIMIT = 4000  # margen sobre 4096


def escape_md(text: str) -> str:
    return "".join(("\\" + ch) if ch in MD_ESCAPE else ch for ch in text)


def code(text: str) -> str:
    return f"```\n{text}\n```"


def chunk(text: str, limit: int = TG_LIMIT) -> list[str]:
    if len(text) <= limit:
        return [text]
    out: list[str] = []
    buf: list[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > limit and buf:
            out.append("".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += len(line)
    if buf:
        out.append("".join(buf))
    return out


def kv_table(rows: list[tuple[str, str]], pad: int = 14) -> str:
    return "\n".join(f"{k:<{pad}} {v}" for k, v in rows)
