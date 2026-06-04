"""Imagen: EXIF, QR (lectura/escritura), LSB stego básica."""
from __future__ import annotations

from io import BytesIO
from pathlib import Path

from PIL import ExifTags, Image


def exif_info(path: Path) -> dict:
    img = Image.open(path)
    exif = getattr(img, "_getexif", lambda: None)() or {}
    return {ExifTags.TAGS.get(k, str(k)): str(v)[:200] for k, v in exif.items()}


def make_qr(text: str) -> bytes:
    import qrcode

    img = qrcode.make(text)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def read_qr(path: Path) -> list[str]:
    try:
        from pyzbar.pyzbar import decode  # type: ignore
    except ImportError:
        return []
    img = Image.open(path)
    return [d.data.decode("utf-8", errors="replace") for d in decode(img)]


def lsb_extract(path: Path, max_bytes: int = 4096) -> str:
    """Extrae LSB del canal R hasta encontrar terminador o agotar bytes."""
    img = Image.open(path).convert("RGB")
    bits: list[int] = []
    for y in range(img.height):
        for x in range(img.width):
            r, _g, _b = img.getpixel((x, y))
            bits.append(r & 1)
            if len(bits) >= max_bytes * 8:
                break
        if len(bits) >= max_bytes * 8:
            break
    out = bytearray()
    for i in range(0, len(bits) - 8, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
        if byte == 0:
            break
    return out.rstrip(b"\x00").decode("utf-8", errors="replace")
