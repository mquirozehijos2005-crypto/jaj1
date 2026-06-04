"""Análisis de archivos: hashes, magic, entropía, strings, PE/ELF, OLE/PDF, YARA."""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from .hash_svc import hash_file

_MAGIC_BYTES = {
    b"MZ": "PE/EXE/DLL (Windows)",
    b"\x7fELF": "ELF (Linux/Unix)",
    b"\xca\xfe\xba\xbe": "Java class / Mach-O fat",
    b"%PDF": "PDF",
    b"PK\x03\x04": "ZIP (también docx/xlsx/jar/apk)",
    b"\xd0\xcf\x11\xe0": "MS Office binario (OLE)",
    b"Rar!": "RAR",
    b"7z\xbc\xaf'\x1c": "7z",
    b"\x1f\x8b": "GZIP",
    b"BM": "Bitmap (BMP)",
    b"\x89PNG": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
    b"#!/": "Script con shebang",
}


def detect_magic(head: bytes) -> str:
    for sig, label in _MAGIC_BYTES.items():
        if head.startswith(sig):
            return label
    try:
        import magic  # python-magic
        return magic.from_buffer(head)
    except Exception:  # noqa: BLE001
        return "desconocido"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def strings_ascii(data: bytes, min_len: int = 5, limit: int = 200) -> list[str]:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    return [s.decode("ascii", errors="replace") for s in found[:limit]]


def basic_report(path: Path) -> dict:
    p = Path(path)
    raw = p.read_bytes()
    with p.open("rb") as f:
        hashes = hash_file(f)
    return {
        "name": p.name,
        "size": len(raw),
        "magic": detect_magic(raw[:512]),
        "entropy": round(shannon_entropy(raw), 3),
        "hashes": hashes,
    }


# ---------- PE / ELF ----------

def pe_info(path: Path) -> dict | None:
    try:
        import pefile  # type: ignore
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT[:10]:
            dll = entry.dll.decode("ascii", "replace")
            for imp in entry.imports[:5]:
                if imp.name:
                    imports.append(f"{dll}:{imp.name.decode('ascii', 'replace')}")
    sections = [
        f"{s.Name.rstrip(b' .' + b'\x00').decode('ascii','replace')} "
        f"vsz={s.Misc_VirtualSize} raw={s.SizeOfRawData}"
        for s in pe.sections
    ]
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": sections,
        "imports_sample": imports[:30],
    }


def elf_info(path: Path) -> dict | None:
    try:
        head = Path(path).read_bytes()[:64]
    except OSError:
        return None
    if not head.startswith(b"\x7fELF"):
        return None
    bits = "64" if head[4] == 2 else "32"
    endian = "LE" if head[5] == 1 else "BE"
    return {"format": "ELF", "bits": bits, "endian": endian}


# ---------- OLE / PDF ----------

def ole_macros(path: Path) -> dict | None:
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except ImportError:
        return None
    try:
        vba = VBA_Parser(str(path))
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    if not vba.detect_vba_macros():
        return {"macros": False}
    out: dict[str, list[str]] = {"streams": [], "suspicious": []}
    for (_, _, vba_filename, _) in vba.extract_macros():
        out["streams"].append(vba_filename)
    try:
        for kw, desc, _ in vba.analyze_macros():
            out["suspicious"].append(f"{kw}: {desc}")
    except Exception:  # noqa: BLE001
        pass
    return {"macros": True, **out}


def pdf_info(path: Path) -> dict | None:
    try:
        import pypdf  # type: ignore
    except ImportError:
        return None
    try:
        reader = pypdf.PdfReader(str(path))
        info = reader.metadata or {}
        return {
            "pages": len(reader.pages),
            "encrypted": reader.is_encrypted,
            "title": str(info.get("/Title", "")),
            "author": str(info.get("/Author", "")),
            "producer": str(info.get("/Producer", "")),
            "creator": str(info.get("/Creator", "")),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


# ---------- YARA ----------

def yara_scan(path: Path, rules_dir: Path) -> list[str]:
    try:
        import yara  # type: ignore
    except ImportError:
        return []
    rules_dir = Path(rules_dir)
    if not rules_dir.exists():
        return []
    rule_files = list(rules_dir.rglob("*.yar")) + list(rules_dir.rglob("*.yara"))
    if not rule_files:
        return []
    try:
        rules = yara.compile(filepaths={str(i): str(p) for i, p in enumerate(rule_files)})
        matches = rules.match(str(path))
    except Exception:  # noqa: BLE001
        return []
    return [m.rule for m in matches]
