"""Configuración cargada desde variables de entorno / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # dotenv es opcional en runtime real
    pass


def _parse_ids(raw: str | None) -> list[int]:
    if not raw:
        return []
    out: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out


def _bool(raw: str | None, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    token: str
    allowed_user_ids: list[int] = field(default_factory=list)
    admin_ids: list[int] = field(default_factory=list)
    default_lang: str = "es"
    rate_limit_per_min: int = 30
    max_file_mb: int = 20
    db_path: Path = Path("./data/ciberbot.db")
    yara_rules_dir: Path = Path("./yara_rules")
    metrics_enabled: bool = True
    metrics_port: int = 9090
    log_level: str = "INFO"

    @property
    def access_restricted(self) -> bool:
        return bool(self.allowed_user_ids)


def load_settings() -> Settings:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN no definido. Crea un .env desde .env.example."
        )
    return Settings(
        token=token,
        allowed_user_ids=_parse_ids(os.environ.get("ALLOWED_USER_IDS")),
        admin_ids=_parse_ids(os.environ.get("ADMIN_IDS")),
        default_lang=os.environ.get("DEFAULT_LANG", "es").strip().lower() or "es",
        rate_limit_per_min=int(os.environ.get("RATE_LIMIT_PER_MIN", "30")),
        max_file_mb=int(os.environ.get("MAX_FILE_MB", "20")),
        db_path=Path(os.environ.get("DB_PATH", "./data/ciberbot.db")).expanduser(),
        yara_rules_dir=Path(
            os.environ.get("YARA_RULES_DIR", "./yara_rules")
        ).expanduser(),
        metrics_enabled=_bool(os.environ.get("METRICS_ENABLED"), True),
        metrics_port=int(os.environ.get("METRICS_PORT", "9090")),
        log_level=os.environ.get("LOG_LEVEL", "INFO").strip().upper() or "INFO",
    )
