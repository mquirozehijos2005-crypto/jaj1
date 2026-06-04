"""Job periódico: revisa la watchlist y alerta a los usuarios."""
from __future__ import annotations

import asyncio
import json
import logging

from telegram import Bot

from .services import dns_svc, ip_svc, subdomain_svc, tls_svc
from .storage import Storage

log = logging.getLogger(__name__)


async def _snapshot(kind: str, target: str) -> dict:
    if kind == "domain":
        a = await dns_svc.lookup(target, ("A", "AAAA", "MX", "NS"))
        try:
            cert = await tls_svc.cert_info(target)
        except Exception:  # noqa: BLE001
            cert = None
        try:
            subs = await subdomain_svc.from_crtsh(target, limit=500)
        except Exception:  # noqa: BLE001
            subs = []
        return {
            "A": a.get("A", []),
            "MX": a.get("MX", []),
            "NS": a.get("NS", []),
            "cert_not_after": cert and cert.get("not_after"),
            "san_count": cert and len(cert.get("san", [])),
            "subdomain_count": len(subs),
        }
    if kind == "ip":
        try:
            geo = await ip_svc.geoip(target)
        except Exception:  # noqa: BLE001
            geo = {}
        return {
            "country": geo.get("country"),
            "isp": geo.get("isp"),
            "as": geo.get("as"),
        }
    return {"target": target}


def _diff(old: dict, new: dict) -> list[str]:
    keys = set(old) | set(new)
    diffs = []
    for k in sorted(keys):
        if old.get(k) != new.get(k):
            diffs.append(f"• {k}: {old.get(k)} → {new.get(k)}")
    return diffs


async def run_once(bot: Bot, storage: Storage) -> None:
    rows = storage.watch_all()
    for row in rows:
        kind = row["kind"]
        target = row["target"]
        try:
            new_snap = await _snapshot(kind, target)
        except Exception as exc:  # noqa: BLE001
            log.warning("watch %s/%s falló: %s", kind, target, exc)
            continue
        old_raw = row.get("last_seen")
        if old_raw:
            try:
                old = json.loads(old_raw)
            except ValueError:
                old = {}
            diffs = _diff(old, new_snap)
            if diffs:
                msg = f"👁 *Watch* `{kind}` `{target}`\n" + "\n".join(diffs)
                try:
                    await bot.send_message(
                        chat_id=row["user_id"], text=msg, parse_mode="Markdown"
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("No se pudo notificar a %s: %s", row["user_id"], exc)
        storage.watch_update_snapshot(row["id"], json.dumps(new_snap, ensure_ascii=False))
        await asyncio.sleep(0.5)
