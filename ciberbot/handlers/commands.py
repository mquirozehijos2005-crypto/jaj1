"""Handlers de comandos del bot. Cada función envuelta con @guarded."""
from __future__ import annotations

import json
import logging
from io import BytesIO

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from ..i18n import t
from ..services import (
    cipher_svc,
    cve_svc,
    dns_svc,
    email_svc,
    encoding_svc,
    file_svc,
    hash_svc,
    http_svc,
    image_svc,
    ioc_svc,
    ip_svc,
    jwt_svc,
    misc_svc,
    password_svc,
    report_svc,
    subdomain_svc,
    tls_svc,
    username_svc,
    wayback_svc,
    whois_svc,
)
from ..utils import crypto_box
from ..utils.format import chunk, code, kv_table
from ..utils.validate import is_domain, is_ip
from .auth import guarded
from .keyboards import back_button, main_menu, submenu

log = logging.getLogger(__name__)


def _lang(ctx: ContextTypes.DEFAULT_TYPE, user_id: int) -> str:
    return ctx.bot_data["storage"].get_lang(
        user_id, ctx.bot_data["settings"].default_lang
    )


def _save_last(ctx: ContextTypes.DEFAULT_TYPE, user_id: int, payload: dict) -> None:
    ctx.bot_data.setdefault("last_results", {})[user_id] = payload


# ============== Básicos ==============

@guarded("start")
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    lang = _lang(ctx, user.id) if user else "es"
    name = (user.first_name if user else None) or ""
    greeting = f"¡Hola, {name}! " if name and lang == "es" else (f"Hi {name}! " if name else "")
    await update.message.reply_text(
        greeting + t("welcome", lang),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_menu(lang),
    )


@guarded("about")
async def cmd_about(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    from .. import __version__
    lang = _lang(ctx, update.effective_user.id)
    await update.message.reply_text(
        t("about", lang).format(version=__version__),
        parse_mode=ParseMode.MARKDOWN,
        disable_web_page_preview=True,
    )


@guarded("menu")
async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    lang = _lang(ctx, update.effective_user.id)
    await update.message.reply_text(
        t("menu_title", lang),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_menu(lang),
    )


@guarded("help")
async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    txt = (
        "*Comandos principales*\n"
        "Dominio: /dns /whois /ssl /tlsscan /headers /redirects /fingerprint "
        "/subs /recon /dnssec /wayback\n"
        "IP: /ip /rdap /bgp /tor /scan /banner\n"
        "Hash/Enc: /hash /hashid /b64e /b64d /hexe /hexd /urle /urld /rot "
        "/atbash /magic\n"
        "JWT: /jwt /jwtcrack\n"
        "Pass: /pwgen /passphrase /pwstrength /pwned\n"
        "IOC/Email: /iocs /defang /refang /email /spfdkim /mailheaders\n"
        "OSINT: /user /gh\n"
        "Files: envía un archivo · /yara\n"
        "Crypto: /caesar /vigenere /vbrute /xorbrute /qr /lsb\n"
        "CVE: /cve /cvesearch /epss\n"
        "Watch: /watch /watchlist /unwatch\n"
        "Misc: /fakeid /note /lang /report\n"
    )
    await update.message.reply_text(txt, parse_mode=ParseMode.MARKDOWN)


@guarded("lang")
async def cmd_lang(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /lang es | /lang en")
        return
    new_lang = ctx.args[0].lower()
    if new_lang not in ("es", "en"):
        await update.message.reply_text("Idiomas: es, en")
        return
    ctx.bot_data["storage"].set_lang(update.effective_user.id, new_lang)
    await update.message.reply_text("OK ✅")


# ============== Dominio / URL ==============

def _need(args: list[str], n: int, usage: str) -> bool:
    return len(args) >= n


async def _reply(update: Update, text: str, parse_mode: str | None = ParseMode.MARKDOWN) -> None:
    for piece in chunk(text):
        await update.message.reply_text(piece, parse_mode=parse_mode)


@guarded("dns")
async def cmd_dns(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /dns <dominio>")
        return
    domain = ctx.args[0]
    if not is_domain(domain):
        await update.message.reply_text("Dominio inválido.")
        return
    data = await dns_svc.lookup(domain)
    provider = dns_svc.detect_mail_provider(data.get("MX", []))
    lines = [f"*DNS de* `{domain}`"]
    for k, v in data.items():
        lines.append(f"\n*{k}*")
        lines.append(code("\n".join(v) if v else "-"))
    if provider:
        lines.append(f"\n📧 Mail provider: *{provider}*")
    _save_last(ctx, update.effective_user.id, {"dns": data})
    await _reply(update, "\n".join(lines))


@guarded("whois")
async def cmd_whois(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /whois <dominio>")
        return
    data = await whois_svc.domain_whois(ctx.args[0])
    _save_last(ctx, update.effective_user.id, {"whois": data})
    body = code(json.dumps(data, indent=2, ensure_ascii=False))
    await _reply(update, f"*WHOIS*\n{body}")


@guarded("ssl")
async def cmd_ssl(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /ssl <dominio> [puerto]")
        return
    host = ctx.args[0]
    port = int(ctx.args[1]) if len(ctx.args) > 1 else 443
    info = await tls_svc.cert_info(host, port)
    rows = [
        ("CN", info["subject_cn"] or "-"),
        ("Issuer", f"{info['issuer_cn']} / {info['issuer_org']}"),
        ("TLS", info["tls_version"]),
        ("Cipher", info["cipher"] or "-"),
        ("Not before", info["not_before"] or "-"),
        ("Not after", info["not_after"] or "-"),
        ("Days left", str(info["days_left"])),
        ("SAN", ", ".join(info["san"][:8]) + ("..." if len(info["san"]) > 8 else "")),
    ]
    _save_last(ctx, update.effective_user.id, {"ssl": info})
    await _reply(update, f"*TLS de* `{host}:{port}`\n{code(kv_table(rows))}")


@guarded("tlsscan")
async def cmd_tlsscan(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /tlsscan <host>")
        return
    res = await tls_svc.supported_protocols(ctx.args[0])
    rows = [(k, "✅" if v else "❌") for k, v in res.items()]
    await _reply(update, f"*Protocolos TLS* `{ctx.args[0]}`\n{code(kv_table(rows))}")


@guarded("headers")
async def cmd_headers(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /headers <url>")
        return
    info = await http_svc.fetch_headers(ctx.args[0])
    sec_rows = [
        (k, "✅" if v else "❌") for k, v in info["security"].items()
    ]
    body = (
        f"*HTTP* `{info['url']}` → *{info['status']}*\n"
        f"Server: `{info.get('server') or '-'}`\n\n"
        f"*Security headers*\n{code(kv_table(sec_rows))}"
    )
    if info["missing"]:
        body += "\n*Faltan:* " + ", ".join(info["missing"])
    _save_last(ctx, update.effective_user.id, {"headers": info})
    await _reply(update, body)


@guarded("redirects")
async def cmd_redirects(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /redirects <url>")
        return
    chain = await http_svc.redirect_chain(ctx.args[0])
    lines = [f"*Cadena de redirecciones*"]
    for i, hop in enumerate(chain, 1):
        if "error" in hop:
            lines.append(f"{i}. ❌ {hop['url']} → {hop['error']}")
        else:
            arrow = f" → {hop['location']}" if hop.get("location") else ""
            lines.append(f"{i}. *{hop['status']}* {hop['url']}{arrow}")
    await _reply(update, "\n".join(lines))


@guarded("fingerprint")
async def cmd_fingerprint(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /fingerprint <url>")
        return
    info = await http_svc.fingerprint(ctx.args[0])
    rows = [
        ("URL", info["url"]),
        ("Status", str(info["status"])),
        ("Server", info.get("server") or "-"),
        ("Title", info.get("title") or "-"),
        ("Tech", ", ".join(info["tech"]) or "-"),
    ]
    await _reply(update, "*Fingerprint*\n" + code(kv_table(rows, pad=8)))


@guarded("subs")
async def cmd_subs(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /subs <dominio>")
        return
    await update.message.chat.send_action("typing")
    subs = await subdomain_svc.cached_from_crtsh(ctx.bot_data["storage"], ctx.args[0])
    if not subs:
        await update.message.reply_text("Sin subdominios.")
        return
    _save_last(ctx, update.effective_user.id, {"subs": subs})
    body = "\n".join(subs[:200])
    await _reply(update, f"*Subdominios* `{ctx.args[0]}` ({len(subs)})\n{code(body)}")


@guarded("recon")
async def cmd_recon(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /recon <dominio>")
        return
    info = await http_svc.robots_and_friends(ctx.args[0])
    out = [f"*Recon* `{ctx.args[0]}`"]
    for label, item in info.items():
        if "error" in item:
            out.append(f"\n*{label}*: ❌ {item['error']}")
        elif item["status"] == 200:
            out.append(f"\n*{label}*: ✅\n{code(item['preview'][:1200])}")
        else:
            out.append(f"\n*{label}*: status {item['status']}")
    await _reply(update, "\n".join(out))


@guarded("dnssec")
async def cmd_dnssec(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /dnssec <dominio>")
        return
    res = await dns_svc.dnssec_check(ctx.args[0])
    body = code(json.dumps(res, indent=2))
    await _reply(update, f"*DNSSEC*\n{body}")


@guarded("wayback")
async def cmd_wayback(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /wayback <url o dominio>")
        return
    snaps = await wayback_svc.snapshots(ctx.args[0])
    if not snaps:
        await update.message.reply_text("Sin snapshots.")
        return
    body = "\n".join(f"`{s['timestamp']}` {s['snapshot']}" for s in snaps)
    await _reply(update, f"*Wayback* `{ctx.args[0]}`\n{body}")


# ============== IP / Red ==============

@guarded("ip")
async def cmd_ip(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /ip <ip>")
        return
    ip = ctx.args[0]
    if not is_ip(ip):
        await update.message.reply_text("IP inválida.")
        return
    geo = await ip_svc.geoip(ip)
    rev = await ip_svc.reverse_dns(ip)
    rows = [
        ("IP", geo.get("query", ip)),
        ("País", f"{geo.get('country','-')} ({geo.get('countryCode','-')})"),
        ("Región", geo.get("regionName", "-")),
        ("Ciudad", geo.get("city", "-")),
        ("Lat,Lon", f"{geo.get('lat','-')},{geo.get('lon','-')}"),
        ("ISP", geo.get("isp", "-")),
        ("Org", geo.get("org", "-")),
        ("ASN", geo.get("as", "-")),
        ("Reverse", rev or "-"),
        ("Hosting", "✅" if geo.get("hosting") else "❌"),
        ("Proxy", "✅" if geo.get("proxy") else "❌"),
    ]
    _save_last(ctx, update.effective_user.id, {"ip": geo, "reverse": rev})
    await _reply(update, f"*IP* `{ip}`\n{code(kv_table(rows))}")


@guarded("rdap")
async def cmd_rdap(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /rdap <ip>")
        return
    data = await whois_svc.ip_rdap(ctx.args[0])
    await _reply(update, "*RDAP*\n" + code(json.dumps(data, indent=2, ensure_ascii=False)))


@guarded("bgp")
async def cmd_bgp(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /bgp <ip|ASNxxx>")
        return
    data = await ip_svc.bgp_info(ctx.args[0])
    await _reply(
        update,
        "*BGP*\n" + code(json.dumps(data, indent=2, ensure_ascii=False)[:3500]),
    )


@guarded("tor")
async def cmd_tor(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /tor <ip>")
        return
    is_exit = await ip_svc.is_tor_exit(ctx.args[0])
    await update.message.reply_text(
        f"{ctx.args[0]} → " + ("🧅 ES exit node de Tor" if is_exit else "no parece exit de Tor")
    )


@guarded("scan")
async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /scan <host> [puertos csv]")
        return
    host = ctx.args[0]
    ports = None
    if len(ctx.args) > 1:
        try:
            ports = [int(p) for p in ctx.args[1].split(",") if p.strip()]
        except ValueError:
            await update.message.reply_text("Puertos inválidos.")
            return
    await update.message.chat.send_action("typing")
    open_ports = await ip_svc.scan_ports(host, ports)
    body = ", ".join(str(p) for p in open_ports) or "ninguno"
    await update.message.reply_text(f"Puertos abiertos en {host}: {body}")


@guarded("banner")
async def cmd_banner(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if len(ctx.args) < 2:
        await update.message.reply_text("Uso: /banner <host> <puerto>")
        return
    host, port = ctx.args[0], int(ctx.args[1])
    b = await ip_svc.banner(host, port)
    await update.message.reply_text(f"Banner {host}:{port}:\n{code(b or '(vacío)')}", parse_mode=ParseMode.MARKDOWN)


# ============== Hash / Encoding ==============

@guarded("hash")
async def cmd_hash(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /hash <texto>")
        return
    text = " ".join(ctx.args)
    res = hash_svc.hash_text(text)
    rows = [(k.upper(), v) for k, v in res.items()]
    await _reply(update, "*Hashes*\n" + code(kv_table(rows, pad=8)))


@guarded("hashid")
async def cmd_hashid(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /hashid <hash>")
        return
    h = ctx.args[0]
    candidates = hash_svc.identify(h)
    if not candidates:
        await update.message.reply_text("No coincide con tipos conocidos.")
        return
    body = ", ".join(candidates)
    hint = hash_svc.hashcat_hint(candidates[0])
    await update.message.reply_text(
        f"Posibles tipos: *{body}*\n`{hint}`", parse_mode=ParseMode.MARKDOWN
    )


def _enc_handler(name: str, fn):
    @guarded(name)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not ctx.args:
            await update.message.reply_text(f"Uso: /{name} <texto>")
            return
        text = " ".join(ctx.args)
        try:
            out = fn(text)
        except Exception as exc:  # noqa: BLE001
            await update.message.reply_text(f"❌ {exc}")
            return
        await _reply(update, code(out))
    return wrapper


cmd_b64e = _enc_handler("b64e", encoding_svc.b64e)
cmd_b64d = _enc_handler("b64d", encoding_svc.b64d)
cmd_hexe = _enc_handler("hexe", encoding_svc.hexe)
cmd_hexd = _enc_handler("hexd", encoding_svc.hexd)
cmd_urle = _enc_handler("urle", encoding_svc.urle)
cmd_urld = _enc_handler("urld", encoding_svc.urld)
cmd_atbash = _enc_handler("atbash", encoding_svc.atbash)


@guarded("rot")
async def cmd_rot(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if len(ctx.args) < 2:
        await update.message.reply_text("Uso: /rot <n> <texto>")
        return
    try:
        n = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("N inválido.")
        return
    text = " ".join(ctx.args[1:])
    await _reply(update, code(encoding_svc.rot(n, text)))


@guarded("magic")
async def cmd_magic(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /magic <texto>")
        return
    text = " ".join(ctx.args)
    out = encoding_svc.magic(text)
    if not out:
        await update.message.reply_text("No encontré decodificación legible.")
        return
    body = ["*Magic decoder*"]
    for path, decoded in out:
        body.append(f"\n• `{' → '.join(path)}`\n{code(decoded[:1500])}")
    await _reply(update, "\n".join(body))


# ============== JWT ==============

@guarded("jwt")
async def cmd_jwt(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /jwt <token>")
        return
    try:
        info = jwt_svc.decode(ctx.args[0])
    except Exception as exc:  # noqa: BLE001
        await update.message.reply_text(f"❌ {exc}")
        return
    body = (
        "*Header*\n" + code(json.dumps(info["header"], indent=2)) +
        "\n*Payload*\n" + code(json.dumps(info["payload"], indent=2, ensure_ascii=False))
    )
    if info["warnings"]:
        body += "\n*⚠️ Warnings*\n" + "\n".join(f"• {w}" for w in info["warnings"])
    await _reply(update, body)


@guarded("jwtcrack")
async def cmd_jwtcrack(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if len(ctx.args) < 2:
        await update.message.reply_text("Uso: /jwtcrack <token> <secret>")
        return
    ok = jwt_svc.try_verify(ctx.args[0], " ".join(ctx.args[1:]))
    await update.message.reply_text("✅ secret válido" if ok else "❌ secret no válido")


# ============== Passwords ==============

@guarded("pwgen")
async def cmd_pwgen(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    n = int(ctx.args[0]) if ctx.args and ctx.args[0].isdigit() else 20
    pw = password_svc.generate(n)
    await update.message.reply_text(code(pw), parse_mode=ParseMode.MARKDOWN)


@guarded("passphrase")
async def cmd_passphrase(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    n = int(ctx.args[0]) if ctx.args and ctx.args[0].isdigit() else 5
    await update.message.reply_text(code(password_svc.passphrase(n)), parse_mode=ParseMode.MARKDOWN)


@guarded("pwstrength")
async def cmd_pwstrength(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /pwstrength <password>")
        return
    pw = " ".join(ctx.args)
    info = password_svc.strength(pw)
    rows = [
        ("Score", f"{info['score']}/4"),
        ("log10 guesses", f"{info['guesses_log10']:.1f}"),
        ("Online", info["crack_times"]["online_throttling_100_per_hour"]),
        ("Offline fast", info["crack_times"]["offline_fast_hashing_1e10_per_second"]),
    ]
    body = "*Fuerza*\n" + code(kv_table(rows, pad=14))
    if info["warning"]:
        body += f"\n⚠️ {info['warning']}"
    if info["suggestions"]:
        body += "\n💡 " + " | ".join(info["suggestions"])
    await _reply(update, body)


@guarded("pwned")
async def cmd_pwned(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /pwned <password>")
        return
    pw = " ".join(ctx.args)
    n = await password_svc.pwned(pw)
    if n == 0:
        await update.message.reply_text("✅ No aparece en HIBP.")
    else:
        await update.message.reply_text(
            f"⚠️ Aparece en HIBP *{n:,} veces*. No la uses.",
            parse_mode=ParseMode.MARKDOWN,
        )


# ============== IOCs / Email ==============

@guarded("iocs")
async def cmd_iocs(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /iocs <texto>")
        return
    text = " ".join(ctx.args)
    found = ioc_svc.extract(text)
    parts = ["*IOCs*"]
    for k, vs in found.items():
        if vs:
            parts.append(f"\n*{k}* ({len(vs)})\n" + code("\n".join(vs[:50])))
    await _reply(update, "\n".join(parts) if len(parts) > 1 else "Sin IOCs.")


@guarded("defang")
async def cmd_defang(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /defang <texto>")
        return
    await _reply(update, code(ioc_svc.defang(" ".join(ctx.args))))


@guarded("refang")
async def cmd_refang(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /refang <texto>")
        return
    await _reply(update, code(ioc_svc.refang(" ".join(ctx.args))))


@guarded("email")
async def cmd_email(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /email <correo>")
        return
    res = await email_svc.validate(ctx.args[0])
    body = ["*Email*", code(json.dumps(res, indent=2, ensure_ascii=False))]
    if res.get("valid"):
        mx = await email_svc.mx_records(res["domain"])
        body.append("*MX*\n" + code("\n".join(mx) or "-"))
    await _reply(update, "\n".join(body))


@guarded("spfdkim")
async def cmd_spfdkim(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /spfdkim <dominio>")
        return
    res = await email_svc.spf_dkim_dmarc(ctx.args[0])
    await _reply(update, "*SPF/DKIM/DMARC*\n" + code(json.dumps(res, indent=2, ensure_ascii=False)))


@guarded("mailheaders")
async def cmd_mailheaders(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    raw = update.message.reply_to_message.text if update.message.reply_to_message else None
    if not raw:
        await update.message.reply_text(
            "Reenvía/cita el email con cabeceras crudas y responde a ese mensaje con /mailheaders."
        )
        return
    info = email_svc.analyze_headers(raw)
    await _reply(update, "*Email headers*\n" + code(json.dumps(info, indent=2, ensure_ascii=False)))


# ============== OSINT username ==============

@guarded("user")
async def cmd_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /user <username>")
        return
    await update.message.chat.send_action("typing")
    results = await username_svc.search(ctx.args[0])
    found = [(name, url) for name, ok, url in results if ok]
    not_found = [name for name, ok, _ in results if not ok]
    body = [f"*Username* `{ctx.args[0]}`"]
    if found:
        body.append("\n*Posibles aciertos:*")
        body.extend(f"✅ {n} — {u}" for n, u in found)
    body.append(f"\n_{len(not_found)} sin coincidencia._")
    await _reply(update, "\n".join(body))


@guarded("gh")
async def cmd_gh(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /gh <username>")
        return
    info = await misc_svc.github_user(ctx.args[0])
    if not info:
        await update.message.reply_text("No encontrado o rate-limit.")
        return
    await _reply(update, "*GitHub*\n" + code(json.dumps(info, indent=2, ensure_ascii=False)))


# ============== Crypto / CTF ==============

@guarded("caesar")
async def cmd_caesar(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /caesar <texto>")
        return
    out = cipher_svc.caesar_brute(" ".join(ctx.args))
    body = "*Caesar brute*\n" + "\n".join(
        f"shift={s} score={sc:.2f}\n{code(d[:300])}" for s, d, sc in out
    )
    await _reply(update, body)


@guarded("vigenere")
async def cmd_vigenere(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if len(ctx.args) < 2:
        await update.message.reply_text("Uso: /vigenere <key> <texto>")
        return
    key, *rest = ctx.args
    out = cipher_svc.vigenere_decrypt(" ".join(rest), key)
    await _reply(update, code(out))


@guarded("vbrute")
async def cmd_vbrute(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /vbrute <texto>")
        return
    text = " ".join(ctx.args)
    out = cipher_svc.vigenere_dictionary_attack(text, cipher_svc.default_dictionary())
    body = "*Vigenère dict*\n" + "\n".join(
        f"key={k} score={sc:.2f}\n{code(d[:300])}" for k, d, sc in out
    )
    await _reply(update, body)


@guarded("xorbrute")
async def cmd_xorbrute(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /xorbrute <hex>")
        return
    try:
        data = bytes.fromhex(ctx.args[0])
    except ValueError:
        await update.message.reply_text("Hex inválido.")
        return
    out = cipher_svc.xor_single_byte_brute(data)
    body = "*XOR 1-byte*\n" + "\n".join(
        f"key=0x{k:02x} score={sc:.2f}\n{code(d[:300])}" for k, d, sc in out
    )
    await _reply(update, body)


@guarded("qr")
async def cmd_qr(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /qr <texto>")
        return
    png = image_svc.make_qr(" ".join(ctx.args))
    await update.message.reply_photo(BytesIO(png), caption="QR generado")


@guarded("lsb")
async def cmd_lsb(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message.reply_to_message or not update.message.reply_to_message.photo:
        await update.message.reply_text("Responde a una imagen con /lsb")
        return
    photo = update.message.reply_to_message.photo[-1]
    f = await photo.get_file()
    bio = BytesIO()
    await f.download_to_memory(bio)
    bio.seek(0)
    from pathlib import Path
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp.write(bio.getvalue())
        tmp_path = Path(tmp.name)
    try:
        out = image_svc.lsb_extract(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    await _reply(update, "*LSB extract*\n" + code(out[:2000] or "(vacío)"))


# ============== CVE / EPSS / fakeid ==============

@guarded("cve")
async def cmd_cve(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /cve CVE-YYYY-NNNN")
        return
    info = await cve_svc.by_id(ctx.args[0])
    if not info:
        await update.message.reply_text("No encontrado.")
        return
    body = (
        f"*{info['id']}* (CVSS {info.get('cvss','-')})\n"
        f"_{info.get('published','-')}_\n\n"
        f"{(info.get('summary') or '')[:1500]}\n\n"
        f"*Refs*\n" + "\n".join(info.get("references") or [])[:1500]
    )
    await _reply(update, body)


@guarded("cvesearch")
async def cmd_cvesearch(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /cvesearch <keyword>")
        return
    items = await cve_svc.search(" ".join(ctx.args))
    if not items:
        await update.message.reply_text("Sin resultados.")
        return
    body = "\n\n".join(f"*{i['id']}* (CVSS {i.get('cvss','-')})\n{i['summary']}" for i in items)
    await _reply(update, body)


@guarded("epss")
async def cmd_epss(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args:
        await update.message.reply_text("Uso: /epss CVE-YYYY-NNNN")
        return
    info = await misc_svc.epss(ctx.args[0])
    if not info:
        await update.message.reply_text("Sin EPSS.")
        return
    await update.message.reply_text(
        f"*{info['cve']}*  EPSS={info['epss']}  pct={info['percentile']}",
        parse_mode=ParseMode.MARKDOWN,
    )


@guarded("fakeid")
async def cmd_fakeid(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    locale = ctx.args[0] if ctx.args else "es_ES"
    try:
        info = misc_svc.fake_identity(locale)
    except Exception:  # noqa: BLE001
        info = misc_svc.fake_identity("es_ES")
    info["_warn"] = "Solo para datos de prueba/QA. NO usar para fraude."
    await _reply(update, "*Fake ID*\n" + code(json.dumps(info, indent=2, ensure_ascii=False)))


# ============== Watchlist ==============

@guarded("watch")
async def cmd_watch(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if len(ctx.args) < 2 or ctx.args[0] not in ("domain", "ip", "hash", "url"):
        await update.message.reply_text("Uso: /watch <domain|ip|hash|url> <target>")
        return
    kind, target = ctx.args[0], ctx.args[1]
    ok = ctx.bot_data["storage"].watch_add(update.effective_user.id, kind, target)
    await update.message.reply_text("✅ añadido" if ok else "Ya estaba en la watchlist.")


@guarded("watchlist")
async def cmd_watchlist(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    rows = ctx.bot_data["storage"].watch_list(update.effective_user.id)
    if not rows:
        await update.message.reply_text("Watchlist vacía.")
        return
    body = "\n".join(f"#{r['id']} [{r['kind']}] {r['target']}" for r in rows)
    await _reply(update, "*Watchlist*\n" + code(body))


@guarded("unwatch")
async def cmd_unwatch(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not ctx.args or not ctx.args[0].isdigit():
        await update.message.reply_text("Uso: /unwatch <id>")
        return
    ok = ctx.bot_data["storage"].watch_remove(update.effective_user.id, int(ctx.args[0]))
    await update.message.reply_text("✅ eliminado" if ok else "No encontrado.")


# ============== Notas cifradas ==============

@guarded("note")
async def cmd_note(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    storage = ctx.bot_data["storage"]
    user_id = update.effective_user.id
    if not ctx.args:
        await update.message.reply_text(
            "Uso:\n/note save <título> <pass> | <texto>\n"
            "/note list\n/note open <id> <pass>\n/note del <id>"
        )
        return
    sub = ctx.args[0].lower()
    if sub == "list":
        rows = storage.note_list(user_id)
        if not rows:
            await update.message.reply_text("Sin notas.")
            return
        body = "\n".join(f"#{r['id']}  {r['title']}" for r in rows)
        await _reply(update, "*Notas*\n" + code(body))
        return
    if sub == "save":
        rest = " ".join(ctx.args[1:])
        if "|" not in rest:
            await update.message.reply_text("Falta el `|` separador del cuerpo.")
            return
        head, body = rest.split("|", 1)
        parts = head.strip().split(" ")
        if len(parts) < 2:
            await update.message.reply_text("Uso: /note save <título> <pass> | <texto>")
            return
        title = " ".join(parts[:-1])
        passphrase = parts[-1]
        ct, salt, nonce = crypto_box.encrypt(passphrase, body.strip())
        nid = storage.note_save(user_id, title, ct, salt, nonce)
        await update.message.reply_text(f"✅ guardada como #{nid}")
        return
    if sub == "open" and len(ctx.args) >= 3 and ctx.args[1].isdigit():
        nid = int(ctx.args[1])
        passphrase = " ".join(ctx.args[2:])
        n = storage.note_get(user_id, nid)
        if not n:
            await update.message.reply_text("No encontrada.")
            return
        try:
            text = crypto_box.decrypt(passphrase, n["body"], n["salt"], n["nonce"])
        except Exception:  # noqa: BLE001
            await update.message.reply_text("❌ passphrase incorrecta.")
            return
        await _reply(update, f"*{n['title']}*\n{code(text)}")
        return
    if sub == "del" and len(ctx.args) >= 2 and ctx.args[1].isdigit():
        ok = storage.note_delete(user_id, int(ctx.args[1]))
        await update.message.reply_text("✅" if ok else "No encontrada.")
        return
    await update.message.reply_text("Subcomando inválido.")


# ============== Reportes ==============

@guarded("report")
async def cmd_report(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    last = ctx.bot_data.get("last_results", {}).get(user_id)
    if not last:
        await update.message.reply_text("No hay resultado previo para reportar.")
        return
    fmt = (ctx.args[0].lower() if ctx.args else "md")
    title = "CiberBot report"
    if fmt == "pdf":
        data = report_svc.to_pdf(title, last)
        await update.message.reply_document(BytesIO(data), filename="report.pdf")
    else:
        md = report_svc.to_markdown(title, last)
        await update.message.reply_document(BytesIO(md.encode("utf-8")), filename="report.md")


# ============== YARA reply ==============

@guarded("yara")
async def cmd_yara(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message.reply_to_message
    if not msg or not msg.document:
        await update.message.reply_text("Responde a un documento con /yara")
        return
    settings = ctx.bot_data["settings"]
    f = await msg.document.get_file()
    bio = BytesIO()
    await f.download_to_memory(bio)
    import tempfile
    from pathlib import Path
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(bio.getvalue())
        path = Path(tmp.name)
    try:
        matches = file_svc.yara_scan(path, settings.yara_rules_dir)
    finally:
        path.unlink(missing_ok=True)
    await update.message.reply_text(
        "YARA: " + (", ".join(matches) if matches else "sin matches")
    )
