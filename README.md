---
title: CiberBot
emoji: 🛡️
colorFrom: indigo
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Telegram cybersecurity / OSINT / CTF bot (no API keys)
---

# CiberBot — Bot de ciberseguridad para Telegram (sin API keys)

Bot interactivo de ciberseguridad / OSINT / CTF. Solo necesita el token del bot. Pensado para correr 24/7 en una VPS Linux.

## Capacidades

| Área | Funciones |
|---|---|
| 🌐 Dominio / URL | DNS, WHOIS, SSL/TLS, escaneo de protocolos TLS, headers de seguridad, redirecciones, fingerprint de tecnologías, subdominios (crt.sh), `robots.txt` / `sitemap.xml` / `security.txt`, DNSSEC, Wayback Machine |
| 🛰 IP / Red | GeoIP + ASN (ip-api), RDAP, BGP (bgpview.io), Tor exit check, scan TCP suave, banner grabbing, reverse DNS, DoH |
| 🔐 Hash / Encoding | MD5/SHA1/SHA256/SHA512 de texto y archivos, identificación de hash, hint hashcat, Base64/Base32/Hex/URL, ROT-N, Atbash, **magic decoder** (auto-detección en cadena) |
| 🎫 JWT | Decodificar header/payload, detectar `alg=none`, HS256, abuso de `kid`, verificar HS256 con secreto |
| 🔑 Passwords | Generador, passphrases tipo diceware, fuerza con zxcvbn, HIBP por k-anonimato (sin API key) |
| 🚩 IOCs / Email | Extracción de IOCs, defang/refang, validación email + MX, SPF/DKIM/DMARC, analizador de cabeceras |
| 👤 OSINT username | Búsqueda en ~18 plataformas, perfil GitHub |
| 📁 Archivos / Malware | Hashes + magic + entropía + strings, PE info (pefile), ELF info, OLE/macros (oletools), PDF metadata (pypdf), YARA |
| 🧪 Cripto / CTF | Caesar brute, Vigenère (clave o diccionario), XOR 1 byte brute, QR generador y lector, stego LSB extract |
| 🛡 CVE | Lookup por ID y por keyword (cve.circl.lu), EPSS (first.org) |
| 👁 Watchlist | Sigue dominios/IPs y avisa cambios en DNS, certificados, subdominios o GeoIP |
| 🔒 Notas | Notas cifradas AES-GCM con passphrase, derivación scrypt |
| 📈 Misc | Identidades fake (QA), reportes Markdown/PDF, modo inline, métricas Prometheus, multi-idioma ES/EN |

## Servicios externos (todos públicos, sin API key)

- `crt.sh`, `cloudflare-dns.com`, `rdap.org`, `bgpview.io`
- `api.pwnedpasswords.com` (k-anonimato)
- `ip-api.com`, `cve.circl.lu`, `api.first.org/data/v1/epss`
- `web.archive.org`, `check.torproject.org/torbulkexitlist`
- DNS / WHOIS estándar

## Requisitos

- Python 3.11+
- Linux: `whois`, `libmagic1`, `libzbar0` (lectura QR), `build-essential` (yara-python compila contra libyara)

## Instalación rápida (VPS con systemd)

```bash
sudo bash deploy/install_vps.sh
sudoedit /opt/ciberbot/.env   # pega TELEGRAM_BOT_TOKEN
sudo systemctl start ciberbot
sudo journalctl -u ciberbot -f
```

## VPS sin systemd (contenedores, HF Spaces, WSL básico)

Si al hacer `systemctl` ves `System has not been booted with systemd`, usa los scripts manuales:

```bash
cd /ruta/al/repo
bash deploy/start.sh        # crea venv, instala deps, arranca en background
bash deploy/status.sh       # estado y últimas líneas del log
bash deploy/stop.sh         # detener
tail -f logs/bot.log        # logs en vivo
```

O simplemente en foreground dentro de `tmux` / `screen`:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edita y pega TELEGRAM_BOT_TOKEN
python -m ciberbot
```

## Docker

```bash
cp .env.example .env  # rellena el token
docker compose up -d --build
```

## Comandos clave

```
/start /menu /help /lang es|en
/dns /whois /ssl /tlsscan /headers /redirects /fingerprint /subs /recon /dnssec /wayback
/ip /rdap /bgp /tor /scan /banner
/hash /hashid /b64e /b64d /hexe /hexd /urle /urld /rot /atbash /magic
/jwt /jwtcrack
/pwgen /passphrase /pwstrength /pwned
/iocs /defang /refang /email /spfdkim /mailheaders
/user /gh
/caesar /vigenere /vbrute /xorbrute /qr /lsb
/cve /cvesearch /epss
/watch /watchlist /unwatch
/note save|list|open|del
/report md|pdf
/yara  (en reply a un archivo)
```

Envía cualquier documento o imagen y el bot responde con hashes, magic, entropía, strings, EXIF, QR, PE/ELF/PDF/OLE info y matches YARA si tienes reglas en `yara_rules/`.

## Aviso ético

Solo para uso defensivo, OSINT pasiva y entrenamiento. **No** la uses contra sistemas o personas sin autorización explícita.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
ruff check ciberbot tests
```
