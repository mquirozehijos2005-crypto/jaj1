"""HTTP de salud para HF Spaces / contenedores que exigen un puerto abierto."""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger(__name__)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a, **_kw) -> None:  # silenciar
        pass

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps({"ok": True, "service": "ciberbot"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(port: int = 7860) -> None:
    def _run() -> None:
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
            log.info("Health server escuchando en :%d", port)
            srv.serve_forever()
        except OSError as exc:
            log.warning("Health server no pudo arrancar: %s", exc)

    t = threading.Thread(target=_run, daemon=True, name="healthserver")
    t.start()
