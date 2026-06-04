"""Métricas Prometheus opcionales."""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class _NoopMetric:
    def labels(self, *a, **kw):  # noqa: D401
        return self

    def inc(self, *_a, **_kw):
        pass

    def observe(self, *_a, **_kw):
        pass


CMD_COUNTER = _NoopMetric()
CMD_LATENCY = _NoopMetric()
ERRORS = _NoopMetric()


def setup_metrics(enabled: bool, port: int) -> None:
    global CMD_COUNTER, CMD_LATENCY, ERRORS
    if not enabled:
        return
    try:
        from prometheus_client import Counter, Histogram, start_http_server
    except ImportError:
        log.warning("prometheus_client no instalado; métricas desactivadas")
        return

    CMD_COUNTER = Counter(
        "ciberbot_commands_total", "Comandos ejecutados", ["command"]
    )
    CMD_LATENCY = Histogram(
        "ciberbot_command_seconds", "Latencia de comandos", ["command"]
    )
    ERRORS = Counter("ciberbot_errors_total", "Errores", ["command"])
    try:
        start_http_server(port)
        log.info("Métricas Prometheus en :%d/metrics", port)
    except OSError as exc:
        log.warning("No se pudo iniciar métricas: %s", exc)
