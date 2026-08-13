"""
Sistema de monitoramento e alertas em tempo real do PixCripto (`app/monitoring.py`).

Responsabilidades:
  1. `send_alert` - ponto central de disparo de alertas: persiste no banco
     (`alert_log`), envia via HTTP POST para um webhook configuravel e aplica
     rate-limiting para evitar inundar canais externos com alertas repetidos.
  2. `get_recent_alerts` - consulta o log para auditoria sem webhook externo.

Design de rate-limiting: mapa em memoria {event_type: ultimo_timestamp_enviado},
protegido por lock de thread. Janela configuravel via PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS.
Obs: o rate-limit e por process (em memoria) - em um cluster multi-processo seria
necessario um backend externo (Redis etc.), mas para um node unico e suficiente.

Webhook: disparo assicrono numa daemon thread para NUNCA bloquear o chamador.
Qualquer excecao no POST e capturada e logada - o fluxo principal nunca e interrompido
por falha de entrega de alerta (firewalls, webhooks fora do ar, timeouts etc.).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Dict, List

from . import storage
from .settings import settings

logger = logging.getLogger("pixcripto.monitoring")

_rate_limit_cache: Dict[str, float] = {}
_rate_limit_lock = threading.Lock()
_storage_init_lock = threading.Lock()
_storage_ready = False


def _ensure_storage_ready() -> None:
    global _storage_ready
    if _storage_ready:
        return
    with _storage_init_lock:
        if _storage_ready:
            return
        storage.init_db()
        _storage_ready = True


def send_alert(event_type: str, severity: str, message: str, details: dict) -> None:
    """
    Dispara um alerta de monitoramento.

    Nunca levanta excecao para o chamador - alertas sao best-effort.
    """
    now = time.time()
    rate_limit = settings.alert_rate_limit_seconds

    with _rate_limit_lock:
        last_sent = _rate_limit_cache.get(event_type, 0.0)
        if now - last_sent < rate_limit:
            logger.debug(
                "Alerta '%s' suprimido por rate-limit (janela=%ds, proximo em %.0fs)",
                event_type, rate_limit, rate_limit - (now - last_sent),
            )
            return
        _rate_limit_cache[event_type] = now

    details_json = json.dumps(details, ensure_ascii=False, default=str)
    webhook_url = settings.alert_webhook_url
    _ensure_storage_ready()

    if webhook_url:
        payload = {
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details,
            "timestamp": now,
        }
        threading.Thread(
            target=_post_webhook,
            args=(webhook_url, payload, event_type, severity, message, details_json),
            daemon=True,
            name=f"pixcripto-alert-{event_type}",
        ).start()
        return

    try:
        storage.persist_alert(event_type, severity, message, details_json, False)
    except Exception as exc:
        logger.warning("Falha ao persistir alerta '%s' no banco: %s", event_type, exc)

    _log_locally(severity, event_type, message, details_json)


def _post_webhook(
    webhook_url: str,
    payload: dict,
    event_type: str,
    severity: str,
    message: str,
    details_json: str,
) -> None:
    """Tenta enviar o alerta via HTTP POST e persiste o resultado."""
    delivered = False
    try:
        import httpx

        response = httpx.post(webhook_url, json=payload, timeout=5.0)
        delivered = response.is_success
        if not delivered:
            logger.warning(
                "Webhook de alerta '%s' respondeu HTTP %d - alerta nao confirmado",
                event_type, response.status_code,
            )
    except Exception as exc:
        logger.warning("Falha ao enviar webhook de alerta '%s': %s", event_type, exc)

    try:
        storage.persist_alert(event_type, severity, message, details_json, delivered)
    except Exception as exc:
        logger.warning("Falha ao persistir alerta '%s' apos tentativa de webhook: %s", event_type, exc)

    _log_locally(severity, event_type, message, details_json)


def _log_locally(severity: str, event_type: str, message: str, details_json: str) -> None:
    """Emite o alerta no logger local com o nivel de severidade correto."""
    log_fn = logger.critical if severity == "critical" else logger.warning if severity == "warning" else logger.info
    log_fn("[ALERTA][%s] %s: %s | detalhes=%s", severity.upper(), event_type, message, details_json)


def get_recent_alerts(limit: int = 50) -> List[dict]:
    """Retorna os ultimos N alertas persistidos."""
    try:
        _ensure_storage_ready()
        return storage.list_recent_alerts(limit=limit)
    except Exception as exc:
        logger.warning("Falha ao consultar alert_log: %s", exc)
        return []


def reset_rate_limit_cache() -> None:
    """Limpa o cache de rate-limit - uso exclusivo em testes."""
    with _rate_limit_lock:
        _rate_limit_cache.clear()
    global _storage_ready
    with _storage_init_lock:
        _storage_ready = False
