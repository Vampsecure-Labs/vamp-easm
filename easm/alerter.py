# © VampSecure Studios — VampSecure Labs Security Research Division
"""
alerter.py — Sistema de alertas para vamp-easm
================================================
Envía notificaciones cuando se detectan diffs de severidad CRITICAL o HIGH.

Métodos de alerta disponibles:
  · Webhook HTTP  — POST JSON al endpoint configurado
  · Variable de entorno EASM_ALERT_WEBHOOK como alternativa al flag --alert-webhook

El payload enviado al webhook sigue el esquema estándar VSL compatible
con Slack (incoming webhooks), Discord, Mattermost y cualquier receptor
que acepte JSON.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import List, Optional

from .differ import Diff


# ---------------------------------------------------------------------------
# Severidades que disparan alertas
# ---------------------------------------------------------------------------

SEVERIDADES_ALERTA = {"CRITICAL", "HIGH"}


# ---------------------------------------------------------------------------
# Construcción del payload de alerta
# ---------------------------------------------------------------------------

def _construir_payload(
    target: str,
    diffs: List[Diff],
    scan_id: str,
) -> dict:
    """
    Construye el payload JSON que se envía al webhook.

    El formato es compatible con Slack incoming webhooks mediante el campo
    'text' y 'attachments', y también incluye un campo estructurado 'data'
    con todos los diffs para integraciones personalizadas.

    Parameters
    ----------
    target  : Dominio escaneado
    diffs   : Lista de diffs CRITICAL/HIGH a alertar
    scan_id : UUID del escaneo que generó los diffs

    Returns
    -------
    dict : Payload listo para serializar a JSON
    """
    ahora = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Resumen para Slack/Discord (campo 'text')
    resumen_lineas = [f"*[EASM] Alerta de superficie de ataque — {target}*"]
    for d in diffs:
        emoji = "🚨" if d.severidad == "CRITICAL" else "⚠️"
        resumen_lineas.append(f"{emoji} `{d.categoria}` [{d.severidad}] — {d.activo}")
    resumen = "\n".join(resumen_lineas)

    # Detalles estructurados
    detalles = []
    for d in diffs:
        detalles.append({
            "categoria":   d.categoria,
            "severidad":   d.severidad,
            "activo":      d.activo,
            "descripcion": d.descripcion,
            "evidencia":   d.evidencia,
            "finding_id":  d.finding.id if d.finding else None,
        })

    return {
        "text": resumen,
        "username": "vamp-easm",
        "attachments": [
            {
                "color":  "#c0392b" if any(d.severidad == "CRITICAL" for d in diffs) else "#d35400",
                "title":  f"EASM — {target} — {ahora}",
                "text":   f"scan_id: `{scan_id}`\n{len(diffs)} diffs alertables",
                "footer": "VampSecure Labs · vamp-easm",
            }
        ],
        "data": {
            "tool":     "vamp-easm",
            "version":  "1.0",
            "target":   target,
            "scan_id":  scan_id,
            "ts":       ahora,
            "diffs":    detalles,
        },
    }


# ---------------------------------------------------------------------------
# Envío de alertas
# ---------------------------------------------------------------------------

def enviar_webhook(
    url: str,
    target: str,
    diffs: List[Diff],
    scan_id: str,
    timeout: int = 10,
) -> bool:
    """
    Envía un POST JSON al webhook especificado con los diffs alertables.

    Solo procesa diffs de severidad CRITICAL o HIGH. Si no hay ninguno,
    no envía nada.

    Parameters
    ----------
    url     : URL del webhook receptor
    target  : Dominio escaneado
    diffs   : Todos los diffs del escaneo (se filtra por severidad)
    scan_id : UUID del escaneo
    timeout : Segundos de timeout para la petición HTTP

    Returns
    -------
    bool : True si el envío fue exitoso (HTTP 2xx), False si falló
    """
    diffs_alertables = [d for d in diffs if d.severidad in SEVERIDADES_ALERTA]
    if not diffs_alertables:
        return True  # nada que alertar → éxito

    payload = _construir_payload(target, diffs_alertables, scan_id)
    body    = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "vamp-easm/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        return False
    except Exception:
        return False


def resolver_webhook_url(flag_url: Optional[str]) -> Optional[str]:
    """
    Resuelve la URL del webhook: prioriza el flag CLI, luego la variable
    de entorno EASM_ALERT_WEBHOOK.

    Parameters
    ----------
    flag_url : Valor del flag --alert-webhook (None si no se proporcionó)

    Returns
    -------
    str | None : URL del webhook, o None si no está configurado
    """
    if flag_url:
        return flag_url
    return os.environ.get("EASM_ALERT_WEBHOOK")


def gestionar_alertas(
    webhook_url: Optional[str],
    target: str,
    diffs: List[Diff],
    scan_id: str,
) -> None:
    """
    Punto de entrada principal del sistema de alertas.

    Comprueba si hay diffs alertables y, si existe un webhook configurado,
    intenta el envío. Los errores de envío no interrumpen la ejecución
    del programa principal.

    Parameters
    ----------
    webhook_url : URL del webhook (None → solo log en consola)
    target      : Dominio escaneado
    diffs       : Lista de diffs del escaneo
    scan_id     : UUID del escaneo
    """
    diffs_criticos = [d for d in diffs if d.severidad == "CRITICAL"]
    diffs_altos    = [d for d in diffs if d.severidad == "HIGH"]

    if not diffs_criticos and not diffs_altos:
        return

    if not webhook_url:
        # Sin webhook configurado: el usuario verá los diffs en la salida estándar
        return

    enviar_webhook(webhook_url, target, diffs, scan_id)
