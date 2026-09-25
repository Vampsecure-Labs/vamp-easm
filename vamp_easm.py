#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_easm.py — Motor de Attack Surface Management Continuo
===========================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Motor de EASM (External Attack Surface Management) continuo que escanea
la superficie de ataque de un dominio objetivo, registra el historial en
SQLite y genera alertas cuando detecta cambios respecto al escaneo anterior.

El diferencial frente a escaneos puntuales es la **continuidad**: cada
ejecución mide deltas (diffs) contra el estado anterior, permitiendo
detectar nuevos activos, cambios de IP, puertos nuevos, certificados
expirados o cambiados.

ESCANEO EN TRES CAPAS
----------------------
  1. DNS/Subdominios  — crt.sh + HackerTarget (urllib stdlib)
  2. Puertos/Servicios — asyncio TCP connect (o nmap con --nmap)
  3. Certificados TLS  — inspección con ssl stdlib (SANs, expiración, fingerprint)

HISTORIAL SQLite
----------------
  vamp_easm.db (directorio de trabajo) — tablas: scans, assets, certs

DIFFS DETECTADOS
----------------
  NUEVO_SUBDOMINIO     HIGH      CERT_EXPIRADO   HIGH/CRITICAL
  NUEVO_PUERTO         MEDIUM    CERT_CAMBIADO   CRITICAL
  SERVICIO_DESAPARECIDO LOW      IP_CAMBIADA     MEDIUM

USO
---
  python vamp_easm.py scan    --target ejemplo.com [--ports top100|22,80,443]
  python vamp_easm.py scan    --target ejemplo.com --shodan-key KEY --shodan-monitor
  python vamp_easm.py history --target ejemplo.com [--limit 10]
  python vamp_easm.py assets  --target ejemplo.com
  python vamp_easm.py export  --target ejemplo.com [--json] [--html]
  python vamp_easm.py monitor --target ejemplo.com --shodan-key KEY --setup
  python vamp_easm.py monitor --target ejemplo.com --shodan-key KEY --check
  python vamp_easm.py monitor --target ejemplo.com --shodan-key KEY --remove
  python vamp_easm.py monitor --shodan-key KEY --list

EXIT CODES
----------
  0 — Sin diffs o diffs de severidad MEDIUM/LOW
  1 — Hay diffs de severidad HIGH
  2 — Hay diffs de severidad CRITICAL

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from easm import scanner, storage, differ, alerter
from vampsec_report import (
    Finding, ReportMeta, VampSecReport,
    add_report_args, meta_from_args,
)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

VERSION = "1.5"
TOOL    = "vamp-easm"
BRAND   = "VampSecure Labs — EASM Continuo"

BANNER = (
    "\n"
    "__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ \n"
    "\\ \\ / /_\\ |  \\/  | _ \\/ __| __/ __| | | | _ \\ __| |    /_\\ | _ ) __|\n"
    " \\ V / _ \\| |\\/| |  _/\\__ \\ _| (__| |_| |   / _|| |__ / _ \\| _ \\__ \\\n"
    "  \\_/_/ \\_\\_|  |_|_|  |___/___\\___|\\___/|_|_\\___|____/_/ \\_\\___/___/\n"
    '  by Antonio Hernandez "Belky" — VampSecure Studios\n'
    "  vamp-easm v1.5 · External Attack Surface Management\n"
    "  ────────────────────────────────────────────────────────────────────────\n"
    "  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal\n"
)

# Mapa de colores de severidad para Rich
_COLORES = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
}

console = Console()


# ---------------------------------------------------------------------------
# Helpers de presentación
# ---------------------------------------------------------------------------

def _badge_sev(sev: str) -> str:
    """Devuelve el texto de severidad con estilo Rich."""
    color = _COLORES.get(sev, "white")
    return f"[{color}]{sev}[/{color}]"


def _ts_ahora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _tabla_diffs(diffs: List[differ.Diff]) -> Table:
    """Construye una tabla Rich con los diffs del escaneo."""
    tabla = Table(
        title="[bold]Diffs detectados[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold dim",
    )
    tabla.add_column("Finding",    style="bold dim", width=12)
    tabla.add_column("Categoría",  style="cyan",     width=24)
    tabla.add_column("Severidad",  width=12)
    tabla.add_column("Activo",     style="white",    no_wrap=False)

    for d in diffs:
        fid = d.finding.id if d.finding else "—"
        tabla.add_row(
            fid,
            d.categoria,
            _badge_sev(d.severidad),
            d.activo,
        )
    return tabla


def _tabla_assets(rows) -> Table:
    """Construye una tabla Rich con los activos de un target."""
    tabla = Table(
        title="[bold]Activos conocidos[/bold]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold dim",
    )
    tabla.add_column("Subdominio",     style="cyan",    no_wrap=False)
    tabla.add_column("IP",             style="white",   width=18)
    tabla.add_column("Puerto",         style="yellow",  width=8)
    tabla.add_column("Protocolo",      style="dim",     width=8)
    tabla.add_column("Servicio",       style="green",   width=14)
    tabla.add_column("Primera vista",  style="dim",     width=20)
    tabla.add_column("Última vista",   style="dim",     width=20)

    for r in rows:
        tabla.add_row(
            r["subdominio"],
            r["ip"] or "—",
            str(r["puerto"]) if r["puerto"] else "—",
            r["protocolo"] or "tcp",
            r["servicio"] or "—",
            r["primera_vista"][:16] if r["primera_vista"] else "—",
            r["ultima_vista"][:16]  if r["ultima_vista"]  else "—",
        )
    return tabla


def _tabla_historial(rows) -> Table:
    """Construye una tabla Rich con el historial de escaneos."""
    tabla = Table(
        title="[bold]Historial de escaneos[/bold]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold dim",
    )
    tabla.add_column("Inicio",      style="cyan",  width=20)
    tabla.add_column("Fin",         style="dim",   width=20)
    tabla.add_column("Activos",     style="green", width=10)
    tabla.add_column("Diffs",       style="yellow",width=8)
    tabla.add_column("Scan ID",     style="dim",   width=38)

    for r in rows:
        tabla.add_row(
            r["ts_start"][:16] if r["ts_start"] else "—",
            r["ts_end"][:16]   if r["ts_end"]   else "en curso",
            str(r["assets_found"]),
            str(r["diffs_found"]),
            r["id"],
        )
    return tabla


# ---------------------------------------------------------------------------
# Integración Shodan  (v1.3)
# ---------------------------------------------------------------------------

# Puertos considerados sensibles para emitir hallazgo MEDIUM
_SHODAN_PUERTOS_SENSIBLES = {21, 23, 445, 3389, 1433, 3306, 5432, 5900, 6379, 27017, 9200}


class ShodanEASMEnricher:
    """
    Enriquecimiento EASM con la API REST de Shodan por IP.

    Para cada IP descubierta en el escaneo consulta
    https://api.shodan.io/shodan/host/<ip>?key=<api_key>
    y añade hallazgos al listado de findings del escaneo:

      - Puerto sensible abierto           → MEDIUM
      - Vulnerabilidades en campo 'vulns' → HIGH
      - Hostname alternativo              → INFO

    Límite: 10 IPs máximo por invocación (para no agotar créditos API).
    """

    _HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
    _MAX_IPS   = 10

    def __init__(self, api_key: str) -> None:
        self._key = api_key

    def _enrich_with_shodan(
        self,
        ips_or_hosts: list,
        api_key: str,
        findings: list,
    ) -> None:
        """
        Enriquece la lista de findings con datos Shodan para cada IP.

        Modifica findings in-place añadiendo los hallazgos relevantes.

        Parámetros
        ----------
        ips_or_hosts : list[str]  — IPs o nombres de host a consultar
        api_key      : str        — Clave API de Shodan
        findings     : list       — Lista de Finding a la que se añaden los hallazgos
        """
        import urllib.request as _ureq
        import json as _json

        # Filtrar solo IPs (IPv4 básico) y descartar repeticiones
        ips_validas = []
        vistas: set = set()
        for h in ips_or_hosts:
            h = h.strip()
            partes = h.split(".")
            if len(partes) == 4 and all(p.isdigit() for p in partes) and h not in vistas:
                ips_validas.append(h)
                vistas.add(h)

        ips_validas = ips_validas[: self._MAX_IPS]

        idx_base = max((int(f.id.split("-")[-1]) for f in findings if "-" in f.id), default=0)

        for i, ip in enumerate(ips_validas, start=1):
            url = self._HOST_URL.format(ip=ip, key=api_key)
            try:
                req = _ureq.Request(
                    url,
                    headers={"User-Agent": f"vamp-easm/{VERSION}"},
                )
                with _ureq.urlopen(req, timeout=15) as resp:
                    codigo = resp.status
                    if codigo == 401:
                        findings.append(Finding(
                            id          = f"EASM-SHD-{idx_base + i:03d}",
                            title       = "API key Shodan inválida o sin créditos",
                            severity    = "INFO",
                            description = "La clave API de Shodan devolvió 401. Verificar validez y cuota.",
                            evidence    = f"URL: {self._HOST_URL.format(ip=ip, key='***')}",
                            affected    = ip,
                            remediation = "Comprobar la clave API en https://account.shodan.io/",
                            tags        = ["shodan", "easm"],
                        ))
                        return   # Si 401, todas las demás peticiones fallarán también
                    if codigo == 404:
                        # IP no indexada en Shodan: INFO silencioso
                        continue
                    if codigo != 200:
                        continue
                    data = _json.loads(resp.read())
            except Exception:
                # Error de red o timeout: continuar con la siguiente IP
                continue

            puertos:   list = data.get("ports", []) or []
            _vr = data.get("vulns", {}) or {}
            # La API puede devolver lista o dict según versión del endpoint
            vulns_raw: dict = {v: {} for v in _vr} if isinstance(_vr, list) else _vr
            hostnames: list = data.get("hostnames", []) or []
            org:       str  = data.get("org", "") or ""
            sistema:   str  = data.get("os", "") or ""

            # Hallazgo: puertos sensibles abiertos
            sensibles = [p for p in puertos if p in _SHODAN_PUERTOS_SENSIBLES]
            for puerto in sensibles:
                idx_base += 1
                findings.append(Finding(
                    id          = f"EASM-SHD-{idx_base:03d}",
                    title       = f"Puerto sensible {puerto} abierto según Shodan — {ip}",
                    severity    = "MEDIUM",
                    description = (
                        f"Shodan ha indexado el puerto {puerto} como abierto en la IP {ip}. "
                        "Este puerto corresponde a un servicio de alto riesgo si está expuesto "
                        "sin control de acceso."
                    ),
                    evidence    = (
                        f"IP: {ip}\n"
                        f"Puerto: {puerto}\n"
                        f"Org: {org or '—'}\n"
                        f"OS: {sistema or '—'}\n"
                        f"Fuente: Shodan (datos históricos — verificar estado actual)"
                    ),
                    affected    = f"{ip}:{puerto}",
                    remediation = (
                        f"Verificar si el puerto {puerto} en {ip} debe estar accesible desde Internet. "
                        "Aplicar reglas de firewall para restringir el acceso por IP de origen. "
                        "Actualizar el servicio a la última versión segura."
                    ),
                    tags        = ["shodan", "easm", "exposed-port"],
                ))

            # Hallazgo: vulnerabilidades reportadas por Shodan (campo 'vulns')
            if vulns_raw:
                cves_str = ", ".join(list(vulns_raw.keys())[:10])
                idx_base += 1
                findings.append(Finding(
                    id          = f"EASM-SHD-{idx_base:03d}",
                    title       = f"Vulnerabilidades Shodan en {ip}: {cves_str[:60]}",
                    severity    = "HIGH",
                    description = (
                        f"Shodan reporta {len(vulns_raw)} vulnerabilidad(es) conocida(s) en la IP {ip}. "
                        "Estas vulnerabilidades pueden estar presentes en los servicios actualmente "
                        "expuestos según el índice de Shodan."
                    ),
                    evidence    = (
                        f"IP: {ip}\n"
                        f"Vulnerabilidades Shodan: {cves_str}\n"
                        f"Org: {org or '—'}\n"
                        f"Fuente: Shodan — los datos pueden tener latencia de semanas"
                    ),
                    affected    = ip,
                    remediation = (
                        "Verificar el estado actual de las vulnerabilidades listadas en los servicios "
                        "del host. Consultar el NVD para detalles de parches y aplicarlos. "
                        "Referencia: https://nvd.nist.gov/"
                    ),
                    cve         = list(vulns_raw.keys())[0] if vulns_raw else None,
                    tags        = ["shodan", "easm", "cve", "vulnerability"],
                ))

            # Hallazgo INFO: hostname alternativo reportado por Shodan
            for hostname in hostnames[:3]:
                idx_base += 1
                findings.append(Finding(
                    id          = f"EASM-SHD-{idx_base:03d}",
                    title       = f"Shodan reporta hostname alternativo: {hostname}",
                    severity    = "INFO",
                    description = (
                        f"Shodan indexa el hostname '{hostname}' para la IP {ip}. "
                        "Puede indicar servicios adicionales o dominios compartiendo esta IP."
                    ),
                    evidence    = f"IP: {ip}\nHostname Shodan: {hostname}",
                    affected    = ip,
                    remediation = "Verificar que el hostname corresponde a infraestructura autorizada.",
                    tags        = ["shodan", "easm", "hostname"],
                ))


# ---------------------------------------------------------------------------
# Integración Shodan Monitor (v1.5)
# ---------------------------------------------------------------------------

class ShodanMonitorManager:
    """
    Gestión de alertas Shodan Monitor para monitorización automática de IPs.

    Shodan Monitor crea alertas que se activan cuando Shodan detecta nuevos
    puertos abiertos, vulnerabilidades o cambios en las IPs monitorizadas.

    Endpoints:
      GET    /shodan/alert/info?key=        → lista todas las alertas activas
      POST   /shodan/alert?key=             → crea una alerta nueva
      GET    /shodan/alert/{id}/info?key=   → estado y matches de una alerta
      DELETE /shodan/alert/{id}?key=        → elimina una alerta
    """

    _BASE   = "https://api.shodan.io/shodan/alert"
    _ESTADO = Path.home() / ".config" / "vampsec" / "easm_shodan_monitor.json"

    def __init__(self, api_key: str) -> None:
        self._key = api_key

    def _peticion(self, metodo: str, url: str, body: Optional[dict] = None) -> dict:
        """Realiza una petición HTTP a la API de Shodan Monitor."""
        import urllib.request as _ureq
        import urllib.error   as _uerr
        import json           as _json

        data_bytes = None
        if body is not None:
            data_bytes = _json.dumps(body).encode()

        req = _ureq.Request(
            url,
            data=data_bytes,
            method=metodo,
            headers={
                "User-Agent":   f"vamp-easm/{VERSION}",
                "Accept":       "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with _ureq.urlopen(req, timeout=20) as resp:
                contenido = resp.read()
                if not contenido:
                    return {}
                return _json.loads(contenido)
        except _uerr.HTTPError as e:
            return {"__error__": e.code, "__msg__": e.reason}
        except Exception as e:
            return {"__error__": -1, "__msg__": str(e)}

    def listar_alertas(self) -> list:
        """Devuelve la lista de todas las alertas Shodan Monitor activas."""
        resultado = self._peticion("GET", f"{self._BASE}/info?key={self._key}")
        if "__error__" in resultado:
            return []
        if isinstance(resultado, list):
            return resultado
        return resultado.get("alerts", [])

    def crear_alerta(self, nombre: str, ips: List[str]) -> Optional[dict]:
        """
        Crea una alerta Shodan Monitor para la lista de IPs.

        Parámetros
        ----------
        nombre : str       — Nombre identificativo de la alerta
        ips    : list[str] — Lista de IPs o rangos CIDR a monitorizar

        Devuelve el dict de la alerta creada, o None si hay error.
        """
        ips_filtradas = [ip.strip() for ip in ips if ip.strip()]
        if not ips_filtradas:
            return None

        body = {
            "name":    nombre,
            "filters": {"ip": ips_filtradas},
        }
        resultado = self._peticion("POST", f"{self._BASE}?key={self._key}", body=body)
        if "__error__" in resultado:
            return None
        return resultado

    def obtener_alerta(self, alert_id: str) -> Optional[dict]:
        """Obtiene el estado actual y los matches de una alerta por ID."""
        resultado = self._peticion("GET", f"{self._BASE}/{alert_id}/info?key={self._key}")
        if "__error__" in resultado:
            return None
        return resultado

    def eliminar_alerta(self, alert_id: str) -> bool:
        """Elimina una alerta Shodan Monitor. Devuelve True si tuvo éxito."""
        resultado = self._peticion("DELETE", f"{self._BASE}/{alert_id}?key={self._key}")
        return resultado.get("success", False) or "__error__" not in resultado

    def _cargar_estado(self) -> dict:
        """Carga el estado persistido en ~/.config/vampsec/easm_shodan_monitor.json."""
        import json as _j
        if self._ESTADO.exists():
            try:
                return _j.loads(self._ESTADO.read_text())
            except Exception:
                return {}
        return {}

    def _guardar_estado(self, estado: dict) -> None:
        """Persiste el estado en ~/.config/vampsec/easm_shodan_monitor.json."""
        import json as _j
        self._ESTADO.parent.mkdir(parents=True, exist_ok=True)
        self._ESTADO.write_text(_j.dumps(estado, indent=2, ensure_ascii=False))

    def setup_para_target(self, target: str, ips: List[str]) -> Optional[str]:
        """
        Crea (o reutiliza) una alerta Shodan Monitor para el target.

        Devuelve el ID de la alerta, o None si no se pudo crear.
        """
        estado = self._cargar_estado()

        # Reutilizar alerta existente si sigue activa en Shodan
        if target in estado:
            alert_id = estado[target].get("alert_id")
            if alert_id and self.obtener_alerta(alert_id):
                console.print(
                    f"   [dim]Alerta Shodan Monitor ya existente: "
                    f"ID [bold]{alert_id}[/bold][/dim]"
                )
                return alert_id

        nombre  = f"vamp-easm:{target}"
        alerta  = self.crear_alerta(nombre, ips)
        if not alerta:
            return None

        alert_id = alerta.get("id") or alerta.get("alert_id")
        if not alert_id:
            return None

        estado[target] = {
            "alert_id":     alert_id,
            "alert_name":   nombre,
            "ips":          ips,
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "last_checked": None,
            "last_matches": {},
        }
        self._guardar_estado(estado)
        return alert_id

    def check_matches(self, target: str, findings: List) -> None:
        """
        Consulta la alerta activa del target y genera findings por cambios.

        Compara los matches actuales con el estado previo persistido en disco
        y emite hallazgos para nuevos puertos o CVEs detectados desde la
        última comprobación. Modifica findings in-place.
        """
        estado = self._cargar_estado()
        if target not in estado:
            findings.append(Finding(
                id          = "EASM-MON-001",
                title       = "Shodan Monitor no configurado para este target",
                severity    = "INFO",
                description = (
                    "No hay ninguna alerta Shodan Monitor activa para este target. "
                    "Ejecuta 'vamp-easm monitor --target ... --setup' para crearla."
                ),
                evidence    = f"Target: {target}\nEstado: sin alerta",
                affected    = target,
                remediation = (
                    "Ejecutar: vamp-easm monitor --target <dominio> "
                    "--shodan-key <KEY> --setup"
                ),
                tags        = ["shodan-monitor", "easm"],
            ))
            return

        info_target = estado[target]
        alert_id    = info_target.get("alert_id")
        if not alert_id:
            return

        alerta = self.obtener_alerta(alert_id)
        if alerta is None:
            findings.append(Finding(
                id          = "EASM-MON-002",
                title       = f"Alerta Shodan Monitor {alert_id} no encontrada",
                severity    = "HIGH",
                description = (
                    f"La alerta Shodan Monitor con ID '{alert_id}' no responde. "
                    "Puede haber sido eliminada o expirado. Recrear con '--setup'."
                ),
                evidence    = f"Alert ID: {alert_id}\nTarget: {target}",
                affected    = target,
                remediation = (
                    "Ejecutar: vamp-easm monitor --target <dominio> "
                    "--shodan-key <KEY> --setup"
                ),
                tags        = ["shodan-monitor", "easm"],
            ))
            return

        # Construir mapa {ip: {ports, vulns}} de los matches actuales
        matches_actuales: dict = {}
        for match in alerta.get("matches", []) or []:
            ip = match.get("ip_str", "")
            if not ip:
                continue
            puertos = match.get("port", [])
            if isinstance(puertos, int):
                puertos = [puertos]
            cves = list((match.get("vulns", {}) or {}).keys())
            if ip not in matches_actuales:
                matches_actuales[ip] = {"ports": [], "vulns": []}
            for p in puertos:
                if p not in matches_actuales[ip]["ports"]:
                    matches_actuales[ip]["ports"].append(p)
            for c in cves:
                if c not in matches_actuales[ip]["vulns"]:
                    matches_actuales[ip]["vulns"].append(c)

        # Índice base para IDs de hallazgos
        matches_previos = info_target.get("last_matches", {}) or {}
        idx_base = 10

        for ip, datos in matches_actuales.items():
            puertos_previos = set(matches_previos.get(ip, {}).get("ports", []))
            vulns_previas   = set(matches_previos.get(ip, {}).get("vulns", []))

            # Nuevos puertos detectados
            for puerto in datos["ports"]:
                if puerto in puertos_previos:
                    continue
                idx_base += 1
                sev = "HIGH" if puerto in _SHODAN_PUERTOS_SENSIBLES else "MEDIUM"
                findings.append(Finding(
                    id          = f"EASM-MON-{idx_base:03d}",
                    title       = f"Shodan Monitor: nuevo puerto {puerto} en {ip}",
                    severity    = sev,
                    description = (
                        f"Shodan Monitor alertó de la apertura del puerto {puerto} "
                        f"en {ip}. No estaba presente en la última comprobación."
                    ),
                    evidence    = (
                        f"IP: {ip}\n"
                        f"Puerto nuevo: {puerto}\n"
                        f"Puertos previos: "
                        f"{', '.join(str(p) for p in sorted(puertos_previos)) or '—'}\n"
                        f"Fuente: Shodan Monitor (alerta {alert_id})"
                    ),
                    affected    = f"{ip}:{puerto}",
                    remediation = (
                        f"Verificar inmediatamente el puerto {puerto} en {ip}. "
                        "Si no es un servicio autorizado, aplicar regla de firewall."
                    ),
                    tags        = ["shodan-monitor", "easm", "new-port"],
                ))

            # Nuevas CVEs detectadas
            vulns_nuevas = [v for v in datos["vulns"] if v not in vulns_previas]
            if vulns_nuevas:
                cves_str = ", ".join(vulns_nuevas[:10])
                idx_base += 1
                sev = "CRITICAL" if len(vulns_nuevas) >= 3 else "HIGH"
                findings.append(Finding(
                    id          = f"EASM-MON-{idx_base:03d}",
                    title       = (
                        f"Shodan Monitor: {len(vulns_nuevas)} CVE(s) "
                        f"nueva(s) en {ip}"
                    ),
                    severity    = sev,
                    description = (
                        f"Shodan Monitor reporta {len(vulns_nuevas)} nueva(s) "
                        f"vulnerabilidad(es) en {ip}: {cves_str[:100]}."
                    ),
                    evidence    = (
                        f"IP: {ip}\n"
                        f"CVEs nuevas: {cves_str}\n"
                        f"CVEs previas: "
                        f"{', '.join(sorted(vulns_previas)[:10]) or '—'}\n"
                        f"Fuente: Shodan Monitor (alerta {alert_id})"
                    ),
                    affected    = ip,
                    remediation = (
                        "Consultar NVD para detalles y aplicar parches. "
                        "Referencia: https://nvd.nist.gov/"
                    ),
                    cve         = vulns_nuevas[0],
                    tags        = ["shodan-monitor", "easm", "cve", "new-vuln"],
                ))

        # IPs que desaparecen de matches (puertos posiblemente cerrados)
        for ip in matches_previos:
            if ip not in matches_actuales and matches_previos[ip].get("ports"):
                idx_base += 1
                findings.append(Finding(
                    id          = f"EASM-MON-{idx_base:03d}",
                    title       = f"Shodan Monitor: {ip} sin matches activos",
                    severity    = "INFO",
                    description = (
                        f"La IP {ip} ya no aparece en los matches de Shodan Monitor. "
                        "Los puertos previamente detectados podrían haberse cerrado."
                    ),
                    evidence    = (
                        f"IP: {ip}\n"
                        f"Puertos previos: "
                        f"{', '.join(str(p) for p in matches_previos[ip].get('ports', []))}\n"
                        "Fuente: Shodan Monitor"
                    ),
                    affected    = ip,
                    remediation = (
                        "Verificar el estado actual del host. "
                        "Si es intencional, actualizar el inventario."
                    ),
                    tags        = ["shodan-monitor", "easm", "port-closed"],
                ))

        # Persistir estado actualizado
        info_target["last_checked"] = datetime.now(timezone.utc).isoformat()
        info_target["last_matches"] = matches_actuales
        estado[target] = info_target
        self._guardar_estado(estado)


# ---------------------------------------------------------------------------
# Integración Censys (v1.4)
# ---------------------------------------------------------------------------

# URL base de la API Censys v2
_CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"

# Puertos considerados sensibles para enriquecer hallazgos Censys
_CENSYS_PUERTOS_SENSIBLES = {21, 22, 23, 25, 80, 443, 445, 3389, 1433, 3306, 5432, 5900, 6379, 8080, 8443, 27017, 9200}


class CensysEASMEnricher:
    """
    Enriquecimiento EASM con la API Censys v2.

    Consulta el endpoint de búsqueda de hosts Censys usando la query
    ``parsed.names:<dominio>`` para detectar hosts indexados por Censys
    que no fueron descubiertos por crt.sh/HackerTarget.

    Hallazgos emitidos:
      - CENSYS_HOST_EXPOSED: host encontrado por Censys pero no en el
        escaneo activo (superficie no visible para la organización).
      - Puerto sensible abierto según Censys: MEDIUM.

    Límite: 1 petición por segundo (rate limit de la API gratuita).
    Resultados por página: 100 hosts (máximo permitido por la API).
    """

    _MAX_PAGINAS = 3   # máximo de páginas (300 hosts) por invocación

    def __init__(self, censys_id: str, censys_secret: str) -> None:
        self._id     = censys_id
        self._secret = censys_secret

    def _auth_header(self) -> str:
        """Devuelve el valor de la cabecera Authorization (Basic Auth)."""
        import base64 as _b64
        creds = f"{self._id}:{self._secret}".encode()
        return "Basic " + _b64.b64encode(creds).decode()

    def enriquecer(
        self,
        dominio: str,
        ips_conocidas: set,
        findings: list,
    ) -> None:
        """
        Consulta Censys por el dominio y añade hallazgos a la lista recibida.

        Parámetros
        ----------
        dominio       : str        — Dominio objetivo
        ips_conocidas : set[str]   — IPs ya descubiertas por el escaneo
        findings      : list       — Lista de Finding a la que se añaden hallazgos
        """
        import urllib.request as _ureq
        import urllib.error   as _uerr
        import json           as _json
        import time           as _time

        auth = self._auth_header()
        idx_base = max(
            (int(f.id.split("-")[-1]) for f in findings if "-" in f.id),
            default=0,
        )

        cursor: str | None = None
        pagina = 0
        hosts_censys: list[dict] = []

        while pagina < self._MAX_PAGINAS:
            # Construir URL con paginación
            params = f"q=parsed.names%3A{_ureq.quote(dominio)}&per_page=100"
            if cursor:
                params += f"&cursor={_ureq.quote(cursor)}"
            url = f"{_CENSYS_SEARCH_URL}?{params}"

            try:
                req = _ureq.Request(
                    url,
                    headers={
                        "Authorization": auth,
                        "User-Agent":    f"vamp-easm/{VERSION}",
                        "Accept":        "application/json",
                    },
                )
                with _ureq.urlopen(req, timeout=20) as resp:
                    if resp.status != 200:
                        break
                    data = _json.loads(resp.read())
            except _uerr.HTTPError as e:
                if e.code in (401, 403):
                    findings.append(Finding(
                        id          = f"EASM-CNS-{idx_base + 1:03d}",
                        title       = "Credenciales Censys inválidas o sin permisos",
                        severity    = "INFO",
                        description = (
                            f"La API Censys devolvió {e.code}. "
                            "Verificar --censys-id y --censys-secret."
                        ),
                        evidence    = f"URL: {_CENSYS_SEARCH_URL}",
                        affected    = dominio,
                        remediation = "Comprobar credenciales en https://search.censys.io/account",
                        tags        = ["censys", "easm"],
                    ))
                break
            except Exception:
                break

            lote = data.get("result", {}).get("hits", [])
            hosts_censys.extend(lote)
            cursor = data.get("result", {}).get("links", {}).get("next")
            pagina += 1

            if not cursor or not lote:
                break

            # Respetar el límite de 1 req/seg de la API gratuita
            _time.sleep(1.0)

        # Procesar cada host devuelto por Censys
        for host in hosts_censys:
            ip      = host.get("ip", "")
            nombres = host.get("names", []) or []
            servicios = host.get("services", []) or []
            puertos = [s.get("port") for s in servicios if s.get("port")]

            # Si la IP no fue encontrada por crt.sh/HackerTarget → hallazgo
            if ip and ip not in ips_conocidas:
                idx_base += 1
                nombres_str = ", ".join(nombres[:5]) or "—"
                puertos_str = ", ".join(str(p) for p in puertos[:10]) or "—"
                findings.append(Finding(
                    id          = f"EASM-CNS-{idx_base:03d}",
                    title       = f"Host expuesto detectado por Censys (no en escaneo activo) — {ip}",
                    severity    = "HIGH",
                    description = (
                        f"Censys indexa el host {ip} asociado al dominio '{dominio}' "
                        "pero no fue descubierto por crt.sh ni HackerTarget. Puede "
                        "tratarse de infraestructura shadow, activos olvidados o "
                        "exposición no intencionada."
                    ),
                    evidence    = (
                        f"IP: {ip}\n"
                        f"Nombres DNS (Censys): {nombres_str}\n"
                        f"Puertos indexados: {puertos_str}\n"
                        f"Dominio consultado: {dominio}\n"
                        "Fuente: Censys API v2 (datos históricos — verificar estado actual)"
                    ),
                    affected    = ip,
                    remediation = (
                        "Verificar si el activo pertenece a la organización. "
                        "Si es legítimo, incluirlo en el inventario de superficie de ataque. "
                        "Si no, investigar posible shadow IT o activo olvidado."
                    ),
                    tags        = ["censys", "easm", "CENSYS_HOST_EXPOSED"],
                ))

            # Puertos sensibles abiertos según Censys (para IPs conocidas y nuevas)
            sensibles = [p for p in puertos if p in _CENSYS_PUERTOS_SENSIBLES]
            for puerto in sensibles:
                # Evitar duplicados con hallazgos Shodan
                ya_reportado = any(
                    f"{ip}:{puerto}" in (getattr(f, "affected", "") or "")
                    for f in findings
                )
                if ya_reportado:
                    continue
                idx_base += 1
                findings.append(Finding(
                    id          = f"EASM-CNS-{idx_base:03d}",
                    title       = f"Puerto sensible {puerto} abierto según Censys — {ip}",
                    severity    = "MEDIUM",
                    description = (
                        f"Censys ha indexado el puerto {puerto} como abierto en "
                        f"la IP {ip}. Este puerto corresponde a un servicio de "
                        "alto riesgo si está expuesto sin control de acceso."
                    ),
                    evidence    = (
                        f"IP: {ip}  Puerto: {puerto}\n"
                        f"Servicios Censys: {', '.join(s.get('service_name','?') for s in servicios if s.get('port') == puerto) or '—'}\n"
                        "Fuente: Censys API v2"
                    ),
                    affected    = f"{ip}:{puerto}",
                    remediation = (
                        f"Comprobar si el puerto {puerto} debe estar expuesto a internet. "
                        "Si no es necesario, restringir acceso con firewall."
                    ),
                    tags        = ["censys", "easm", "port"],
                ))


# ---------------------------------------------------------------------------
# Comando: scan
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """
    Ejecuta un escaneo completo del target, guarda resultados en SQLite,
    calcula diffs respecto al escaneo anterior y muestra los hallazgos.

    Returns
    -------
    int : Código de salida (0 limpio, 1 HIGH, 2 CRITICAL)
    """
    target = args.target

    # Inicializar la base de datos
    storage.inicializar_db()

    console.print(Panel(
        f"[bold cyan]vamp-easm v{VERSION}[/bold cyan]  ·  {BRAND}\n"
        f"Target: [bold]{target}[/bold]  ·  {_ts_ahora()}",
        border_style="dim",
    ))

    # ── Registrar inicio del escaneo ──────────────────────────────────────
    scan_id = storage.nuevo_scan(target)

    # ── Determinar lista de puertos ───────────────────────────────────────
    if args.ports and args.ports != "top100":
        try:
            puertos = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            console.print("[red]Error:[/red] --ports debe ser 'top100' o una lista de puertos (ej: 22,80,443)")
            return 1
    else:
        puertos = scanner.TOP_100_PORTS

    # ── Capa 1: subdominios ───────────────────────────────────────────────
    console.print("\n[cyan]►[/cyan] [bold]Fase 1:[/bold] Enumeración de subdominios (crt.sh + HackerTarget)…")
    resultado = scanner.ejecutar_escaneo(
        target=target,
        puertos=puertos,
        usar_nmap=getattr(args, "nmap", False),
    )

    # Guardar subdominios en SQLite (sin puerto)
    for sub in resultado.subdominios:
        ip = sub.ips[0] if sub.ips else None
        storage.upsert_asset(
            target=target,
            subdominio=sub.nombre,
            scan_id=scan_id,
            ip=ip,
        )
    console.print(f"   {len(resultado.subdominios)} subdominios encontrados.")

    # ── Capa 2: puertos ───────────────────────────────────────────────────
    console.print("[cyan]►[/cyan] [bold]Fase 2:[/bold] Escaneo de puertos…")
    for pa in resultado.puertos:
        # Resolver IP del host si es posible
        ip_pa = None
        for sub in resultado.subdominios:
            if sub.nombre == pa.host:
                ip_pa = sub.ips[0] if sub.ips else None
                break
        storage.upsert_asset(
            target=target,
            subdominio=pa.host,
            scan_id=scan_id,
            ip=ip_pa,
            puerto=pa.puerto,
            protocolo=pa.protocolo,
            servicio=pa.servicio,
        )
    console.print(f"   {len(resultado.puertos)} puertos abiertos encontrados.")

    # ── Capa 3: certificados ──────────────────────────────────────────────
    console.print("[cyan]►[/cyan] [bold]Fase 3:[/bold] Inspección de certificados TLS…")
    for cert in resultado.certs:
        if cert.error:
            continue
        storage.insertar_cert(
            target=target,
            host=cert.host,
            scan_id=scan_id,
            issued_to=cert.issued_to,
            issuer=cert.issuer,
            not_after=cert.not_after,
            sans=",".join(cert.sans) if cert.sans else None,
            fingerprint=cert.fingerprint,
            autofirmado=cert.autofirmado,
        )
    certs_ok = [c for c in resultado.certs if not c.error]
    console.print(f"   {len(certs_ok)} certificados inspeccionados.")

    # ── Nota Shodan al inicio (si no se proporcionó clave) ───────────────────
    shodan_key_easm = (
        getattr(args, "shodan_key", None)
        or __import__("os").environ.get("SHODAN_API_KEY", "")
    )
    if not shodan_key_easm:
        console.print(
            "[dim]  ℹ Shodan no activo — usa --shodan-key para enriquecer con datos Shodan[/dim]"
        )

    # Leer claves Censys (opcional, v1.4)
    censys_id     = getattr(args, "censys_id",     None) or __import__("os").environ.get("CENSYS_API_ID",     "")
    censys_secret = getattr(args, "censys_secret", None) or __import__("os").environ.get("CENSYS_API_SECRET", "")
    if not (censys_id and censys_secret):
        console.print(
            "[dim]  ℹ Censys no activo — usa --censys-id y --censys-secret para enriquecer con datos Censys[/dim]"
        )

    # ── Motor de diffs ────────────────────────────────────────────────────
    console.print("\n[cyan]►[/cyan] [bold]Calculando diffs respecto al escaneo anterior…[/bold]")
    scan_anterior = storage.ultimo_scan(target)
    # El último scan completado puede ser el actual si ya acabó (no debería),
    # así que buscamos el penúltimo para comparar
    historial = storage.historial_scans(target, limit=5)
    scan_id_prev: Optional[str] = None
    for row in historial:
        if row["id"] != scan_id:
            scan_id_prev = row["id"]
            break

    motor = differ.MotorDiff(
        target=target,
        scan_id=scan_id,
        scan_id_prev=scan_id_prev,
        storage=storage,
    )
    diffs = motor.calcular()

    # Contar totales de activos
    assets_total = len(resultado.subdominios) + len(resultado.puertos)

    # Cerrar escaneo en SQLite
    storage.cerrar_scan(scan_id, assets_found=assets_total, diffs_found=len(diffs))

    # ── Enriquecimiento Shodan (opcional) ────────────────────────────────────
    findings_shodan: List[Finding] = []
    if shodan_key_easm:
        console.print("\n[cyan]►[/cyan] [bold]Enriquecimiento Shodan (por IP)…[/bold]")
        ips_descubiertas = []
        for sub in resultado.subdominios:
            if sub.ips:
                ips_descubiertas.extend(sub.ips)
        if ips_descubiertas:
            enricher = ShodanEASMEnricher(shodan_key_easm)
            enricher._enrich_with_shodan(ips_descubiertas, shodan_key_easm, findings_shodan)
            console.print(
                f"   {len([f for f in findings_shodan if f.severity in ('HIGH','MEDIUM')])} "
                f"hallazgos Shodan (MEDIUM+HIGH) · {len(findings_shodan)} totales"
            )
        else:
            console.print("   [dim]Sin IPs resueltas para consultar Shodan.[/dim]")

    # ── Enriquecimiento Censys (v1.4, opcional) ───────────────────────────
    findings_censys: List[Finding] = []
    if censys_id and censys_secret:
        console.print("\n[cyan]►[/cyan] [bold]Enriquecimiento Censys (por dominio)…[/bold]")
        # Recopilar IPs ya conocidas del escaneo activo
        ips_conocidas: set = set()
        for sub in resultado.subdominios:
            if sub.ips:
                ips_conocidas.update(sub.ips)

        censys_enricher = CensysEASMEnricher(censys_id, censys_secret)
        censys_enricher.enriquecer(target, ips_conocidas, findings_censys)
        nuevos = len([f for f in findings_censys if "CENSYS_HOST_EXPOSED" in (getattr(f, "tags", None) or [])])
        console.print(
            f"   {nuevos} host(s) nuevos (CENSYS_HOST_EXPOSED) · "
            f"{len(findings_censys)} hallazgos totales Censys"
        )

    # ── Shodan Monitor: verificar alertas activas (v1.5) ─────────────────
    findings_monitor: List[Finding] = []
    if shodan_key_easm and getattr(args, "shodan_monitor", False):
        console.print("\n[cyan]►[/cyan] [bold]Shodan Monitor: verificando alertas activas…[/bold]")
        mon_mgr = ShodanMonitorManager(shodan_key_easm)
        mon_mgr.check_matches(target, findings_monitor)
        nuevos_mon = [
            f for f in findings_monitor
            if "new-port" in (getattr(f, "tags", None) or [])
            or "new-vuln" in (getattr(f, "tags", None) or [])
        ]
        console.print(
            f"   {len(nuevos_mon)} nueva(s) amenaza(s) Shodan Monitor · "
            f"{len(findings_monitor)} hallazgos totales"
        )

    # ── Mostrar resultados ────────────────────────────────────────────────
    if diffs:
        console.print(_tabla_diffs(diffs))
    else:
        if scan_id_prev:
            console.print("\n[green]✓ Sin diffs respecto al escaneo anterior. Superficie estable.[/green]")
        else:
            console.print("\n[blue]ℹ Primer escaneo del target — baseline registrado. No hay escaneo anterior para comparar.[/blue]")

    # ── Alertas ───────────────────────────────────────────────────────────
    webhook_url = alerter.resolver_webhook_url(getattr(args, "alert_webhook", None))
    alerter.gestionar_alertas(webhook_url, target, diffs, scan_id)

    # ── Exportar informes si se pidió ─────────────────────────────────────
    findings = [d.finding for d in diffs if d.finding is not None]
    # Incluir hallazgos Shodan en el informe si los hay
    findings.extend(findings_shodan)
    # Incluir hallazgos Censys en el informe si los hay (v1.4)
    findings.extend(findings_censys)
    # Incluir hallazgos Shodan Monitor en el informe si los hay (v1.5)
    findings.extend(findings_monitor)
    if findings:
        meta = meta_from_args(args, tool=TOOL, version=VERSION)
        meta.scope = target
        informe = VampSecReport(meta, findings)

        if getattr(args, "json", False):
            fname = f"easm_{target}_{scan_id[:8]}.json"
            informe.to_json(fname)
            console.print(f"[green]→ JSON:[/green] {fname}")

        if getattr(args, "html", False):
            fname = f"easm_{target}_{scan_id[:8]}.html"
            informe.to_html_client(fname)
            console.print(f"[green]→ HTML:[/green] {fname}")

    # ── Código de salida ──────────────────────────────────────────────────
    sevs = {d.severidad for d in diffs}
    if "CRITICAL" in sevs:
        return 2
    if "HIGH" in sevs:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Comando: history
# ---------------------------------------------------------------------------

def cmd_history(args: argparse.Namespace) -> int:
    """Muestra el historial de escaneos para el target especificado."""
    storage.inicializar_db()
    limit = getattr(args, "limit", 10)
    rows  = storage.historial_scans(args.target, limit=limit)

    if not rows:
        console.print(f"[dim]Sin historial para el target:[/dim] {args.target}")
        return 0

    console.print(_tabla_historial(rows))
    return 0


# ---------------------------------------------------------------------------
# Comando: assets
# ---------------------------------------------------------------------------

def cmd_assets(args: argparse.Namespace) -> int:
    """Muestra todos los activos conocidos para el target especificado."""
    storage.inicializar_db()
    rows = storage.todos_los_assets(args.target)

    if not rows:
        console.print(f"[dim]Sin activos registrados para el target:[/dim] {args.target}")
        return 0

    console.print(_tabla_assets(rows))
    return 0


# ---------------------------------------------------------------------------
# Comando: export
# ---------------------------------------------------------------------------

def cmd_export(args: argparse.Namespace) -> int:
    """
    Exporta un snapshot del último escaneo en JSON y/o HTML.
    Útil para integración con vamp-penreport.
    """
    storage.inicializar_db()

    # Buscar último escaneo
    rows = storage.historial_scans(args.target, limit=1)
    if not rows:
        console.print(f"[red]Error:[/red] No hay escaneos registrados para {args.target}")
        return 1

    scan_id = rows[0]["id"]
    assets  = storage.assets_del_scan(args.target, scan_id)
    certs   = storage.certs_del_scan(args.target, scan_id)

    # Construir findings de info a partir de los activos
    findings: List[Finding] = []
    n = 1
    for a in assets:
        if a["puerto"]:
            findings.append(Finding(
                id=f"EASM-{n:03d}",
                title=f"Activo expuesto — {a['subdominio']}:{a['puerto']}",
                severity="INFO",
                description=f"Puerto {a['puerto']}/{a['protocolo']} abierto en {a['subdominio']}.",
                evidence=f"Host: {a['subdominio']}\nIP: {a['ip'] or '—'}\nPuerto: {a['puerto']}/{a['protocolo']}\nServicio: {a['servicio'] or '—'}",
                affected=f"{a['subdominio']}:{a['puerto']}",
                remediation="Verificar que el servicio está correctamente asegurado y es intencionado.",
                tags=["easm", "asset", "inventory"],
            ))
            n += 1

    meta = meta_from_args(args, tool=TOOL, version=VERSION)
    meta.scope = args.target
    informe = VampSecReport(meta, findings)

    if not getattr(args, "json", False) and not getattr(args, "html", False):
        # Por defecto exportar ambos
        args.json = True
        args.html = True

    exportados = []
    if getattr(args, "json", False):
        fname = f"easm_export_{args.target}_{scan_id[:8]}.json"
        informe.to_json(fname)
        exportados.append(fname)

    if getattr(args, "html", False):
        fname = f"easm_export_{args.target}_{scan_id[:8]}.html"
        informe.to_html_client(fname)
        exportados.append(fname)

    for f in exportados:
        console.print(f"[green]→ Exportado:[/green] {f}")

    return 0


# ---------------------------------------------------------------------------
# Comando: watch
# ---------------------------------------------------------------------------

def _escanear_target(
    target: str,
    puertos: List[int],
    usar_nmap: bool,
    alert_webhook: Optional[str],
) -> List[differ.Diff]:
    """
    Ejecuta un escaneo completo del target, persiste en SQLite y devuelve
    los diffs calculados frente al escaneo inmediatamente anterior.

    Función interna compartida por cmd_scan (indirectamente) y cmd_watch.
    """
    storage.inicializar_db()
    scan_id = storage.nuevo_scan(target)

    resultado = scanner.ejecutar_escaneo(
        target=target,
        puertos=puertos,
        usar_nmap=usar_nmap,
    )

    # Persistir subdominios
    for sub in resultado.subdominios:
        ip = sub.ips[0] if sub.ips else None
        storage.upsert_asset(target=target, subdominio=sub.nombre,
                             scan_id=scan_id, ip=ip)

    # Persistir puertos
    for pa in resultado.puertos:
        ip_pa = None
        for sub in resultado.subdominios:
            if sub.nombre == pa.host:
                ip_pa = sub.ips[0] if sub.ips else None
                break
        storage.upsert_asset(target=target, subdominio=pa.host,
                             scan_id=scan_id, ip=ip_pa,
                             puerto=pa.puerto, protocolo=pa.protocolo,
                             servicio=pa.servicio)

    # Persistir certificados
    for cert in resultado.certs:
        if cert.error:
            continue
        storage.insertar_cert(target=target, host=cert.host,
                              scan_id=scan_id, issued_to=cert.issued_to,
                              issuer=cert.issuer, not_after=cert.not_after,
                              sans=",".join(cert.sans) if cert.sans else None,
                              fingerprint=cert.fingerprint,
                              autofirmado=cert.autofirmado)

    # Calcular diffs frente al escaneo anterior
    historial = storage.historial_scans(target, limit=5)
    scan_id_prev: Optional[str] = None
    for row in historial:
        if row["id"] != scan_id:
            scan_id_prev = row["id"]
            break

    motor = differ.MotorDiff(target=target, scan_id=scan_id,
                              scan_id_prev=scan_id_prev, storage=storage)
    diffs = motor.calcular()

    assets_total = len(resultado.subdominios) + len(resultado.puertos)
    storage.cerrar_scan(scan_id, assets_found=assets_total,
                        diffs_found=len(diffs))

    # Gestionar alertas solo si hay cambios
    if diffs:
        webhook_url = alerter.resolver_webhook_url(alert_webhook)
        alerter.gestionar_alertas(webhook_url, target, diffs, scan_id)

    return diffs


def cmd_watch(args: argparse.Namespace) -> int:
    """
    Modo watch continuo: ejecuta escaneos periódicos del target, compara
    con el resultado anterior almacenado en SQLite e imprime solo los
    cambios detectados (nuevos puertos, subdominios, certs, etc.).

    El webhook (--alert-webhook) solo se dispara cuando hay diffs.
    El bucle continúa hasta interrupción manual (Ctrl+C).

    Returns
    -------
    int : Siempre 0 al salir por interrupción.
    """
    target   = args.target
    interval = getattr(args, "interval", 3600)
    webhook  = getattr(args, "alert_webhook", None)

    # Determinar lista de puertos
    if getattr(args, "ports", None) and args.ports != "top100":
        try:
            puertos = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            console.print("[red]Error:[/red] --ports debe ser 'top100' o lista CSV (ej: 22,80,443)")
            return 1
    else:
        puertos = scanner.TOP_100_PORTS

    console.print(Panel(
        f"[bold cyan]vamp-easm v{VERSION}[/bold cyan]  ·  {BRAND}\n"
        f"Modo: [bold]WATCH[/bold] · Target: [bold]{target}[/bold] · "
        f"Intervalo: {interval}s  ·  {_ts_ahora()}",
        border_style="yellow",
    ))

    iteracion = 0
    try:
        while True:
            iteracion += 1
            ts_scan = _ts_ahora()
            console.print(
                f"\n[yellow]►[/yellow] [bold]Escaneo #{iteracion}[/bold] — {ts_scan}"
            )

            diffs = _escanear_target(
                target=target,
                puertos=puertos,
                usar_nmap=getattr(args, "nmap", False),
                alert_webhook=webhook,
            )

            if diffs:
                console.print(_tabla_diffs(diffs))
            else:
                console.print(
                    "[green]✓ Sin cambios respecto al escaneo anterior.[/green]"
                )

            console.print(
                f"[dim]Próximo escaneo en {interval}s "
                f"(Ctrl+C para detener)[/dim]"
            )
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Watch detenido por el usuario.[/yellow]")

    return 0


# ---------------------------------------------------------------------------
# Comando: diff
# ---------------------------------------------------------------------------

def cmd_diff(args: argparse.Namespace) -> int:
    """
    Muestra todos los cambios detectados entre dos snapshots almacenados.

    --from y --to aceptan fechas en formato YYYY-MM-DD o YYYY-MM-DDTHH:MM.
    Se busca el escaneo cuyo ts_start sea el más cercano (posterior) a cada
    fecha indicada.

    Returns
    -------
    int : 0 sin diffs, 1 con diffs HIGH, 2 con diffs CRITICAL.
    """
    storage.inicializar_db()

    target     = args.target
    fecha_from = getattr(args, "from_date", None) or ""
    fecha_to   = getattr(args, "to_date",   None) or ""

    # Obtener historial completo del target (máx 1000 para cubrir rango amplio)
    historial = storage.historial_scans(target, limit=1000)
    if not historial:
        console.print(f"[red]Error:[/red] Sin historial para {target}")
        return 1

    def _scan_id_por_fecha(fecha_prefix: str, historial_rows) -> Optional[str]:
        """
        Devuelve el scan_id cuyo ts_start comienza con fecha_prefix.
        Si no hay match exacto, devuelve el más antiguo posterior a ese prefijo.
        """
        if not fecha_prefix:
            return None
        for row in reversed(historial_rows):   # orden cronológico ascendente
            if row["ts_start"] and row["ts_start"] >= fecha_prefix:
                return row["id"]
        return None

    scan_id_from = _scan_id_por_fecha(fecha_from, historial)
    scan_id_to   = _scan_id_por_fecha(fecha_to,   historial)

    if not scan_id_from:
        console.print(
            f"[red]Error:[/red] No se encontró escaneo en o posterior a "
            f"[bold]{fecha_from}[/bold] para {target}"
        )
        return 1

    if not scan_id_to:
        console.print(
            f"[red]Error:[/red] No se encontró escaneo en o posterior a "
            f"[bold]{fecha_to}[/bold] para {target}"
        )
        return 1

    if scan_id_from == scan_id_to:
        console.print("[yellow]⚠ Los dos snapshots apuntan al mismo escaneo — sin diff.[/yellow]")
        return 0

    console.print(Panel(
        f"[bold cyan]vamp-easm v{VERSION}[/bold cyan]  ·  {BRAND}\n"
        f"Target: [bold]{target}[/bold] · Diff acumulado\n"
        f"Desde: [dim]{fecha_from}[/dim] (scan {scan_id_from[:8]})\n"
        f"Hasta: [dim]{fecha_to}[/dim]  (scan {scan_id_to[:8]})",
        border_style="dim",
    ))

    motor = differ.MotorDiff(
        target=target,
        scan_id=scan_id_to,
        scan_id_prev=scan_id_from,
        storage=storage,
    )
    diffs = motor.calcular()

    if diffs:
        console.print(_tabla_diffs(diffs))
    else:
        console.print("[green]✓ Sin cambios entre los dos snapshots indicados.[/green]")

    sevs = {d.severidad for d in diffs}
    if "CRITICAL" in sevs:
        return 2
    if "HIGH" in sevs:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Comando: monitor
# ---------------------------------------------------------------------------

def cmd_monitor(args: argparse.Namespace) -> int:
    """
    Gestión de alertas Shodan Monitor para monitorización automática de IPs.

    Acciones disponibles:
      --setup  : crea una alerta Shodan Monitor para las IPs del target
      --check  : consulta la alerta y muestra nuevas amenazas detectadas
      --remove : elimina la alerta del target
      --list   : lista todas las alertas Shodan Monitor de la cuenta
    """
    shodan_key = (
        getattr(args, "shodan_key", None)
        or __import__("os").environ.get("SHODAN_API_KEY", "")
    )
    if not shodan_key:
        console.print("[red]Error:[/red] Se requiere --shodan-key o SHODAN_API_KEY")
        return 1

    mgr = ShodanMonitorManager(shodan_key)

    # ── Listar todas las alertas ──────────────────────────────────────────
    if getattr(args, "list_alerts", False):
        alertas = mgr.listar_alertas()
        if not alertas:
            console.print("[dim]No hay alertas Shodan Monitor activas.[/dim]")
            return 0
        tabla = Table(title="Alertas Shodan Monitor", box=box.SIMPLE_HEAVY)
        tabla.add_column("ID",     style="cyan",  no_wrap=True)
        tabla.add_column("Nombre", style="white")
        tabla.add_column("IPs",    style="dim",   max_width=40)
        tabla.add_column("Creada", style="dim")
        for a in alertas:
            tabla.add_row(
                str(a.get("id",      "—")),
                str(a.get("name",    "—")),
                str(a.get("filters", {}).get("ip", "—"))[:40],
                str(a.get("created", "—"))[:16],
            )
        console.print(tabla)
        return 0

    # Las demás acciones requieren --target
    target = getattr(args, "target", None)
    if not target:
        console.print(
            "[red]Error:[/red] --target es obligatorio para "
            "--setup, --check y --remove"
        )
        return 1

    # ── Setup: crear alerta Shodan Monitor ───────────────────────────────
    if getattr(args, "setup", False):
        storage.inicializar_db()
        assets  = storage.todos_los_assets(target)
        ips_set: set = {a["ip"] for a in assets if a["ip"]} if assets else set()

        if not ips_set:
            # Fallback: resolución DNS directa del dominio
            import socket as _sock
            try:
                for item in _sock.getaddrinfo(target, None):
                    ips_set.add(item[4][0])
            except Exception:
                pass

        if not ips_set:
            console.print(
                f"[red]Error:[/red] Sin IPs para {target}. "
                "Ejecuta primero: vamp-easm scan --target " + target
            )
            return 1

        import ipaddress as _ipa
        def _es_publica(ip: str) -> bool:
            try:
                return not _ipa.ip_address(ip).is_private
            except ValueError:
                return False
        ips = [ip for ip in ips_set if _es_publica(ip)]
        if not ips:
            console.print("[red]Error:[/red] No se encontraron IPs públicas para el target.")
            return 1
        ips_str = ", ".join(ips[:5]) + ("…" if len(ips) > 5 else "")
        console.print(
            f"[cyan]►[/cyan] Creando alerta Shodan Monitor para "
            f"[bold]{target}[/bold] · {len(ips)} IP(s): [dim]{ips_str}[/dim]"
        )

        alert_id = mgr.setup_para_target(target, ips)
        if not alert_id:
            console.print(
                "[red]Error:[/red] No se pudo crear la alerta en Shodan Monitor.\n"
                "[dim]Verifica que la clave API tiene permisos de monitorización.[/dim]"
            )
            return 1

        console.print(
            f"[green]✓ Alerta creada:[/green] ID [bold]{alert_id}[/bold]\n"
            f"  Usa '--check' para consultar los matches."
        )
        return 0

    # ── Check: consultar matches y generar findings ───────────────────────
    if getattr(args, "check", False):
        console.print(
            f"[cyan]►[/cyan] Consultando Shodan Monitor para [bold]{target}[/bold]…"
        )
        findings: List[Finding] = []
        mgr.check_matches(target, findings)

        if not findings:
            console.print("[green]✓ Sin novedades en Shodan Monitor.[/green]")
            return 0

        tabla = Table(title=f"Shodan Monitor — {target}", box=box.SIMPLE_HEAVY)
        tabla.add_column("ID",       style="dim",   no_wrap=True, max_width=16)
        tabla.add_column("Sev",      no_wrap=True,  max_width=10)
        tabla.add_column("Título",   style="white", max_width=60)
        tabla.add_column("Afectado", style="cyan",  max_width=25)
        for f in findings:
            tabla.add_row(
                f.id,
                _badge_sev(f.severity),
                f.title[:60],
                f.affected or "—",
            )
        console.print(tabla)

        criticos = [f for f in findings if f.severity == "CRITICAL"]
        highs    = [f for f in findings if f.severity == "HIGH"]
        console.print(
            f"\n[bold]Resumen:[/bold] {len(findings)} hallazgos — "
            f"{len(criticos)} CRITICAL · {len(highs)} HIGH"
        )
        if criticos:
            return 2
        if highs:
            return 1
        return 0

    # ── Remove: eliminar alerta ───────────────────────────────────────────
    if getattr(args, "remove", False):
        estado = mgr._cargar_estado()
        if target not in estado:
            console.print(f"[yellow]⚠[/yellow] Sin alerta registrada para {target}")
            return 0
        alert_id = estado[target].get("alert_id")
        if not alert_id:
            console.print(f"[yellow]⚠[/yellow] Sin alert_id registrado para {target}")
            return 0
        console.print(
            f"[cyan]►[/cyan] Eliminando alerta Shodan Monitor "
            f"ID [bold]{alert_id}[/bold]…"
        )
        if mgr.eliminar_alerta(alert_id):
            del estado[target]
            mgr._guardar_estado(estado)
            console.print(f"[green]✓ Alerta {alert_id} eliminada.[/green]")
            return 0
        console.print(f"[red]Error:[/red] No se pudo eliminar la alerta {alert_id}")
        return 1

    console.print(
        "[yellow]⚠[/yellow] Especifica una acción: "
        "--setup, --check, --remove o --list"
    )
    return 1


# ---------------------------------------------------------------------------
# CLI — definición de argumentos
# ---------------------------------------------------------------------------

def construir_parser() -> argparse.ArgumentParser:
    """Construye el parser argparse con todos los subcomandos."""
    parser = argparse.ArgumentParser(
        prog="vamp-easm",
        description=(
            "vamp-easm — Motor de Attack Surface Management Continuo\n"
            "VampSecure Labs · VampSecure Studios"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python vamp_easm.py scan    --target ejemplo.com\n"
            "  python vamp_easm.py scan    --target ejemplo.com --ports 22,80,443 --html\n"
            "  python vamp_easm.py scan    --target ejemplo.com --shodan-key KEY --shodan-monitor\n"
            "  python vamp_easm.py history --target ejemplo.com --limit 5\n"
            "  python vamp_easm.py assets  --target ejemplo.com\n"
            "  python vamp_easm.py export  --target ejemplo.com --json\n"
            "  python vamp_easm.py watch   --target ejemplo.com --interval 1800\n"
            "  python vamp_easm.py diff    --target ejemplo.com --from 2026-09-01 --to 2026-09-17\n"
            "  python vamp_easm.py monitor --target ejemplo.com --shodan-key KEY --setup\n"
            "  python vamp_easm.py monitor --target ejemplo.com --shodan-key KEY --check\n"
            "  python vamp_easm.py monitor --shodan-key KEY --list\n"
        ),
    )
    parser.add_argument(
        "--version", action="version",
        version=f"vamp-easm {VERSION} · VampSecure Labs",
    )

    subparsers = parser.add_subparsers(dest="comando", help="Subcomando a ejecutar")


    # ── scan ─────────────────────────────────────────────────────────────
    p_scan = subparsers.add_parser("scan", help="Escanear un target y calcular diffs")
    p_scan.add_argument(
        "--target", required=True, metavar="DOMINIO",
        help="Dominio objetivo (ej: ejemplo.com)",
    )
    p_scan.add_argument(
        "--ports", default="top100", metavar="PORTS",
        help="Puertos a escanear: 'top100' (por defecto) o lista CSV (ej: 22,80,443)",
    )
    p_scan.add_argument(
        "--nmap", action="store_true",
        help="Usar nmap como backend de escaneo de puertos (requiere nmap en PATH)",
    )
    p_scan.add_argument(
        "--json", action="store_true",
        help="Exportar hallazgos en formato JSON (informe VSL estándar)",
    )
    p_scan.add_argument(
        "--html", action="store_true",
        help="Exportar hallazgos en formato HTML profesional (informe VSL)",
    )
    p_scan.add_argument(
        "--alert-webhook", metavar="URL", dest="alert_webhook",
        help="URL del webhook para alertas CRITICAL/HIGH (alternativa: env EASM_ALERT_WEBHOOK)",
    )
    p_scan.add_argument(
        "--shodan-key", metavar="API_KEY", dest="shodan_key",
        help="Clave API Shodan (o var SHODAN_API_KEY) — enriquece IPs descubiertas "
             "con puertos, servicios y vulnerabilidades indexadas por Shodan",
    )
    p_scan.add_argument(
        "--censys-id", metavar="ID", dest="censys_id",
        help="ID de la API Censys v2 (o var CENSYS_API_ID) — enriquece el escaneo "
             "con hosts detectados por Censys no visibles en crt.sh/HackerTarget (v1.4)",
    )
    p_scan.add_argument(
        "--censys-secret", metavar="SECRET", dest="censys_secret",
        help="Secret de la API Censys v2 (o var CENSYS_API_SECRET) — requerido junto "
             "con --censys-id para activar el enriquecimiento Censys (v1.4)",
    )
    p_scan.add_argument(
        "--shodan-monitor", action="store_true", dest="shodan_monitor",
        help="Integrar con Shodan Monitor: verificar alertas activas durante el escaneo. "
             "Requiere --shodan-key y haber ejecutado previamente "
             "'vamp-easm monitor --setup' (v1.5)",
    )
    add_report_args(p_scan)

    # ── history ───────────────────────────────────────────────────────────
    p_hist = subparsers.add_parser("history", help="Ver historial de escaneos de un target")
    p_hist.add_argument("--target", required=True, metavar="DOMINIO", help="Dominio objetivo")
    p_hist.add_argument("--limit", type=int, default=10, metavar="N", help="Número de entradas (por defecto: 10)")

    # ── assets ────────────────────────────────────────────────────────────
    p_assets = subparsers.add_parser("assets", help="Ver activos conocidos de un target")
    p_assets.add_argument("--target", required=True, metavar="DOMINIO", help="Dominio objetivo")

    # ── export ────────────────────────────────────────────────────────────
    p_export = subparsers.add_parser("export", help="Exportar snapshot del último escaneo")
    p_export.add_argument("--target", required=True, metavar="DOMINIO", help="Dominio objetivo")
    p_export.add_argument("--json", action="store_true", help="Exportar como JSON")
    p_export.add_argument("--html", action="store_true", help="Exportar como HTML")
    add_report_args(p_export)

    # ── watch ─────────────────────────────────────────────────────────────
    p_watch = subparsers.add_parser(
        "watch",
        help="Modo watch continuo: escanea periódicamente y notifica solo cambios",
    )
    p_watch.add_argument(
        "--target", required=True, metavar="DOMINIO",
        help="Dominio objetivo a monitorizar",
    )
    p_watch.add_argument(
        "--interval", type=int, default=3600, metavar="SEGUNDOS",
        help="Segundos entre escaneos (default: 3600)",
    )
    p_watch.add_argument(
        "--alert-webhook", metavar="URL", dest="alert_webhook",
        help="URL del webhook para alertas cuando se detecten cambios "
             "(alternativa: env EASM_ALERT_WEBHOOK)",
    )
    p_watch.add_argument(
        "--ports", default="top100", metavar="PORTS",
        help="Puertos a escanear: 'top100' (default) o lista CSV (ej: 22,80,443)",
    )
    p_watch.add_argument(
        "--nmap", action="store_true",
        help="Usar nmap como backend de escaneo de puertos",
    )
    p_watch.add_argument(
        "--shodan-key", metavar="API_KEY", dest="shodan_key",
        help="Clave API Shodan (o var SHODAN_API_KEY) — enriquece IPs descubiertas "
             "con datos Shodan en cada ciclo de watch",
    )

    # ── diff ──────────────────────────────────────────────────────────────
    p_diff = subparsers.add_parser(
        "diff",
        help="Mostrar cambios acumulados entre dos snapshots almacenados",
    )
    p_diff.add_argument(
        "--target", required=True, metavar="DOMINIO",
        help="Dominio objetivo",
    )
    p_diff.add_argument(
        "--from", required=True, dest="from_date", metavar="FECHA",
        help="Fecha de inicio del rango (YYYY-MM-DD o YYYY-MM-DDTHH:MM)",
    )
    p_diff.add_argument(
        "--to", required=True, dest="to_date", metavar="FECHA",
        help="Fecha de fin del rango (YYYY-MM-DD o YYYY-MM-DDTHH:MM)",
    )

    # ── monitor ───────────────────────────────────────────────────────────
    p_mon = subparsers.add_parser(
        "monitor",
        help="Gestión de alertas Shodan Monitor para monitorización automática de IPs",
    )
    p_mon.add_argument(
        "--target", metavar="DOMINIO",
        help="Dominio objetivo (requerido para --setup, --check, --remove)",
    )
    p_mon.add_argument(
        "--shodan-key", metavar="API_KEY", dest="shodan_key",
        help="Clave API Shodan (o var SHODAN_API_KEY)",
    )
    p_mon.add_argument(
        "--setup", action="store_true",
        help="Crear alerta Shodan Monitor para las IPs del target",
    )
    p_mon.add_argument(
        "--check", action="store_true",
        help="Consultar matches actuales y mostrar nuevas amenazas detectadas",
    )
    p_mon.add_argument(
        "--remove", action="store_true",
        help="Eliminar la alerta Shodan Monitor del target",
    )
    p_mon.add_argument(
        "--list", action="store_true", dest="list_alerts",
        help="Listar todas las alertas Shodan Monitor activas en la cuenta",
    )

    return parser


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def main() -> None:
    """Punto de entrada principal. Parsea la CLI y despacha al subcomando."""
    parser = construir_parser()
    args   = parser.parse_args()

    if not args.comando:
        parser.print_help()
        sys.exit(0)

    _dispatch = {
        "scan":    cmd_scan,
        "history": cmd_history,
        "assets":  cmd_assets,
        "export":  cmd_export,
        "watch":   cmd_watch,
        "diff":    cmd_diff,
        "monitor": cmd_monitor,
    }

    handler = _dispatch.get(args.comando)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
