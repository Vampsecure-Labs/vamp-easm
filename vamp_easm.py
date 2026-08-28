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
  python vamp_easm.py history --target ejemplo.com [--limit 10]
  python vamp_easm.py assets  --target ejemplo.com
  python vamp_easm.py export  --target ejemplo.com [--json] [--html]

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
from datetime import datetime, timezone
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

VERSION = "1.0"
TOOL    = "vamp-easm"
BRAND   = "VampSecure Labs — EASM Continuo"

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
            "  python vamp_easm.py scan --target ejemplo.com\n"
            "  python vamp_easm.py scan --target ejemplo.com --ports 22,80,443 --html\n"
            "  python vamp_easm.py history --target ejemplo.com --limit 5\n"
            "  python vamp_easm.py assets --target ejemplo.com\n"
            "  python vamp_easm.py export --target ejemplo.com --json\n"
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
    }

    handler = _dispatch.get(args.comando)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
