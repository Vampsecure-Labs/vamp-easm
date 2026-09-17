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
import time
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

VERSION = "1.2"
TOOL    = "vamp-easm"
BRAND   = "VampSecure Labs — EASM Continuo"

BANNER = (
    "\n"
    "__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ \n"
    "\\ \\ / /_\\ |  \\/  | _ \\/ __| __/ __| | | | _ \\ __| |    /_\\ | _ ) __|\n"
    " \\ V / _ \\| |\\/| |  _/\\__ \\ _| (__| |_| |   / _|| |__ / _ \\| _ \\__ \\\n"
    "  \\_/_/ \\_\\_|  |_|_|  |___/___\\___|\\___/|_|_\\___|____/_/ \\_\\___/___/\n"
    '  by Antonio Hernandez "Belky" — VampSecure Studios\n'
    "  vamp-easm v1.2 · External Attack Surface Management\n"
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
            "  python vamp_easm.py history --target ejemplo.com --limit 5\n"
            "  python vamp_easm.py assets  --target ejemplo.com\n"
            "  python vamp_easm.py export  --target ejemplo.com --json\n"
            "  python vamp_easm.py watch   --target ejemplo.com --interval 1800\n"
            "  python vamp_easm.py diff    --target ejemplo.com --from 2026-09-01 --to 2026-09-17\n"
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
    }

    handler = _dispatch.get(args.comando)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
