# © VampSecure Studios — VampSecure Labs Security Research Division
"""
storage.py — Capa de persistencia SQLite para vamp-easm
=========================================================
Gestiona el historial de escaneos, activos descubiertos y certificados TLS.
La base de datos se crea automáticamente en el directorio de trabajo.

Tablas:
  · scans   — registro de cada ejecución (UUID, target, timestamps, contadores)
  · assets  — activos descubiertos: subdominios, IPs, puertos, servicios
  · certs   — certificados TLS con metadatos de validez y huella digital
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Nombre del fichero de base de datos (relativo al directorio de trabajo)
# ---------------------------------------------------------------------------
DB_FILE = "vamp_easm.db"

# ---------------------------------------------------------------------------
# DDL — creación de tablas si no existen
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    ts_start     TEXT NOT NULL,
    ts_end       TEXT,
    assets_found INTEGER DEFAULT 0,
    diffs_found  INTEGER DEFAULT 0
);

-- Inventario deduplicado: una fila por activo único (target, subdominio, puerto).
-- primera_vista / ultima_vista registran cuándo se vio por primera y última vez.
CREATE TABLE IF NOT EXISTS assets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT NOT NULL,
    subdominio    TEXT NOT NULL,
    ip            TEXT,
    puerto        INTEGER,
    protocolo     TEXT DEFAULT 'tcp',
    servicio      TEXT,
    primera_vista TEXT NOT NULL,
    ultima_vista  TEXT NOT NULL,
    UNIQUE(target, subdominio, puerto)
);

-- Log por escaneo: registra exactamente qué activos se encontraron en cada scan.
-- Permite calcular diffs entre el escaneo actual y el anterior sin ambigüedad.
CREATE TABLE IF NOT EXISTS scan_asset_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT NOT NULL,
    target     TEXT NOT NULL,
    subdominio TEXT NOT NULL,
    ip         TEXT,
    puerto     INTEGER,
    protocolo  TEXT DEFAULT 'tcp',
    servicio   TEXT,
    UNIQUE(scan_id, subdominio, puerto)
);

CREATE TABLE IF NOT EXISTS certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    host        TEXT NOT NULL,
    issued_to   TEXT,
    issuer      TEXT,
    not_after   TEXT,
    sans        TEXT,
    fingerprint TEXT,
    autofirmado INTEGER DEFAULT 0,
    ts          TEXT NOT NULL,
    scan_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_target    ON assets(target);
CREATE INDEX IF NOT EXISTS idx_sal_scan         ON scan_asset_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_sal_target       ON scan_asset_log(target);
CREATE INDEX IF NOT EXISTS idx_certs_target     ON certs(target);
CREATE INDEX IF NOT EXISTS idx_scans_target     ON scans(target);
"""


def _conectar() -> sqlite3.Connection:
    """Abre (o crea) la base de datos y retorna una conexión con row_factory."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def inicializar_db() -> None:
    """Crea las tablas si no existen. Llamar al inicio de cada ejecución."""
    with _conectar() as conn:
        conn.executescript(_DDL)


# ---------------------------------------------------------------------------
# Operaciones sobre scans
# ---------------------------------------------------------------------------

def nuevo_scan(target: str) -> str:
    """
    Registra el inicio de un nuevo escaneo y devuelve su UUID.

    Parameters
    ----------
    target : Dominio objetivo del escaneo

    Returns
    -------
    str : UUID del escaneo recién creado
    """
    scan_id = str(uuid.uuid4())
    ahora = _ahora()
    with _conectar() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, ts_start) VALUES (?, ?, ?)",
            (scan_id, target, ahora),
        )
    return scan_id


def cerrar_scan(scan_id: str, assets_found: int, diffs_found: int) -> None:
    """Actualiza el escaneo con timestamp de fin y contadores."""
    with _conectar() as conn:
        conn.execute(
            """UPDATE scans
               SET ts_end=?, assets_found=?, diffs_found=?
               WHERE id=?""",
            (_ahora(), assets_found, diffs_found, scan_id),
        )


def ultimo_scan(target: str) -> Optional[sqlite3.Row]:
    """Devuelve el registro del último escaneo completado para el target."""
    with _conectar() as conn:
        return conn.execute(
            """SELECT * FROM scans
               WHERE target=? AND ts_end IS NOT NULL
               ORDER BY ts_end DESC LIMIT 1""",
            (target,),
        ).fetchone()


def historial_scans(target: str, limit: int = 10) -> List[sqlite3.Row]:
    """Lista los últimos N escaneos completados de un target, de más reciente a más antiguo."""
    with _conectar() as conn:
        return conn.execute(
            """SELECT * FROM scans
               WHERE target=? AND ts_end IS NOT NULL
               ORDER BY ts_end DESC LIMIT ?""",
            (target, limit),
        ).fetchall()


# ---------------------------------------------------------------------------
# Operaciones sobre assets
# ---------------------------------------------------------------------------

def upsert_asset(
    target: str,
    subdominio: str,
    scan_id: str,
    ip: Optional[str] = None,
    puerto: Optional[int] = None,
    protocolo: str = "tcp",
    servicio: Optional[str] = None,
) -> None:
    """
    Inserta o actualiza el inventario deduplicado de activos y registra el
    activo en el log del escaneo actual (scan_asset_log).

    El inventario (tabla assets) mantiene primera_vista/ultima_vista.
    El log por escaneo (tabla scan_asset_log) registra exactamente qué se
    encontró en cada scan_id, lo que permite calcular diffs correctamente.

    Parameters
    ----------
    target     : Dominio raíz objetivo
    subdominio : Subdominio o host encontrado
    scan_id    : UUID del escaneo actual
    ip         : Dirección IP resuelta (None si no resuelve)
    puerto     : Puerto TCP abierto (None para registrar solo el subdominio)
    protocolo  : Protocolo (por defecto 'tcp')
    servicio   : Nombre del servicio detectado
    """
    ahora = _ahora()
    with _conectar() as conn:
        # Actualizar inventario deduplicado
        conn.execute(
            """INSERT INTO assets
                   (target, subdominio, ip, puerto, protocolo, servicio, primera_vista, ultima_vista)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(target, subdominio, puerto) DO UPDATE SET
                   ip=excluded.ip,
                   servicio=excluded.servicio,
                   ultima_vista=excluded.ultima_vista""",
            (target, subdominio, ip, puerto, protocolo, servicio, ahora, ahora),
        )
        # Registrar en el log del escaneo actual (snapshot por scan)
        conn.execute(
            """INSERT OR IGNORE INTO scan_asset_log
                   (scan_id, target, subdominio, ip, puerto, protocolo, servicio)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, target, subdominio, ip, puerto, protocolo, servicio),
        )


def todos_los_assets(target: str) -> List[sqlite3.Row]:
    """Devuelve todos los activos conocidos para un target (inventario completo)."""
    with _conectar() as conn:
        return conn.execute(
            "SELECT * FROM assets WHERE target=? ORDER BY subdominio, puerto",
            (target,),
        ).fetchall()


def assets_del_scan(target: str, scan_id: str) -> List[sqlite3.Row]:
    """
    Devuelve los activos registrados en un escaneo concreto desde scan_asset_log.
    Usado por el motor de diffs para comparar dos escaneos.
    """
    with _conectar() as conn:
        return conn.execute(
            """SELECT * FROM scan_asset_log
               WHERE target=? AND scan_id=?
               ORDER BY subdominio, puerto""",
            (target, scan_id),
        ).fetchall()


# ---------------------------------------------------------------------------
# Operaciones sobre certificados
# ---------------------------------------------------------------------------

def insertar_cert(
    target: str,
    host: str,
    scan_id: str,
    issued_to: Optional[str] = None,
    issuer: Optional[str] = None,
    not_after: Optional[str] = None,
    sans: Optional[str] = None,
    fingerprint: Optional[str] = None,
    autofirmado: bool = False,
) -> None:
    """Inserta un registro de certificado TLS para el escaneo actual."""
    with _conectar() as conn:
        conn.execute(
            """INSERT INTO certs
                   (target, host, issued_to, issuer, not_after, sans, fingerprint, autofirmado, ts, scan_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (target, host, issued_to, issuer, not_after, sans, fingerprint,
             1 if autofirmado else 0, _ahora(), scan_id),
        )


def certs_del_scan(target: str, scan_id: str) -> List[sqlite3.Row]:
    """Devuelve los certificados registrados en un escaneo concreto."""
    with _conectar() as conn:
        return conn.execute(
            "SELECT * FROM certs WHERE target=? AND scan_id=? ORDER BY host",
            (target, scan_id),
        ).fetchall()


def cert_anterior(target: str, host: str, scan_id_actual: str) -> Optional[sqlite3.Row]:
    """Devuelve el último certificado registrado para este host antes del escaneo actual."""
    with _conectar() as conn:
        return conn.execute(
            """SELECT * FROM certs
               WHERE target=? AND host=? AND scan_id != ?
               ORDER BY ts DESC LIMIT 1""",
            (target, host, scan_id_actual),
        ).fetchone()


# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------

def _ahora() -> str:
    """Devuelve el timestamp actual en formato ISO-8601 UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
