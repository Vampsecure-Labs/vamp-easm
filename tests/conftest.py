# © VampSecure Studios — VampSecure Labs Security Research Division
"""Fixtures compartidas para los tests de vamp-easm."""

import pytest
import sqlite3
import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def db_en_memoria():
    """
    Base de datos SQLite en memoria para tests de integración del historial
    de activos EASM. Incluye el esquema básico necesario.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Crear esquema mínimo
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            ts_start TEXT,
            ts_end TEXT,
            assets_found INTEGER DEFAULT 0,
            diffs_found INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            subdominio TEXT NOT NULL,
            ip TEXT,
            puerto INTEGER,
            protocolo TEXT DEFAULT 'tcp',
            servicio TEXT,
            scan_id TEXT,
            primera_vista TEXT,
            ultima_vista TEXT
        );
        CREATE TABLE IF NOT EXISTS certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            host TEXT NOT NULL,
            scan_id TEXT,
            issued_to TEXT,
            issuer TEXT,
            not_after TEXT,
            sans TEXT,
            fingerprint TEXT,
            autofirmado INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def target_ejemplo():
    """Dominio objetivo de prueba."""
    return "ejemplo.com"


@pytest.fixture
def scan_id_ejemplo():
    """ID de escaneo de prueba."""
    return "test-scan-uuid-0001"


@pytest.fixture
def finding_fake():
    """Finding de prueba para los tests de Shodan/Censys."""
    # Importar Finding del módulo vampsec_report mockeado
    finding = MagicMock()
    finding.id = "EASM-001"
    finding.title = "Puerto sensible expuesto"
    finding.severity = "MEDIUM"
    finding.description = "Puerto 6379 (Redis) abierto en IP 1.2.3.4"
    finding.evidence = "IP: 1.2.3.4\nPuerto: 6379"
    finding.affected = "1.2.3.4:6379"
    finding.remediation = "Restringir acceso con firewall"
    finding.tags = ["shodan", "easm", "exposed-port"]
    return finding


@pytest.fixture
def ips_publicas():
    """Lista de IPs públicas para tests."""
    return ["5.6.7.8", "9.10.11.12"]


@pytest.fixture
def shodan_host_response():
    """Respuesta simulada del endpoint Shodan /shodan/host/<ip>."""
    return {
        "ip_str": "5.6.7.8",
        "org": "Test Organization",
        "os": "Linux",
        "ports": [22, 80, 443, 6379],
        "hostnames": ["test.ejemplo.com"],
        "vulns": {"CVE-2024-1001": {}, "CVE-2024-1002": {}},
    }
