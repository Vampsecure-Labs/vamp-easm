# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests de integración para vamp-easm."""

import pytest
import json
import os
import sys
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.integration

_mocks_easm = {
    "easm": MagicMock(),
    "easm.scanner": MagicMock(),
    "easm.storage": MagicMock(),
    "easm.differ": MagicMock(),
    "easm.alerter": MagicMock(),
    "vampsec_report": MagicMock(),
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.table": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.box": MagicMock(),
}
with patch.dict("sys.modules", _mocks_easm):
    import vamp_easm as veasm


# ── Test 1: SQLite en memoria — persistencia de assets ───────────────────────

def test_persistencia_assets_sqlite(db_en_memoria, target_ejemplo, scan_id_ejemplo):
    """
    Verifica que la base de datos SQLite puede almacenar y recuperar activos
    correctamente usando el esquema esperado por EASM.
    """
    conn = db_en_memoria
    cursor = conn.cursor()

    # Insertar un escaneo
    cursor.execute(
        "INSERT INTO scans (id, target, ts_start, assets_found, diffs_found) VALUES (?,?,?,?,?)",
        (scan_id_ejemplo, target_ejemplo, datetime.now(timezone.utc).isoformat(), 0, 0),
    )

    # Insertar activos del escaneo
    activos = [
        (target_ejemplo, "www.ejemplo.com", "1.2.3.4", 443, "tcp", "HTTPS", scan_id_ejemplo),
        (target_ejemplo, "api.ejemplo.com", "1.2.3.5", 80, "tcp", "HTTP", scan_id_ejemplo),
        (target_ejemplo, "mail.ejemplo.com", None, None, None, None, scan_id_ejemplo),
    ]
    cursor.executemany(
        "INSERT INTO assets (target, subdominio, ip, puerto, protocolo, servicio, scan_id) VALUES (?,?,?,?,?,?,?)",
        activos,
    )
    conn.commit()

    # Recuperar activos del escaneo
    cursor.execute(
        "SELECT * FROM assets WHERE target = ? AND scan_id = ?",
        (target_ejemplo, scan_id_ejemplo),
    )
    rows = cursor.fetchall()
    assert len(rows) == 3
    subdominios = {row["subdominio"] for row in rows}
    assert "www.ejemplo.com" in subdominios
    assert "api.ejemplo.com" in subdominios


# ── Test 2: SQLite en memoria — persistencia de certificados ──────────────────

def test_persistencia_certs_sqlite(db_en_memoria, target_ejemplo, scan_id_ejemplo):
    """
    Verifica que los certificados TLS se persisten correctamente en SQLite.
    """
    conn = db_en_memoria
    cursor = conn.cursor()

    # Insertar un scan base
    cursor.execute(
        "INSERT INTO scans (id, target, ts_start) VALUES (?,?,?)",
        (scan_id_ejemplo, target_ejemplo, "2026-10-01T00:00:00"),
    )

    # Insertar un certificado
    cursor.execute(
        """INSERT INTO certs
           (target, host, scan_id, issued_to, issuer, not_after, fingerprint, autofirmado)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            target_ejemplo,
            "www.ejemplo.com",
            scan_id_ejemplo,
            "www.ejemplo.com",
            "Let's Encrypt",
            "2027-01-01",
            "AA:BB:CC:DD",
            0,
        ),
    )
    conn.commit()

    cursor.execute(
        "SELECT * FROM certs WHERE target = ? AND scan_id = ?",
        (target_ejemplo, scan_id_ejemplo),
    )
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0]["issuer"] == "Let's Encrypt"
    assert rows[0]["autofirmado"] == 0


# ── Test 3: ShodanEASMEnricher — enriquecimiento con respuesta mockeada ───────

def test_shodan_easm_enricher_con_mock_urllib():
    """
    Verifica que ShodanEASMEnricher._enrich_with_shodan() parsea correctamente
    la respuesta Shodan y añade findings relevantes a la lista.
    """
    respuesta_shodan = {
        "ip_str": "5.6.7.8",
        "org": "Test Org",
        "os": "Linux",
        "ports": [22, 6379],          # 6379 es sensible
        "hostnames": ["host.test.com"],
        "vulns": {"CVE-2024-9999": {}, "CVE-2023-8888": {}},
    }

    # Simular la respuesta de urllib
    mock_resp = MagicMock()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.status = 200
    mock_resp.read = MagicMock(return_value=json.dumps(respuesta_shodan).encode())

    # Parchear Finding para que sea un objeto real mínimo
    from dataclasses import dataclass
    @dataclass
    class FindingMinimal:
        id: str
        title: str
        severity: str
        description: str
        evidence: str
        affected: str
        remediation: str
        cve: str = ""
        tags: list = None

    with patch.dict("sys.modules", {"vampsec_report": MagicMock()}):
        # Reemplazar Finding en el módulo ya cargado
        original_finding = getattr(veasm, "Finding", None)
        veasm.Finding = FindingMinimal

        enricher = veasm.ShodanEASMEnricher("test-api-key")
        findings = []

        with patch("urllib.request.urlopen", return_value=mock_resp):
            enricher._enrich_with_shodan(["5.6.7.8"], "test-api-key", findings)

        # Restaurar Finding original
        if original_finding:
            veasm.Finding = original_finding

    # Debe haber al menos un finding (puerto sensible 6379 y/o CVEs)
    assert len(findings) >= 1
    sevs = {f.severity for f in findings}
    assert "MEDIUM" in sevs or "HIGH" in sevs


# ── Test 4: ShodanMonitorManager — persistencia de estado ────────────────────

def test_shodan_monitor_persistencia_estado(tmp_path):
    """
    Verifica que el estado del Monitor se persiste y recupera correctamente.
    """
    # Usar un path temporal para el estado
    estado_path = tmp_path / "easm_shodan_monitor.json"

    mgr = veasm.ShodanMonitorManager("test-key")

    # Parchear el path del estado
    with patch.object(type(mgr), "_ESTADO", new=estado_path):
        estado_inicial = mgr._cargar_estado()
        assert estado_inicial == {}

        # Guardar un estado
        estado_nuevo = {
            "ejemplo.com": {
                "alert_id": "alert-123",
                "alert_name": "vamp-easm:ejemplo.com",
                "ips": ["1.2.3.4"],
                "created_at": "2026-10-01T00:00:00",
                "last_checked": None,
                "last_matches": {},
            }
        }
        mgr._guardar_estado(estado_nuevo)

        # Verificar que se recupera correctamente
        estado_recuperado = mgr._cargar_estado()
        assert "ejemplo.com" in estado_recuperado
        assert estado_recuperado["ejemplo.com"]["alert_id"] == "alert-123"


# ── Test 5: Historial de escaneos en SQLite ───────────────────────────────────

def test_historial_scans_sqlite(db_en_memoria, target_ejemplo):
    """
    Verifica que el historial de escaneos se ordena correctamente por fecha.
    """
    conn = db_en_memoria
    cursor = conn.cursor()

    # Insertar varios escaneos en orden cronológico
    scans = [
        ("scan-001", target_ejemplo, "2026-09-01T00:00:00", "2026-09-01T01:00:00", 10, 2),
        ("scan-002", target_ejemplo, "2026-09-15T00:00:00", "2026-09-15T01:00:00", 12, 1),
        ("scan-003", target_ejemplo, "2026-10-01T00:00:00", "2026-10-01T01:00:00", 15, 3),
    ]
    cursor.executemany(
        "INSERT INTO scans (id, target, ts_start, ts_end, assets_found, diffs_found) VALUES (?,?,?,?,?,?)",
        scans,
    )
    conn.commit()

    # Recuperar historial ordenado por fecha descendente
    cursor.execute(
        "SELECT * FROM scans WHERE target = ? ORDER BY ts_start DESC LIMIT 10",
        (target_ejemplo,),
    )
    rows = cursor.fetchall()
    assert len(rows) == 3
    # El más reciente debe ser el primero
    assert rows[0]["id"] == "scan-003"
    assert rows[0]["diffs_found"] == 3
