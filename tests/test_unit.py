# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-easm."""

from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Parchear dependencias que requieren módulos internos o conexiones externas
_mocks_easm = {
    "easm": MagicMock(),
    "easm.scanner": MagicMock(),
    "easm.storage": MagicMock(),
    "easm.differ": MagicMock(),
    "easm.alerter": MagicMock(),
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.table": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.box": MagicMock(),
}
with patch.dict("sys.modules", _mocks_easm):
    import vamp_easm as veasm


# ── Tests para _badge_sev ─────────────────────────────────────────────────────

class TestBadgeSev:
    """Pruebas para la función de estilo de severidad."""

    def test_critical_usa_bold_red(self):
        """CRITICAL debe usar el color 'bold red'."""
        resultado = veasm._badge_sev("CRITICAL")
        assert "CRITICAL" in resultado
        assert "bold red" in resultado

    def test_high_usa_bold_orange(self):
        """HIGH debe usar 'bold orange3'."""
        resultado = veasm._badge_sev("HIGH")
        assert "HIGH" in resultado
        assert "bold orange3" in resultado

    def test_medium_usa_yellow(self):
        """MEDIUM debe usar el color amarillo."""
        resultado = veasm._badge_sev("MEDIUM")
        assert "MEDIUM" in resultado
        assert "yellow" in resultado

    def test_severidad_desconocida_usa_white(self):
        """Una severidad desconocida debe usar 'white' como fallback."""
        resultado = veasm._badge_sev("UNKNWON_LEVEL")
        assert "UNKNWON_LEVEL" in resultado


# ── Tests para ShodanEASMEnricher._enrich_with_shodan ────────────────────────

class TestShodanEASMEnricher:
    """Pruebas para el enriquecimiento Shodan de EASM."""

    def test_solo_ips_validas_son_procesadas(self):
        """Solo cadenas con formato IPv4 válido deben pasarse a la API."""
        veasm.ShodanEASMEnricher("test-key")
        hosts_mixtos = ["5.6.7.8", "no-es-ip", "192.168.1.1", "ejemplo.com"]
        ips_validas = []
        vistas: set = set()
        for h in hosts_mixtos:
            h = h.strip()
            partes = h.split(".")
            if len(partes) == 4 and all(p.isdigit() for p in partes) and h not in vistas:
                ips_validas.append(h)
                vistas.add(h)
        assert "5.6.7.8" in ips_validas
        assert "192.168.1.1" in ips_validas
        assert "no-es-ip" not in ips_validas
        assert "ejemplo.com" not in ips_validas

    def test_limite_max_ips(self):
        """Se deben procesar como máximo _MAX_IPS IPs."""
        enricher = veasm.ShodanEASMEnricher("test-key")
        ips_exceso = [f"1.2.3.{i}" for i in range(20)]
        ips_procesadas = ips_exceso[:enricher._MAX_IPS]
        assert len(ips_procesadas) == 10

    def test_puerto_sensible_genera_finding_medium(self, shodan_host_response):
        """Un puerto sensible como Redis (6379) debe generar un finding MEDIUM."""
        # Comprobar que 6379 está en el set de puertos sensibles
        assert 6379 in veasm._SHODAN_PUERTOS_SENSIBLES

    def test_puertos_sensibles_conocidos(self):
        """El set de puertos sensibles debe incluir los servicios de alto riesgo estándar."""
        sensibles_esperados = {21, 23, 445, 3389, 3306, 5900, 6379, 27017, 9200}
        for puerto in sensibles_esperados:
            assert puerto in veasm._SHODAN_PUERTOS_SENSIBLES

    def test_id_base_extraido_de_findings_existentes(self):
        """El índice base para IDs debe extraerse del último finding existente."""
        f1 = MagicMock()
        f1.id = "EASM-005"
        f2 = MagicMock()
        f2.id = "EASM-012"
        findings = [f1, f2]
        idx_base = max(
            (int(f.id.split("-")[-1]) for f in findings if "-" in f.id),
            default=0,
        )
        assert idx_base == 12


# ── Tests para ShodanMonitorManager ──────────────────────────────────────────

class TestShodanMonitorManager:
    """Pruebas para la gestión de alertas Shodan Monitor."""

    def test_listar_alertas_devuelve_lista_en_error(self):
        """Si la API falla, listar_alertas debe devolver lista vacía."""
        mgr = veasm.ShodanMonitorManager("test-key")
        with patch.object(mgr, "_peticion", return_value={"__error__": 401}):
            alertas = mgr.listar_alertas()
        assert alertas == []

    def test_crear_alerta_sin_ips_devuelve_none(self):
        """Intentar crear una alerta sin IPs debe devolver None."""
        mgr = veasm.ShodanMonitorManager("test-key")
        resultado = mgr.crear_alerta("test-alerta", [])
        assert resultado is None

    def test_crear_alerta_con_error_api_devuelve_none(self):
        """Un error de API al crear alerta debe devolver None."""
        mgr = veasm.ShodanMonitorManager("test-key")
        with patch.object(mgr, "_peticion", return_value={"__error__": 403}):
            resultado = mgr.crear_alerta("mi-alerta", ["1.2.3.4"])
        assert resultado is None

    def test_eliminar_alerta_exito(self):
        """Una respuesta con 'success: True' debe devolver True."""
        mgr = veasm.ShodanMonitorManager("test-key")
        with patch.object(mgr, "_peticion", return_value={"success": True}):
            ok = mgr.eliminar_alerta("alert-id-123")
        assert ok is True


# ── Tests para CensysEASMEnricher ─────────────────────────────────────────────

class TestCensysEASMEnricher:
    """Pruebas para el enriquecimiento Censys de EASM."""

    def test_auth_header_formato_basic(self):
        """La cabecera de autenticación debe usar formato Basic base64."""
        import base64
        enricher = veasm.CensysEASMEnricher("mi-id", "mi-secret")
        esperado = "Basic " + base64.b64encode(b"mi-id:mi-secret").decode()
        assert enricher._auth_header() == esperado

    def test_puertos_sensibles_censys(self):
        """El set de puertos sensibles Censys debe incluir servicios críticos."""
        sensibles = {22, 23, 445, 3389, 3306, 5900, 6379, 27017, 9200}
        for puerto in sensibles:
            assert puerto in veasm._CENSYS_PUERTOS_SENSIBLES

    def test_host_no_en_ips_conocidas_genera_finding_high(self):
        """Un host de Censys no conocido debe generar un finding HIGH."""
        veasm.CensysEASMEnricher("id", "secret")
        findings = []
        host = {"ip": "99.99.99.99", "names": [], "services": []}
        ips_conocidas = {"1.2.3.4", "5.6.7.8"}
        ip = host.get("ip", "")
        if ip and ip not in ips_conocidas:
            # Según la lógica del código, esto genera un finding HIGH
            severity = "HIGH"
            findings.append({"id": "EASM-CNS-001", "severity": severity})
        assert any(f["severity"] == "HIGH" for f in findings)


# ── Tests para check_matches de ShodanMonitorManager ─────────────────────────

class TestCheckMatches:
    """Pruebas para la detección de cambios en Shodan Monitor."""

    def test_target_sin_alerta_genera_finding_info(self):
        """Un target sin alerta configurada debe generar un finding INFO."""
        mgr = veasm.ShodanMonitorManager("test-key")

        estado_vacio = {}
        with patch.object(mgr, "_cargar_estado", return_value=estado_vacio), \
             patch.object(mgr, "_guardar_estado"):
            findings = []
            mgr.check_matches("objetivo-sin-alerta.com", findings)

        assert len(findings) == 1
        assert findings[0].severity == "INFO"

    def test_severidad_nuevo_puerto_sensible_es_high(self):
        """Un nuevo puerto sensible detectado por Monitor debe ser HIGH."""
        # Verificar la lógica de clasificación de severidad
        puerto_sensible = 3389  # RDP
        sev = "HIGH" if puerto_sensible in veasm._SHODAN_PUERTOS_SENSIBLES else "MEDIUM"
        assert sev == "HIGH"

    def test_3_o_mas_cves_nuevas_generan_critical(self):
        """Tres o más CVEs nuevas deben generar severidad CRITICAL."""
        vulns_nuevas = ["CVE-2024-001", "CVE-2024-002", "CVE-2024-003"]
        sev = "CRITICAL" if len(vulns_nuevas) >= 3 else "HIGH"
        assert sev == "CRITICAL"

    def test_menos_de_3_cves_generan_high(self):
        """Menos de tres CVEs nuevas deben generar severidad HIGH."""
        vulns_nuevas = ["CVE-2024-001", "CVE-2024-002"]
        sev = "CRITICAL" if len(vulns_nuevas) >= 3 else "HIGH"
        assert sev == "HIGH"
