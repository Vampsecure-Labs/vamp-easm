# © VampSecure Studios — VampSecure Labs Security Research Division
"""
differ.py — Motor de diferencias para vamp-easm
================================================
Compara el escaneo actual con el historial en SQLite y genera Findings
en formato VSL (prefijo EASM-NNN) para cada cambio detectado.

Categorías de diff y sus severidades:
  NUEVO_SUBDOMINIO     — HIGH      (nueva superficie expuesta)
  NUEVO_PUERTO         — MEDIUM    (nuevo servicio accesible)
  CERT_EXPIRADO        — HIGH      (cert expira en < 30 días)
  CERT_CAMBIADO        — CRITICAL  (fingerprint diferente desde último scan)
  SERVICIO_DESAPARECIDO — LOW      (puerto que ya no responde)
  IP_CAMBIADA          — MEDIUM    (cambio de resolución DNS)
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

from vampsec_report import Finding


# ---------------------------------------------------------------------------
# Umbral de alerta de expiración de certificado (días)
# ---------------------------------------------------------------------------
DIAS_ALERTA_CERT = 30


# ---------------------------------------------------------------------------
# Estructura de diff individual
# ---------------------------------------------------------------------------

@dataclass
class Diff:
    """
    Representa un cambio detectado entre el escaneo actual y el anterior.

    Attributes
    ----------
    categoria  : Tipo de cambio (ver módulo docstring)
    severidad  : CRITICAL | HIGH | MEDIUM | LOW | INFO
    descripcion: Detalle legible del cambio
    activo     : Host, subdominio o endpoint afectado
    evidencia  : Datos técnicos que soportan el diff
    finding    : Finding VSL generado a partir de este diff
    """
    categoria: str
    severidad: str
    descripcion: str
    activo: str
    evidencia: str
    finding: Optional[Finding] = None


# ---------------------------------------------------------------------------
# Contadores de Finding para numeración secuencial EASM-NNN
# ---------------------------------------------------------------------------

class _Contador:
    """Generador de IDs únicos EASM-NNN dentro de una sesión."""
    def __init__(self) -> None:
        self._n = 0

    def siguiente(self) -> str:
        self._n += 1
        return f"EASM-{self._n:03d}"


# ---------------------------------------------------------------------------
# Motor de diffs
# ---------------------------------------------------------------------------

class MotorDiff:
    """
    Compara el escaneo actual (almacenado en SQLite) con el anterior
    y genera la lista de Diffs y sus Findings correspondientes.

    Parameters
    ----------
    target       : Dominio objetivo
    scan_id      : UUID del escaneo actual
    scan_id_prev : UUID del escaneo anterior (None si es el primero)
    storage      : Módulo storage importado (para evitar import circular)
    """

    def __init__(
        self,
        target: str,
        scan_id: str,
        scan_id_prev: Optional[str],
        storage,
    ) -> None:
        self.target       = target
        self.scan_id      = scan_id
        self.scan_id_prev = scan_id_prev
        self.storage      = storage
        self._contador    = _Contador()

    def calcular(self) -> List[Diff]:
        """
        Ejecuta todos los comparadores y devuelve la lista de diffs ordenada
        por severidad (CRITICAL → HIGH → MEDIUM → LOW → INFO).
        """
        diffs: List[Diff] = []

        if self.scan_id_prev is None:
            # Primer escaneo: no hay base de comparación
            return diffs

        diffs += self._diff_subdominios()
        diffs += self._diff_puertos()
        diffs += self._diff_servicios_desaparecidos()
        diffs += self._diff_ips()
        diffs += self._diff_certs()

        # Ordenar por severidad
        _orden = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        diffs.sort(key=lambda d: _orden.get(d.severidad, 99))

        # Asignar Findings VSL
        for d in diffs:
            d.finding = self._hacer_finding(d)

        return diffs

    # ── Comparadores de subdominios ──────────────────────────────────────

    def _diff_subdominios(self) -> List[Diff]:
        """Detecta subdominios que aparecen por primera vez en este escaneo."""
        actuales  = self._subdominios_actuales()
        anteriores = self._subdominios_anteriores()
        nuevos    = actuales - anteriores
        diffs: List[Diff] = []
        for sub in sorted(nuevos):
            diffs.append(Diff(
                categoria="NUEVO_SUBDOMINIO",
                severidad="HIGH",
                activo=sub,
                descripcion=(
                    f"Nuevo subdominio descubierto: {sub}. "
                    "Este host no aparecía en el escaneo anterior y puede "
                    "representar superficie de ataque no auditada."
                ),
                evidencia=f"Subdominio: {sub}\nDetectado en escaneo: {self.scan_id}",
            ))
        return diffs

    def _subdominios_actuales(self) -> Set[str]:
        rows = self.storage.assets_del_scan(self.target, self.scan_id)
        return {r["subdominio"] for r in rows}

    def _subdominios_anteriores(self) -> Set[str]:
        rows = self.storage.assets_del_scan(self.target, self.scan_id_prev)
        return {r["subdominio"] for r in rows}

    # ── Comparadores de puertos ──────────────────────────────────────────

    def _diff_puertos(self) -> List[Diff]:
        """Detecta puertos abiertos nuevos que no existían en el escaneo anterior."""
        actuales   = self._puertos_abiertos_actuales()
        anteriores = self._puertos_abiertos_anteriores()
        nuevos     = actuales - anteriores
        diffs: List[Diff] = []
        for host, puerto in sorted(nuevos):
            diffs.append(Diff(
                categoria="NUEVO_PUERTO",
                severidad="MEDIUM",
                activo=f"{host}:{puerto}",
                descripcion=(
                    f"Puerto {puerto}/tcp abierto por primera vez en {host}. "
                    "Un nuevo puerto puede indicar un servicio no intencionado o "
                    "un cambio de configuración no autorizado."
                ),
                evidencia=(
                    f"Host: {host}\nPuerto: {puerto}/tcp\n"
                    f"Detectado en escaneo: {self.scan_id}"
                ),
            ))
        return diffs

    def _puertos_abiertos_actuales(self) -> Set[Tuple[str, int]]:
        rows = self.storage.assets_del_scan(self.target, self.scan_id)
        return {(r["subdominio"], r["puerto"]) for r in rows if r["puerto"] is not None}

    def _puertos_abiertos_anteriores(self) -> Set[Tuple[str, int]]:
        rows = self.storage.assets_del_scan(self.target, self.scan_id_prev)
        return {(r["subdominio"], r["puerto"]) for r in rows if r["puerto"] is not None}

    # ── Comparadores de servicios desaparecidos ──────────────────────────

    def _diff_servicios_desaparecidos(self) -> List[Diff]:
        """Detecta puertos que estaban abiertos antes y ya no responden."""
        actuales   = self._puertos_abiertos_actuales()
        anteriores = self._puertos_abiertos_anteriores()
        desaparecidos = anteriores - actuales
        diffs: List[Diff] = []
        for host, puerto in sorted(desaparecidos):
            diffs.append(Diff(
                categoria="SERVICIO_DESAPARECIDO",
                severidad="LOW",
                activo=f"{host}:{puerto}",
                descripcion=(
                    f"El puerto {puerto}/tcp en {host} estaba abierto en el escaneo "
                    "anterior y ahora no responde. Puede indicar un cierre intencionado "
                    "o un fallo del servicio."
                ),
                evidencia=(
                    f"Host: {host}\nPuerto: {puerto}/tcp\n"
                    f"Desaparecido en escaneo: {self.scan_id}"
                ),
            ))
        return diffs

    # ── Comparadores de IPs ──────────────────────────────────────────────

    def _diff_ips(self) -> List[Diff]:
        """Detecta cambios de IP en subdominios ya conocidos."""
        actuales   = self._ips_por_subdominio(self.scan_id)
        anteriores = self._ips_por_subdominio(self.scan_id_prev)
        diffs: List[Diff] = []
        for sub in sorted(actuales.keys() & anteriores.keys()):
            ip_nueva  = actuales[sub]
            ip_vieja  = anteriores[sub]
            if ip_nueva and ip_vieja and ip_nueva != ip_vieja:
                diffs.append(Diff(
                    categoria="IP_CAMBIADA",
                    severidad="MEDIUM",
                    activo=sub,
                    descripcion=(
                        f"La resolución DNS del subdominio {sub} ha cambiado. "
                        "Un cambio de IP no autorizado puede indicar un secuestro "
                        "de DNS o una reconfiguración de infraestructura."
                    ),
                    evidencia=(
                        f"Subdominio: {sub}\n"
                        f"IP anterior: {ip_vieja}\n"
                        f"IP actual:   {ip_nueva}"
                    ),
                ))
        return diffs

    def _ips_por_subdominio(self, scan_id: str) -> dict:
        rows = self.storage.assets_del_scan(self.target, scan_id)
        resultado = {}
        for r in rows:
            sub = r["subdominio"]
            if r["ip"] and sub not in resultado:
                resultado[sub] = r["ip"]
        return resultado

    # ── Comparadores de certificados ─────────────────────────────────────

    def _diff_certs(self) -> List[Diff]:
        """
        Detecta certificados expirados (o próximos a expirar) y cambios
        de fingerprint respecto al escaneo anterior.
        """
        certs_actuales = self.storage.certs_del_scan(self.target, self.scan_id)
        ahora = datetime.now(timezone.utc)
        diffs: List[Diff] = []

        for cert in certs_actuales:
            host = cert["host"]

            # Comprobar expiración
            not_after = cert["not_after"]
            if not_after:
                try:
                    expira = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    dias_restantes = (expira - ahora).days
                    if dias_restantes < DIAS_ALERTA_CERT:
                        severidad = "HIGH" if dias_restantes > 0 else "CRITICAL"
                        estado    = (
                            f"expira en {dias_restantes} días"
                            if dias_restantes > 0
                            else "EXPIRADO"
                        )
                        diffs.append(Diff(
                            categoria="CERT_EXPIRADO",
                            severidad=severidad,
                            activo=host,
                            descripcion=(
                                f"El certificado TLS de {host} {estado}. "
                                "Un certificado expirado o próximo a expirar interrumpe "
                                "la comunicación cifrada y puede comprometer la confianza "
                                "de los usuarios."
                            ),
                            evidencia=(
                                f"Host:        {host}\n"
                                f"Emitido a:   {cert['issued_to'] or '—'}\n"
                                f"Emisor:      {cert['issuer'] or '—'}\n"
                                f"Expiración:  {not_after}\n"
                                f"Días restantes: {dias_restantes}"
                            ),
                        ))
                except (ValueError, TypeError):
                    pass

            # Comprobar cambio de fingerprint respecto al escaneo anterior
            cert_ant = self.storage.cert_anterior(self.target, host, self.scan_id)
            if cert_ant and cert["fingerprint"] and cert_ant["fingerprint"]:
                if cert["fingerprint"] != cert_ant["fingerprint"]:
                    diffs.append(Diff(
                        categoria="CERT_CAMBIADO",
                        severidad="CRITICAL",
                        activo=host,
                        descripcion=(
                            f"El certificado TLS de {host} ha cambiado desde el último "
                            "escaneo. Un cambio de fingerprint puede indicar renovación "
                            "legítima o, en el peor caso, un ataque de interposición (MitM)."
                        ),
                        evidencia=(
                            f"Host:               {host}\n"
                            f"Fingerprint anterior: {cert_ant['fingerprint']}\n"
                            f"Fingerprint actual:   {cert['fingerprint']}\n"
                            f"Emisor actual:        {cert['issuer'] or '—'}\n"
                            f"Expira:               {not_after or '—'}"
                        ),
                    ))

        return diffs

    # ── Generación de Finding VSL ────────────────────────────────────────

    def _hacer_finding(self, diff: Diff) -> Finding:
        """Convierte un Diff en un Finding normalizado VSL."""
        _remediaciones = {
            "NUEVO_SUBDOMINIO": (
                "Verificar si el subdominio es conocido y gestionado por el equipo. "
                "Si no es intencional, investigar el origen del registro DNS y eliminarlo "
                "si no es necesario. Actualizar el inventario de activos."
            ),
            "NUEVO_PUERTO": (
                "Revisar si el servicio en el nuevo puerto está autorizado y correctamente "
                "configurado. Aplicar las reglas de firewall adecuadas para restringir el "
                "acceso solo a los rangos IP necesarios."
            ),
            "CERT_EXPIRADO": (
                "Renovar el certificado TLS inmediatamente. Considerar implementar "
                "renovación automática mediante ACME/Let's Encrypt o un gestor de "
                "certificados corporativo. Verificar que los monitores de expiración "
                "están activos."
            ),
            "CERT_CAMBIADO": (
                "Verificar con el equipo de operaciones si el cambio de certificado fue "
                "autorizado y documentado. Si no, iniciar protocolo de respuesta ante "
                "incidentes para descartar un ataque de interposición (MitM). "
                "Comparar el nuevo certificado con el registrado en el sistema de gestión."
            ),
            "SERVICIO_DESAPARECIDO": (
                "Confirmar si la desaparición del servicio fue intencionada. Si no, "
                "verificar el estado del proceso y los logs del sistema. Actualizar el "
                "inventario de activos si el cierre fue planificado."
            ),
            "IP_CAMBIADA": (
                "Confirmar con el equipo de infraestructura si el cambio de IP/DNS fue "
                "autorizado. Si no, investigar posible secuestro de DNS o reconfiguración "
                "no autorizada. Revisar los registros DNS y los logs del registrador."
            ),
        }
        return Finding(
            id=self._contador.siguiente(),
            title=f"{diff.categoria.replace('_', ' ').title()} — {diff.activo}",
            severity=diff.severidad,
            description=diff.descripcion,
            evidence=diff.evidencia,
            affected=diff.activo,
            remediation=_remediaciones.get(diff.categoria, "Investigar y resolver el cambio detectado."),
            tags=["easm", "continuous", diff.categoria.lower()],
        )
