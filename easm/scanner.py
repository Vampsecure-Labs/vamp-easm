# © VampSecure Studios — VampSecure Labs Security Research Division
"""
scanner.py — Motor de escaneo en tres capas para vamp-easm
===========================================================
Realiza el descubrimiento de la superficie de ataque externa en tres fases:

  Capa 1 · DNS/Subdominios
    Consulta crt.sh (Certificate Transparency) y HackerTarget (hostsearch)
    para enumerar subdominios conocidos del target. Solo usa urllib (stdlib).

  Capa 2 · Puertos/Servicios
    Escaneo TCP async sobre el top-100 de puertos (o lista personalizada).
    Si nmap está en PATH y se activa --nmap, se usa como backend.

  Capa 3 · Certificados TLS
    Para cada subdominio con el puerto 443 abierto (o cualquier puerto HTTPS
    detectado), inspecciona el certificado TLS: hostname, emisor, expiración,
    SANs y si es autofirmado.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Top-100 puertos a escanear (fusión de servicios comunes + admin + web)
# ---------------------------------------------------------------------------

TOP_100_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119,
    135, 139, 143, 161, 179, 389, 443, 445, 465, 500,
    514, 515, 587, 631, 636, 873, 993, 995, 1080, 1194,
    1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376, 3000,
    3001, 3306, 3389, 3478, 3632, 4443, 4444, 4848, 5000,
    5001, 5432, 5601, 5672, 5900, 5985, 5986, 6379, 6443,
    7001, 7002, 7070, 7443, 7474, 7777, 8000, 8008, 8080,
    8081, 8082, 8088, 8089, 8161, 8443, 8500, 8530, 8888,
    8983, 9000, 9001, 9042, 9090, 9091, 9092, 9200, 9300,
    9418, 9443, 9999, 10000, 11211, 15672, 16379, 25565,
    27017, 27018, 28017, 50000, 50070, 61616,
]

# Puertos que típicamente llevan TLS
_PUERTOS_TLS: Set[int] = {
    443, 465, 636, 993, 995, 4443, 5601, 5986,
    6443, 7443, 8443, 9200, 9300, 9443, 10000,
}

# Timeout de conexión TCP en segundos
_TCP_TIMEOUT = 2.0
# Timeout para llamadas HTTP a fuentes externas
_HTTP_TIMEOUT = 15

# Semáforo para limitar las conexiones simultáneas en el escaneo de puertos
_MAX_CONCURRENT = 200


# ---------------------------------------------------------------------------
# Estructuras de datos de resultado
# ---------------------------------------------------------------------------

@dataclass
class Subdominio:
    """Subdominio descubierto con su resolución IP."""
    nombre: str
    ips: List[str] = field(default_factory=list)


@dataclass
class PuertoAbierto:
    """Puerto TCP abierto con información de servicio."""
    host: str
    puerto: int
    protocolo: str = "tcp"
    servicio: Optional[str] = None


@dataclass
class CertInfo:
    """Información de un certificado TLS inspeccionado."""
    host: str
    puerto: int
    issued_to: Optional[str]
    issuer: Optional[str]
    not_after: Optional[str]          # ISO-8601 UTC
    sans: List[str] = field(default_factory=list)
    fingerprint: Optional[str] = None
    autofirmado: bool = False
    error: Optional[str] = None


@dataclass
class ResultadoEscaneo:
    """Resultado completo de un escaneo para un target."""
    target: str
    subdominios: List[Subdominio] = field(default_factory=list)
    puertos: List[PuertoAbierto] = field(default_factory=list)
    certs: List[CertInfo] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Capa 1 — Enumeración de subdominios
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = _HTTP_TIMEOUT) -> str:
    """Realiza una petición HTTP GET con stdlib y devuelve el body como texto."""
    req = urllib.request.Request(url, headers={"User-Agent": "vamp-easm/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _subdominios_crtsh(dominio: str) -> Set[str]:
    """
    Consulta Certificate Transparency (crt.sh) para obtener subdominios
    históricos del dominio. Devuelve un conjunto de nombres normalizados.
    """
    url = f"https://crt.sh/?q=%.{dominio}&output=json"
    raw = _http_get(url)
    if not raw:
        return set()
    try:
        datos = json.loads(raw)
    except json.JSONDecodeError:
        return set()

    resultado: Set[str] = set()
    for entrada in datos:
        # name_value puede contener múltiples nombres separados por \n
        for nombre in str(entrada.get("name_value", "")).splitlines():
            nombre = nombre.strip().lstrip("*.")
            if nombre and dominio in nombre:
                resultado.add(nombre.lower())
    return resultado


def _subdominios_hackertarget(dominio: str) -> Set[str]:
    """
    Consulta HackerTarget hostsearch para obtener subdominios del dominio.
    El endpoint devuelve líneas en formato 'host,ip'.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={dominio}"
    raw = _http_get(url)
    resultado: Set[str] = set()
    for linea in raw.splitlines():
        partes = linea.strip().split(",")
        if partes:
            nombre = partes[0].strip().lower()
            if nombre and dominio in nombre and not nombre.startswith("API"):
                resultado.add(nombre)
    return resultado


def _resolver_ip(nombre: str) -> List[str]:
    """Resuelve un nombre de host a sus IPs (IPv4 e IPv6). Devuelve lista vacía si falla."""
    try:
        info = socket.getaddrinfo(nombre, None)
        return list({entry[4][0] for entry in info})
    except Exception:
        return []


def enumerar_subdominios(target: str) -> List[Subdominio]:
    """
    Enumera subdominios del target consultando crt.sh y HackerTarget.
    Siempre incluye el propio target como subdominio raíz.

    Parameters
    ----------
    target : Dominio raíz a analizar (p.ej. 'ejemplo.com')

    Returns
    -------
    list[Subdominio] : Subdominios con sus IPs resueltas
    """
    nombres: Set[str] = set()
    nombres.add(target)                         # el dominio raíz siempre
    nombres.update(_subdominios_crtsh(target))
    nombres.update(_subdominios_hackertarget(target))

    resultado: List[Subdominio] = []
    for nombre in sorted(nombres):
        ips = _resolver_ip(nombre)
        resultado.append(Subdominio(nombre=nombre, ips=ips))
    return resultado


# ---------------------------------------------------------------------------
# Capa 2 — Escaneo de puertos (asyncio TCP connect)
# ---------------------------------------------------------------------------

async def _tcp_connect(
    sem: asyncio.Semaphore,
    host: str,
    puerto: int,
    timeout: float = _TCP_TIMEOUT,
) -> Optional[PuertoAbierto]:
    """
    Intenta una conexión TCP al host:puerto bajo el semáforo dado.
    Devuelve PuertoAbierto si el puerto está abierto, None si está cerrado/filtrado.
    """
    async with sem:
        try:
            conn = asyncio.open_connection(host, puerto)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            servicio = _nombre_servicio(puerto)
            return PuertoAbierto(host=host, puerto=puerto, servicio=servicio)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


def _nombre_servicio(puerto: int) -> Optional[str]:
    """Intenta obtener el nombre de servicio estándar para un puerto."""
    try:
        return socket.getservbyport(puerto, "tcp")
    except OSError:
        return None


async def _escanear_host_async(
    host: str,
    puertos: List[int],
    sem: asyncio.Semaphore,
) -> List[PuertoAbierto]:
    """Escanea todos los puertos de un host de forma concurrente."""
    tareas = [_tcp_connect(sem, host, p) for p in puertos]
    resultados = await asyncio.gather(*tareas)
    return [r for r in resultados if r is not None]


def escanear_puertos_stdlib(
    subdominios: List[Subdominio],
    puertos: List[int],
) -> List[PuertoAbierto]:
    """
    Escanea los puertos especificados en todos los subdominios usando asyncio TCP.

    Parameters
    ----------
    subdominios : Lista de subdominios a escanear
    puertos     : Lista de puertos a probar

    Returns
    -------
    list[PuertoAbierto] : Puertos abiertos encontrados
    """
    sem = asyncio.Semaphore(_MAX_CONCURRENT)

    async def _main() -> List[PuertoAbierto]:
        tareas = []
        for sub in subdominios:
            if sub.ips:                          # solo si resuelve
                tareas.append(_escanear_host_async(sub.nombre, puertos, sem))
        if not tareas:
            return []
        listas = await asyncio.gather(*tareas)
        return [p for lista in listas for p in lista]

    return asyncio.run(_main())


def escanear_puertos_nmap(
    subdominios: List[Subdominio],
    puertos: List[int],
) -> List[PuertoAbierto]:
    """
    Escanea puertos usando nmap como backend (requiere nmap en PATH).
    Usa salida XML de nmap para parsear los puertos abiertos.

    Parameters
    ----------
    subdominios : Lista de subdominios a escanear
    puertos     : Lista de puertos a probar

    Returns
    -------
    list[PuertoAbierto] : Puertos abiertos
    """
    hosts_con_ip = [s.nombre for s in subdominios if s.ips]
    if not hosts_con_ip:
        return []

    puertos_str = ",".join(str(p) for p in sorted(puertos))
    cmd = [
        "nmap", "-sT", "-Pn", "-T4",
        f"-p{puertos_str}",
        "--open",
        "-oX", "-",          # salida XML por stdout
    ] + hosts_con_ip

    try:
        resultado = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return _parsear_nmap_xml(resultado.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return []


def _parsear_nmap_xml(xml: str) -> List[PuertoAbierto]:
    """Parsea la salida XML de nmap para extraer puertos abiertos."""
    import xml.etree.ElementTree as ET
    abiertos: List[PuertoAbierto] = []
    if not xml.strip():
        return abiertos
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return abiertos

    for host in root.findall(".//host"):
        hostname_el = host.find(".//hostname[@type='user']")
        addr_el = host.find(".//address[@addrtype='ipv4']")
        if hostname_el is not None:
            host_str = hostname_el.get("name", "")
        elif addr_el is not None:
            host_str = addr_el.get("addr", "")
        else:
            continue

        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            puerto_num = int(port.get("portid", 0))
            servicio_el = port.find("service")
            servicio = servicio_el.get("name") if servicio_el is not None else None
            abiertos.append(PuertoAbierto(
                host=host_str,
                puerto=puerto_num,
                servicio=servicio,
            ))
    return abiertos


# ---------------------------------------------------------------------------
# Capa 3 — Inspección de certificados TLS
# ---------------------------------------------------------------------------

def inspeccionar_cert(host: str, puerto: int = 443, timeout: float = 5.0) -> CertInfo:
    """
    Abre una conexión TLS al host:puerto y extrae la información del certificado.

    Comprueba si el certificado es autofirmado (mismo CN en issuer y subject),
    calcula la huella SHA-256 y extrae los SANs.

    Parameters
    ----------
    host    : Hostname al que conectarse (se usa también para SNI)
    puerto  : Puerto TLS (por defecto 443)
    timeout : Segundos de timeout de conexión

    Returns
    -------
    CertInfo : Estructura con todos los metadatos del certificado
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE       # capturamos aunque sea inválido

    try:
        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert_der = tls.getpeercert(binary_form=True)
                cert     = tls.getpeercert()
    except Exception as exc:
        return CertInfo(host=host, puerto=puerto,
                        issued_to=None, issuer=None, not_after=None,
                        error=str(exc))

    # Huella SHA-256
    import hashlib
    fingerprint = hashlib.sha256(cert_der).hexdigest() if cert_der else None

    # Emisor y subject
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer", []))
    issued_to = subject.get("commonName")
    issuer_cn = issuer.get("commonName") or issuer.get("organizationName")

    # Fecha de expiración → ISO-8601 UTC
    not_after_raw = cert.get("notAfter", "")
    not_after_iso: Optional[str] = None
    if not_after_raw:
        try:
            dt = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
            not_after_iso = dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            not_after_iso = not_after_raw

    # SANs (Subject Alternative Names)
    sans: List[str] = []
    for tipo, valor in cert.get("subjectAltName", []):
        if tipo == "DNS":
            sans.append(valor)

    # Autofirmado: el CN del emisor coincide con el subject
    autofirmado = bool(
        issued_to and issuer_cn and issued_to == issuer_cn
    )

    return CertInfo(
        host=host,
        puerto=puerto,
        issued_to=issued_to,
        issuer=issuer_cn,
        not_after=not_after_iso,
        sans=sans,
        fingerprint=fingerprint,
        autofirmado=autofirmado,
    )


def inspeccionar_certs_batch(
    subdominios: List[Subdominio],
    puertos_abiertos: List[PuertoAbierto],
) -> List[CertInfo]:
    """
    Inspecciona certificados TLS para todos los subdominios con puertos TLS abiertos.
    Siempre intenta el puerto 443 si el subdominio resuelve, más cualquier
    puerto de la lista _PUERTOS_TLS que esté abierto.

    Parameters
    ----------
    subdominios      : Subdominios descubiertos en la capa 1
    puertos_abiertos : Puertos abiertos detectados en la capa 2

    Returns
    -------
    list[CertInfo] : Certificados inspeccionados
    """
    # Construir conjunto de (host, puerto) a inspeccionar
    candidatos: Set[Tuple[str, int]] = set()

    # Intentar 443 para todos los subdominios que resuelven
    for sub in subdominios:
        if sub.ips:
            candidatos.add((sub.nombre, 443))

    # Añadir puertos TLS abiertos detectados
    for pa in puertos_abiertos:
        if pa.puerto in _PUERTOS_TLS:
            candidatos.add((pa.host, pa.puerto))

    certs: List[CertInfo] = []
    for host, puerto in sorted(candidatos):
        cert = inspeccionar_cert(host, puerto)
        certs.append(cert)
    return certs


# ---------------------------------------------------------------------------
# Función principal de escaneo
# ---------------------------------------------------------------------------

def ejecutar_escaneo(
    target: str,
    puertos: Optional[List[int]] = None,
    usar_nmap: bool = False,
) -> ResultadoEscaneo:
    """
    Ejecuta el escaneo completo en tres capas para el target dado.

    Parameters
    ----------
    target     : Dominio raíz a escanear
    puertos    : Lista de puertos a probar (None → TOP_100_PORTS)
    usar_nmap  : Si True y nmap está en PATH, usarlo como backend de puertos

    Returns
    -------
    ResultadoEscaneo : Estructura con subdominios, puertos abiertos y certs
    """
    if puertos is None:
        puertos = TOP_100_PORTS

    # Capa 1 — subdominios
    subdominios = enumerar_subdominios(target)

    # Capa 2 — puertos
    nmap_disponible = usar_nmap and shutil.which("nmap") is not None
    if nmap_disponible:
        puertos_abiertos = escanear_puertos_nmap(subdominios, puertos)
    else:
        puertos_abiertos = escanear_puertos_stdlib(subdominios, puertos)

    # Capa 3 — certificados TLS
    certs = inspeccionar_certs_batch(subdominios, puertos_abiertos)

    return ResultadoEscaneo(
        target=target,
        subdominios=subdominios,
        puertos=puertos_abiertos,
        certs=certs,
    )
