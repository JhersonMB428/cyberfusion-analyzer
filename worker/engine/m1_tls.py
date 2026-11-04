"""M1 · TLS y certificado (capa L1). Solo handshakes, sin peticiones HTTP.

Por que no sslyze: es AGPL. Usarlo dentro de un servicio que se ofrece por
red obligaria a publicar el codigo del producto. ssl + la configuracion de
OpenSSL cubren lo que la fase 1 necesita con 6 conexiones como maximo.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from .catalog import finding, positive
from .common import ModuleResult

TIMEOUT = 10
# Let's Encrypt y similares renuevan a los 30 dias de vencer: avisar antes
# haria saltar a casi todos los sitios en su renovacion normal.
SHORT_LIVED = ("Let's Encrypt", "ZeroSSL", "Google Trust", "Sectigo Public Server Authentication CA DV")


def _connect(host: str, ctx: ssl.SSLContext):
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.version(), s.getpeercert(), s.getpeercert(binary_form=True)


def _verify(host: str) -> dict:
    """Handshake con verificacion completa. Clasifica el fallo si lo hay."""
    ctx = ssl.create_default_context()
    try:
        version, cert, _ = _connect(host, ctx)
        return {"ok": True, "version": version, "cert": cert}
    except ssl.SSLCertVerificationError as e:
        code = getattr(e, "verify_code", None)
        msg = (getattr(e, "verify_message", "") or str(e)).lower()
        if "expired" in msg or code == 10:
            kind = "expired"
        elif "self-signed" in msg or "self signed" in msg or code in (18, 19):
            kind = "self_signed"
        elif "hostname" in msg or "ip address mismatch" in msg or code == 62:
            kind = "mismatch"
        elif "unable to get local issuer" in msg or code in (20, 21):
            kind = "chain"
        else:
            kind = "invalid"
        return {"ok": False, "kind": kind, "detail": msg[:160]}


def _unverified_cert(host: str) -> dict:
    """Lee el certificado sin validar, para fechas y emisor cuando falla."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    version, _, der = _connect(host, ctx)
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        org = c.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        return {"version": version,
                "not_after": c.not_valid_after_utc,
                "issuer": org[0].value if org else "?"}
    except Exception:
        return {"version": version, "not_after": None, "issuer": "?"}


def _accepts(host: str, proto: ssl.TLSVersion) -> bool:
    """True si el servidor acepta exactamente ese protocolo."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # OpenSSL 3 rechaza TLS 1.0/1.1 por defecto en el cliente; bajamos
        # el nivel de seguridad SOLO en esta prueba para poder preguntar.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = proto
        ctx.maximum_version = proto
    except (ValueError, ssl.SSLError):
        return False
    try:
        _connect(host, ctx)
        return True
    except Exception:
        return False


def _weak_ciphers(host: str) -> bool:
    """True si acepta 3DES, RC4, NULL o EXPORT con TLS 1.2."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("3DES:RC4:NULL:EXPORT:@SECLEVEL=0")
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, ssl.SSLError):
        return False         # este OpenSSL ya no sabe hablar esos cifrados
    try:
        _connect(host, ctx)
        return True
    except Exception:
        return False


def _issuer_org(cert: dict) -> str:
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return issuer.get("organizationName") or issuer.get("commonName") or "?"


def _check(host: str) -> ModuleResult:
    m = ModuleResult("L1")
    try:
        v = _verify(host)
    except (socket.timeout, TimeoutError):
        return m.undetermined("timeout")
    except socket.gaierror:
        return m.undetermined("dns_error")
    except OSError:
        return m.undetermined("http_error", "El sitio no acepta conexiones cifradas (HTTPS).")

    now = datetime.now(timezone.utc)
    if v["ok"]:
        cert = v["cert"]
        org = _issuer_org(cert)
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        version = v["version"]
    else:
        kind = v["kind"]
        try:
            raw = _unverified_cert(host)
        except Exception:
            raw = {"version": None, "not_after": None, "issuer": "?"}
        org, exp, version = raw["issuer"], raw["not_after"], raw["version"]
        ev = {"error": v["detail"]}
        if kind == "expired":
            m.findings.append(finding("F-TLS-001", "alto", ev))
        elif kind == "self_signed":
            m.findings.append(finding("F-TLS-003", "alto", ev))
        elif kind == "mismatch":
            m.findings.append(finding("F-TLS-004", "alto", ev))
        elif kind == "chain":
            m.findings.append(finding("F-TLS-005", "medio", ev))
        else:
            m.findings.append(finding("F-TLS-003", "alto", ev))

    days = (exp - now).days if exp else None
    if days is not None and days >= 0 and v["ok"]:
        short = any(s in org for s in SHORT_LIVED)
        high_at, med_at = (7, 14) if short else (7, 30)
        if days <= high_at:
            m.findings.append(finding("F-TLS-002", "alto", {"days_left": days}, n=days))
        elif days <= med_at:
            m.findings.append(finding("F-TLS-002", "medio", {"days_left": days}, n=days))
        else:
            m.positives.append(positive("P-TLS-001", n=days, emisor=org))

    old = [name for name, p in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                                ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
           if _accepts(host, p)]
    if old:
        m.findings.append(finding("F-TLS-006", "medio", {"accepted": old},
                                  protocolos=" y ".join(old)))
    if _weak_ciphers(host):
        m.findings.append(finding("F-TLS-007", "medio", {"ciphers": "3DES/RC4/NULL/EXPORT"}))
    if version == "TLSv1.3":
        m.positives.append(positive("P-TLS-002", protocolo="TLS 1.3"))

    parts = []
    if version:
        parts.append(version.replace("TLSv", "TLS "))
    if days is not None:
        parts.append(f"vence en {days} días" if days >= 0 else "vencido")
    m.note = " · ".join(parts) or None
    m.evidence = {"issuer": org, "days_left": days, "negotiated": version}
    return m.finish()


async def run(host: str) -> ModuleResult:
    return await asyncio.to_thread(_check, host)
