"""Piezas compartidas por los modulos del motor 0.15."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.resolver
import dns.exception
import tldextract

LAYERS: list[tuple[str, str]] = [
    ("L1", "Certificado y cifrado"),
    ("L2", "DNS y protección de correo"),
    ("L3", "Cabeceras de seguridad"),
    ("L4", "Archivos sensibles expuestos"),
    ("L5", "Gestor de contenidos y extensiones"),
    ("L6", "Software del servidor"),
    ("L7", "Vulnerabilidades conocidas"),
    ("L8", "Reputación y listas negras"),
    ("L9", "Dominio y marca"),
    ("L10", "Superficie visible (subdominios)"),
]
LAYER_NAME = dict(LAYERS)

REASON_NOTE = {
    "waf_blocked": "Un firewall de aplicación bloqueó el análisis automatizado.",
    "timeout": "El sitio tardó demasiado en responder.",
    "http_error": "El sitio respondió con un error.",
    "dns_error": "No pudimos resolver este dominio.",
    "rate_limited": "Una fuente externa limitó las consultas. Reintenta más tarde.",
    "source_unavailable": "Una fuente externa no estuvo disponible.",
    "needs_verification": "Requiere verificar la propiedad del dominio.",
    "not_applicable": "No aplica a este sitio.",
}

# Sin tldextract online: usa la lista de sufijos que trae empaquetada.
# Descargarla en cada arranque seria otra dependencia de red innecesaria.
_tld = tldextract.TLDExtract(suffix_list_urls=())


def registrable(host: str) -> str:
    """'www.tienda.empresa.com.pe' -> 'empresa.com.pe'."""
    ext = _tld(host)
    return ext.top_domain_under_public_suffix or host


@dataclass
class ModuleResult:
    layer: str
    state: str = "ok"                 # ok | attention | undetermined | needs_verification
    reason: str | None = None
    note: str | None = None
    findings: list[dict] = field(default_factory=list)
    positives: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def undetermined(self, reason: str, note: str | None = None) -> "ModuleResult":
        self.state, self.reason = "undetermined", reason
        self.note = note or REASON_NOTE.get(reason)
        self.findings, self.positives = [], []
        return self

    def finish(self) -> "ModuleResult":
        """ok o attention segun haya hallazgos que no sean observaciones."""
        if self.state == "undetermined" or self.state == "needs_verification":
            return self
        real = [f for f in self.findings if f["severity"] != "observ"]
        self.state = "attention" if real else "ok"
        return self


# ------------------------------------------------------------------ DNS
_resolver = dns.resolver.Resolver()
_resolver.lifetime = 5
_resolver.timeout = 5


class DnsFail(Exception):
    """El servidor DNS no respondio (distinto de 'no existe el registro')."""


def dns_query(name: str, rtype: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    """Registros como texto. [] si no existen; DnsFail si no hubo respuesta."""
    res = resolver or _resolver
    try:
        ans = res.resolve(name, rtype, lifetime=5)
        return [r.to_text().strip('"').replace('" "', "") for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.resolver.NoNameservers:
        return []
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
        raise DnsFail(str(e)) from e


def dns_safe(name: str, rtype: str) -> list[str]:
    try:
        return dns_query(name, rtype)
    except DnsFail:
        return []


async def adns(name: str, rtype: str) -> list[str]:
    return await asyncio.to_thread(dns_safe, name, rtype)
