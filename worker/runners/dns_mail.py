"""Runner: DNS y proteccion de correo (SPF, DMARC, DNSSEC, CAA)."""
import asyncio
from urllib.parse import urlparse
import dns.resolver
from ..schema import Finding


def _query(name: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=8)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []


def _parse_tags(record: str) -> dict[str, str]:
    """Parsea 'v=DMARC1;p=quarantine;sp=none' a un dict.

    NO usar 'in' sobre la cadena cruda: 'sp=none' contiene 'p=none'
    como subcadena y produce un falso positivo.
    """
    return dict(
        part.split("=", 1)
        for part in record.replace(" ", "").split(";")
        if "=" in part
    )


def _collect(domain: str) -> list[Finding]:
    out: list[Finding] = []
    txt = _query(domain, "TXT")

    # --- SPF ---
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        out.append(Finding("dns.spf.missing", "surface", "dns_mail",
                           "medium", "confirmed", "low",
                           evidence={"domain": domain}))
    elif any("+all" in s for s in spf):
        out.append(Finding("dns.spf.permissive", "surface", "dns_mail",
                           "high", "confirmed", "low",
                           evidence={"record": spf[0]}))
    else:
        out.append(Finding("ok.dns.spf", "surface", "dns_mail",
                           "info", "confirmed", "low",
                           evidence={"record": spf[0][:120]}))

    # --- DMARC ---
    dmarc = _query(f"_dmarc.{domain}", "TXT")
    policy = next((d for d in dmarc if d.lower().startswith("v=dmarc1")), None)

    if not policy:
        out.append(Finding("dns.dmarc.missing", "surface", "dns_mail",
                           "high", "confirmed", "low",
                           evidence={"domain": domain}))
    else:
        tags = _parse_tags(policy)
        p = tags.get("p", "none").lower()
        sp = tags.get("sp", p).lower()

        if p == "none":
            out.append(Finding("dns.dmarc.monitor_only", "surface", "dns_mail",
                               "medium", "confirmed", "medium",
                               evidence={"policy": p, "record": policy}))
        elif p == "quarantine":
            out.append(Finding("dns.dmarc.not_enforced", "surface", "dns_mail",
                               "low", "confirmed", "low",
                               evidence={"policy": p}))
        else:  # p=reject
            out.append(Finding("ok.dns.dmarc", "surface", "dns_mail",
                               "info", "confirmed", "low",
                               evidence={"policy": p}))

        if sp == "none" and p != "none":
            out.append(Finding("dns.dmarc.subdomain_unprotected", "surface", "dns_mail",
                               "low", "confirmed", "low",
                               evidence={"sp": sp, "domain": domain}))

    # --- CAA ---
    if not _query(domain, "CAA"):
        out.append(Finding("dns.caa.missing", "surface", "dns_mail",
                           "low", "confirmed", "low",
                           evidence={"domain": domain}))

    # --- DNSSEC: solo informativo. Muchos registradores ni lo soportan,
    # asi que penalizarlo genera ruido sin accion posible para el cliente.
    if not _query(domain, "DNSKEY"):
        out.append(Finding("dns.dnssec.missing", "surface", "dns_mail",
                           "info", "firm", "medium",
                           evidence={"domain": domain}))
    else:
        out.append(Finding("ok.dns.dnssec", "surface", "dns_mail",
                           "info", "confirmed", "low",
                           evidence={"domain": domain}))
    return out


async def run(target: str, client) -> list[Finding]:
    host = urlparse(target).hostname or ""
    domain = host[4:] if host.startswith("www.") else host
    if not domain:
        return []
    return await asyncio.to_thread(_collect, domain)
