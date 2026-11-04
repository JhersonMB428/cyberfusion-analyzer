"""M7 a M9 · Reputacion, dominio y marca, superficie visible.

Ninguno toca el sitio analizado: consultan DNS publicos y fuentes de
terceros. Por eso se determinan aunque un firewall bloquee todo el HTTP.

Fuentes elegidas por coste cero y uso comercial sin licencia:
  - Reputacion: filtros de seguridad DNS de Quad9 y Cloudflare (1.1.1.2).
    Se compara su respuesta con la de un resolver sin filtro: si el filtro
    bloquea un dominio que si existe, el dominio esta marcado como malicioso.
    URLhaus se suma solo si se configura URLHAUS_AUTH_KEY (clave gratuita).
    Se descartaron Google Safe Browsing (Lookup API: uso no comercial),
    Spamhaus DBL (licencia para uso comercial) y Shodan InternetDB (uso no
    comercial).
  - Dominio: RDAP segun el registro de IANA; si el TLD no tiene RDAP (.pe),
    WHOIS por el puerto 43.
  - Marca: permutaciones de dnstwist, resueltas aqui con DNS.
  - Superficie: crt.sh (registros de transparencia de certificados) con
    Certspotter de respaldo.
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
from datetime import datetime, timezone

import dns.resolver
import httpx

from .catalog import finding, positive
from .common import DnsFail, ModuleResult, dns_safe

EXT_TIMEOUT = 8


def _resolver(ip: str) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [ip]
    r.timeout = r.lifetime = 4
    return r


def _ask(resolver, name: str) -> list[str] | None:
    """A del dominio. [] = no existe/bloqueado, None = el servidor no respondio."""
    try:
        return [x.to_text() for x in resolver.resolve(name, "A", lifetime=4)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return None


# ----------------------------------------------------------- M7 reputacion
def _reputation(domain: str) -> ModuleResult:
    m = ModuleResult("L8")
    names = [domain, f"www.{domain}"]
    plain = None
    for n in names:
        plain = _ask(_resolver("9.9.9.10"), n) or _ask(_resolver("1.1.1.1"), n)
        if plain:
            target = n
            break
    if not plain:
        # El dominio no tiene web: no hay nada que un filtro pueda bloquear.
        m.note = "El dominio no publica una web que los filtros puedan evaluar"
        m.state = "ok"
        m.positives.append(positive("P-REP-001", n=0))
        return m

    sources, flagged = 0, []
    q9 = _ask(_resolver("9.9.9.9"), target)
    if q9 is not None:
        sources += 1
        if q9 == []:
            flagged.append("Quad9")
    cf = _ask(_resolver("1.1.1.2"), target)
    if cf is not None:
        sources += 1
        if cf == [] or cf == ["0.0.0.0"]:
            flagged.append("Cloudflare")

    key = os.getenv("URLHAUS_AUTH_KEY", "")
    if key:
        try:
            r = httpx.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain},
                           headers={"Auth-Key": key}, timeout=EXT_TIMEOUT)
            j = r.json()
            sources += 1
            if j.get("query_status") == "ok" and int(j.get("url_count") or 0) > 0:
                m.findings.append(finding("F-REP-002", "alto", {"urls": int(j["url_count"])}))
        except Exception:
            pass

    if sources < 2:
        return m.undetermined("source_unavailable")
    if flagged:
        m.findings.append(finding("F-REP-001", "alto", {"filters": flagged}))
    else:
        m.positives.append(positive("P-REP-001", n=sources))
    m.note = (f"Marcado como peligroso por {', '.join(flagged)}" if flagged
              else f"Sin registros en las {sources} fuentes consultadas")
    m.evidence = {"sources": sources, "flagged": flagged}
    return m.finish()


# ------------------------------------------------------ M8 dominio y marca
_rdap_boot: dict[str, str] | None = None


def _rdap_base(tld: str) -> str | None:
    global _rdap_boot
    if _rdap_boot is None:
        _rdap_boot = {}
        try:
            j = httpx.get("https://data.iana.org/rdap/dns.json", timeout=EXT_TIMEOUT).json()
            for tlds, urls in j.get("services", []):
                for t in tlds:
                    _rdap_boot[t.lower()] = urls[0]
        except Exception:
            _rdap_boot = None
            return None
    return (_rdap_boot or {}).get(tld)


DATE_RE = re.compile(r"(?:Registry Expiry Date|Expiration Date|Expiry Date|paid-till|expire[sd]?)\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.I)
WHOIS_PE = "kero.yachay.pe"


def _whois(domain: str, server: str) -> str:
    with socket.create_connection((server, 43), timeout=EXT_TIMEOUT) as s:
        s.sendall((domain + "\r\n").encode())
        buf = b""
        while len(buf) < 60000:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return buf.decode("utf-8", "replace")


def _domain_info(domain: str) -> dict:
    """{'expires': datetime|None, 'locked': bool|None, 'source': str|None}"""
    tld = domain.rsplit(".", 1)[-1].lower()
    base = _rdap_base(tld)
    if base:
        try:
            r = httpx.get(base.rstrip("/") + f"/domain/{domain}", timeout=EXT_TIMEOUT,
                          headers={"Accept": "application/rdap+json"}, follow_redirects=True)
            if r.status_code == 200:
                j = r.json()
                exp = next((e.get("eventDate") for e in j.get("events", [])
                            if e.get("eventAction") == "expiration"), None)
                status = " ".join(j.get("status", [])).lower()
                return {"expires": datetime.fromisoformat(exp.replace("Z", "+00:00")) if exp else None,
                        "locked": "transfer prohibited" in status, "source": "RDAP"}
        except Exception:
            pass
    server = WHOIS_PE if tld == "pe" else None
    if not server:
        try:
            ref = re.search(r"whois:\s*(\S+)", _whois(tld, "whois.iana.org"))
            server = ref.group(1) if ref else None
        except Exception:
            server = None
    if server:
        try:
            raw = _whois(domain, server)
            md = DATE_RE.search(raw)
            exp = datetime.strptime(md.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc) if md else None
            low = raw.lower()
            locked = ("transferprohibited" in low.replace(" ", "")) if "status" in low else None
            return {"expires": exp, "locked": locked, "source": "WHOIS"}
        except Exception:
            pass
    return {"expires": None, "locked": None, "source": None}


def _lookalikes(domain: str) -> tuple[list[str], list[str]]:
    """(con correo, sin correo) entre las variantes registradas, max 100."""
    try:
        import dnstwist
        fz = dnstwist.Fuzzer(domain)
        fz.generate()
        variants = [d["domain"] for d in fz.domains if d["domain"] != domain][:100]
    except Exception:
        return [], []
    with_mx, without = [], []
    res = _resolver("1.1.1.1")

    def check(v):
        a = _ask(res, v)
        if not a:
            return None
        try:
            mx = bool(res.resolve(v, "MX", lifetime=3))
        except Exception:
            mx = False
        return v, mx

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as ex:
        for r in ex.map(check, variants):
            if r:
                (with_mx if r[1] else without).append(r[0])
    return with_mx, without


def _domain_brand(domain: str) -> ModuleResult:
    m = ModuleResult("L9")
    info = _domain_info(domain)
    with_mx, without = _lookalikes(domain)
    days = None
    if info["expires"]:
        days = (info["expires"] - datetime.now(timezone.utc)).days
        if days < 30:
            m.findings.append(finding("F-DOM-001", "alto", {"days_left": days}, n=days))
        elif days < 90:
            m.findings.append(finding("F-DOM-002", "medio", {"days_left": days}, n=days))
    if info["locked"] is False:
        m.findings.append(finding("F-DOM-003", "observ", {}))
    if days is not None and days >= 90 and info["locked"]:
        m.positives.append(positive("P-DOM-001", n=days))
    if with_mx:
        m.findings.append(finding("F-BRAND-001", "medio", {"examples": with_mx[:5]}, n=len(with_mx)))
    if without:
        m.findings.append(finding("F-BRAND-002", "observ", {"examples": without[:5]}, n=len(without)))
    if info["source"] is None and not (with_mx or without) and days is None:
        # Sin registro ni variantes no hay nada que afirmar.
        return m.undetermined("source_unavailable")
    parts = []
    parts.append(f"Vence en {days} días" if days is not None else "Fecha de vencimiento no pública")
    if with_mx or without:
        parts.append(f"{len(with_mx) + len(without)} dominios parecidos registrados")
    m.note = " · ".join(parts)
    m.evidence = {"expires_days": days, "source": info["source"],
                  "lookalikes_mx": with_mx[:5], "lookalikes": without[:5]}
    return m.finish()


# --------------------------------------------------------- M9 superficie
SENSITIVE = re.compile(r"(^|[.-])(dev|test|testing|staging|stage|stg|qa|uat|admin|panel|vpn|git|gitlab|jenkins|backup|bak|old|beta|demo|intranet|cpanel|webmail|phpmyadmin|db|mysql)([.-]|$)", re.I)
# Servicios cuyo nombre queda libre si se borra el recurso: el CNAME que
# sigue apuntando ahi permite a un tercero quedarse con el subdominio.
TAKEOVER = (".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net",
            ".blob.core.windows.net", ".azureedge.net", ".herokudns.com", ".herokuapp.com",
            ".s3.amazonaws.com", ".elasticbeanstalk.com", ".github.io", ".netlify.app",
            ".vercel.app", ".pantheonsite.io", ".ghost.io", ".surge.sh", ".bitbucket.io")


def _subdomains(domain: str) -> list[str] | None:
    names: set[str] = set()
    try:
        r = httpx.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                      timeout=15)
        if r.status_code == 200:
            for row in r.json():
                for n in str(row.get("name_value", "")).split("\n"):
                    names.add(n.strip().lower())
    except Exception:
        pass
    if not names:
        try:
            r = httpx.get("https://api.certspotter.com/v1/issuances",
                          params={"domain": domain, "include_subdomains": "true",
                                  "expand": "dns_names"}, timeout=EXT_TIMEOUT)
            if r.status_code == 200:
                for row in r.json():
                    for n in row.get("dns_names", []):
                        names.add(n.strip().lower())
            elif r.status_code == 429:
                return None
        except Exception:
            return None
    subs = sorted({n.lstrip("*.") for n in names
                   if n.endswith("." + domain) and n.lstrip("*.") != domain})
    return subs[:100]


def _surface(domain: str) -> ModuleResult:
    m = ModuleResult("L10")
    subs = _subdomains(domain)
    if subs is None:
        return m.undetermined("source_unavailable")
    sensitive = [s for s in subs if SENSITIVE.search(s[: -len(domain) - 1])]
    alive_sensitive = [s for s in sensitive if dns_safe(s, "A") or dns_safe(s, "CNAME")]
    if alive_sensitive:
        m.findings.append(finding("F-SURF-001", "medio", {"subdomains": alive_sensitive[:5]}))
    dangling = []
    for s in subs[:60]:
        cn = dns_safe(s, "CNAME")
        if not cn:
            continue
        target = cn[0].rstrip(".").lower()
        if target.endswith(TAKEOVER) and not dns_safe(target, "A") and not dns_safe(target, "CNAME"):
            dangling.append(s)
    if dangling:
        m.findings.append(finding("F-SURF-002", "alto", {"subdomains": dangling[:5]}))
    m.note = (f"{len(subs)} subdominios en certificados públicos"
              + (f" · {len(alive_sensitive)} sensibles" if alive_sensitive else ""))
    m.evidence = {"subdomains": len(subs)}
    return m.finish()


async def reputation(domain: str) -> ModuleResult:
    return await asyncio.to_thread(_reputation, domain)


async def domain_brand(domain: str) -> ModuleResult:
    return await asyncio.to_thread(_domain_brand, domain)


async def surface(domain: str) -> ModuleResult:
    return await asyncio.to_thread(_surface, domain)
