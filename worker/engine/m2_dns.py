"""M2 · DNS y proteccion de correo (capa L2). Solo consultas DNS."""
from __future__ import annotations

import asyncio

from .catalog import finding, positive
from .common import DnsFail, ModuleResult, dns_query, dns_safe

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2",
                  "s1", "s2", "mail", "dkim", "smtp", "zoho", "mxvault",
                  "everlytickey1", "hs1", "hs2", "sendgrid", "mandrill")
SPF_LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _tags(record: str) -> dict[str, str]:
    # Nunca buscar subcadenas en el registro crudo: "sp=none" contiene "p=none".
    return {k.strip().lower(): v.strip() for k, v in
            (p.split("=", 1) for p in record.split(";") if "=" in p)}


def _spf_lookups(record: str, depth: int = 0, seen: set | None = None) -> int:
    """Cuenta las consultas DNS que exige el SPF, siguiendo include/redirect.

    El limite del estandar es 10: pasado ese numero el receptor da el SPF
    por invalido (permerror) y la proteccion deja de funcionar.
    """
    seen = seen if seen is not None else set()
    if depth > 10:
        return 99
    n = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            n += 1
            target = t.split(":", 1)[1] if ":" in t else t.split("=", 1)[1]
            if target in seen:
                continue
            seen.add(target)
            sub = [r for r in dns_safe(target, "TXT") if r.lower().startswith("v=spf1")]
            if sub:
                n += _spf_lookups(sub[0], depth + 1, seen)
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "mx:", "a/", "mx/", "ptr:", "exists:")):
            n += 1
    return n


def _check(domain: str) -> ModuleResult:
    m = ModuleResult("L2")
    try:
        txt = dns_query(domain, "TXT")
        mx = dns_query(domain, "MX")
        ns = dns_query(domain, "NS")
    except DnsFail:
        return m.undetermined("dns_error")
    if not ns and not txt and not mx and not dns_safe(domain, "A"):
        return m.undetermined("dns_error")

    has_mail = bool(mx)
    m.evidence["mx"] = bool(mx)

    # ---------------------------------------------------------------- SPF
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        m.findings.append(finding("F-MAIL-004", "alto" if has_mail else "medio",
                                  {"domain": domain}))
    else:
        rec = spf[0]
        terms = rec.lower().split()
        if len(spf) > 1:
            m.findings.append(finding("F-MAIL-007", "medio", {"records": len(spf)}))
        elif "+all" in terms:
            m.findings.append(finding("F-MAIL-005", "alto", {"spf": rec[:200]}))
        elif "?all" in terms:
            m.findings.append(finding("F-MAIL-006", "medio", {"spf": rec[:200]}))
        else:
            lookups = _spf_lookups(rec)
            if lookups > 10:
                m.findings.append(finding("F-MAIL-007", "medio", {"lookups": lookups}))
            else:
                m.positives.append(positive("P-MAIL-001", spf=rec[:90]))

    # -------------------------------------------------------------- DMARC
    dmarc = [d for d in dns_safe(f"_dmarc.{domain}", "TXT") if d.lower().startswith("v=dmarc1")]
    if not dmarc:
        m.findings.append(finding("F-MAIL-001", "alto" if has_mail else "medio",
                                  {"domain": domain}))
    else:
        tags = _tags(dmarc[0])
        p = tags.get("p", "none").lower()
        ev = {"dmarc": dmarc[0][:200]}
        if p == "none":
            m.findings.append(finding("F-MAIL-002", "medio", ev))
        elif p == "quarantine":
            m.findings.append(finding("F-MAIL-003", "bajo", ev))
        else:
            m.positives.append(positive("P-MAIL-002"))

    # --------------------------------------------------------------- DKIM
    # Nunca concluyente: el selector puede llamarse de cualquier forma.
    if has_mail:
        found = None
        for sel in DKIM_SELECTORS:
            recs = dns_safe(f"{sel}._domainkey.{domain}", "TXT")
            if any("p=" in r for r in recs) or dns_safe(f"{sel}._domainkey.{domain}", "CNAME"):
                found = sel
                break
        if not found:
            m.findings.append(finding("F-MAIL-008", "observ",
                                      {"selectors_checked": len(DKIM_SELECTORS)}))
        m.evidence["dkim_selector"] = found
        m.evidence["mta_sts"] = bool(
            [r for r in dns_safe(f"_mta-sts.{domain}", "TXT") if "v=STSv1" in r])

    # ---------------------------------------------------------- CAA/NS/SEC
    if not dns_safe(domain, "CAA"):
        m.findings.append(finding("F-DNS-001", "bajo", {"domain": domain}))
    if not dns_safe(domain, "DNSKEY"):
        m.findings.append(finding("F-DNS-002", "observ", {"domain": domain}))
    if 0 < len(ns) < 2:
        m.findings.append(finding("F-DNS-003", "medio", {"ns": ns}))

    n = len([f for f in m.findings if f["severity"] != "observ"])
    m.note = (f"{n} {'observación' if n == 1 else 'observaciones'}" if n
              else "Correo y DNS bien configurados")
    return m.finish()


async def run(domain: str) -> ModuleResult:
    return await asyncio.to_thread(_check, domain)
