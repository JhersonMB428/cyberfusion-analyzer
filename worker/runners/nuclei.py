"""Runner: nuclei. Correlacion con CVEs y malas configuraciones conocidas.

IMPORTANTE: nuclei hace escaneo ACTIVO. Solo corre en modo profundo
(deep=True), que exige haber verificado la propiedad del dominio.

Estrategia de plantillas: NO lanzar las ~13.000. Se ejecutan dos pasadas:
  1. Generica: exposiciones y malas configuraciones. Aplica a todo sitio.
  2. Dirigida: CVEs filtrados por el CMS que detectamos antes.

Probar 6.000 CVEs de productos que el sitio no tiene es lento e inutil.
"""
import asyncio, json, os, shutil, tempfile
from ..schema import Finding

NUCLEI = shutil.which("nuclei") or "/usr/local/bin/nuclei"
TEMPLATES = os.getenv("NUCLEI_TEMPLATES", "/root/nuclei-templates")
BUDGET_S = int(os.getenv("NUCLEI_TIMEOUT", "600"))

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "info": "info", "unknown": "info"}

# Plantillas que duplican lo que ya detectan NUESTROS runners. Sin esto
# el mismo problema se cuenta dos veces y la nota baja el doble.
SUPPRESS = {
    "http-missing-security-headers", "ssl-issuer", "tls-version",
    "wordpress-detect", "wp-xmlrpc", "waf-detect", "robots-txt-endpoint",
    "options-method", "ssl-dns-names", "http-trace", "wordpress-user-enum",
    "wp-json-user-enumeration", "dns-saas-service-detection",
    "caa-fingerprint", "mismatched-ssl-certificate", "wordpress-readme",
}

# Etiquetas que indican deteccion por VERSION, no por explotacion real.
VERSION_TAGS = {"tech", "detect", "version", "favicon", "panel"}

# Que plantillas de CVE cargar segun el CMS detectado.
CMS_TAGS = {
    "wordpress": "wordpress,wp-plugin,wp-theme,wp",
    "joomla": "joomla",
    "drupal": "drupal",
    "magento": "magento",
}


def _to_finding(row: dict) -> Finding | None:
    tid = row.get("template-id", "")
    if tid in SUPPRESS:
        return None

    info = row.get("info", {}) or {}
    cls = info.get("classification") or {}
    tags = set(info.get("tags") or [])

    sev = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "info")
    cves = [c.upper() for c in (cls.get("cve-id") or []) if c]

    return Finding(
        finding_key=f"nuclei.{tid}",
        layer="app",
        source="nuclei",
        severity=sev,
        confidence="tentative" if tags & VERSION_TAGS else "confirmed",
        effort="low" if (cves or "misconfig" in tags) else "medium",
        cve=cves,
        cvss=cls.get("cvss-score"),
        evidence={
            "name": info.get("name"),
            "matched_at": row.get("matched-at") or row.get("host"),
            "matcher": row.get("matcher-name"),
            "extracted": (row.get("extracted-results") or [])[:5],
            "reference": (info.get("reference") or [])[:3],
            "remediation": info.get("remediation"),
            "tags": sorted(tags)[:8],
        },
    )


def parse_jsonl(text: str) -> list[Finding]:
    """Separado del subprocess para poder probarlo sin ejecutar nuclei."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            f = _to_finding(json.loads(line))
        except json.JSONDecodeError:
            continue
        if f:
            out.append(f)
    return out


async def _pass(target: str, dirs: list[str], tags: str | None,
                timeout: int) -> tuple[list[Finding], bool]:
    """Una pasada de nuclei. Devuelve (hallazgos, se_agoto_el_tiempo).

    Escribe a un archivo con -o para poder recuperar resultados PARCIALES
    si se agota el tiempo. Antes se perdia todo el trabajo.
    """
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as fh:
        out_path = fh.name

    args = [
        NUCLEI, "-u", target, "-jsonl", "-o", out_path,
        "-silent", "-disable-update-check", "-no-interactsh",
        "-severity", "low,medium,high,critical",
        # Nunca contra un sitio ajeno: nada que degrade el servicio.
        "-exclude-tags", "dos,fuzz,intrusive,brute-force",
        "-rate-limit", "40", "-c", "25", "-timeout", "6", "-retries", "1",
        # Sin esto, un 302 hacia 169.254.169.254 lleva a nuclei al
        # endpoint de metadatos de Azure. Verificar la propiedad del
        # dominio no impide que su dueno lo apunte a donde quiera.
        "-disable-redirects",
    ]
    for d in dirs:
        args += ["-t", os.path.join(TEMPLATES, d)]
    if tags:
        args += ["-tags", tags]

    timed_out = False
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        await proc.wait()

    try:
        with open(out_path, encoding="utf-8", errors="replace") as fh:
            findings = parse_jsonl(fh.read())
    except FileNotFoundError:
        findings = []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
    return findings, timed_out


async def run(target: str, client, deep: bool = False,
              cms: str | None = None) -> list[Finding]:
    if not deep:
        return []

    findings: list[Finding] = []
    partial = False

    # Pasada 1: generica. Rapida y aplica a cualquier sitio.
    got, to = await _pass(target,
                          ["http/exposures", "http/misconfiguration"],
                          None, int(BUDGET_S * 0.4))
    findings += got
    partial |= to

    # Pasada 2: dirigida al CMS detectado. Sin CMS conocido no tiene
    # sentido probar miles de CVEs de productos que el sitio no usa.
    tags = CMS_TAGS.get((cms or "").lower())
    if tags:
        got, to = await _pass(target,
                              ["http/cves", "http/vulnerabilities"],
                              tags, int(BUDGET_S * 0.6))
        findings += got
        partial |= to

    if partial:
        findings.append(Finding(
            "nuclei.timed_out", "app", "nuclei",
            "info", "confirmed", "low",
            evidence={"detail": f"Analisis activo incompleto: se agoto el "
                                f"presupuesto de {BUDGET_S}s. Los hallazgos "
                                f"mostrados son validos pero no exhaustivos."},
        ))
    return findings
