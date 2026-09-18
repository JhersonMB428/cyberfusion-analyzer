"""Runner: cabeceras de seguridad HTTP."""
import httpx
from ..schema import Finding

CHECKS = [
    ("strict-transport-security", "hsts", "high", "low"),
    ("content-security-policy", "csp", "medium", "high"),
    ("x-content-type-options", "nosniff", "low", "low"),
    ("x-frame-options", "clickjacking", "medium", "low"),
    ("referrer-policy", "referrer", "low", "low"),
    ("permissions-policy", "permissions", "low", "medium"),
]


async def run(target: str, client: httpx.AsyncClient) -> list[Finding]:
    out: list[Finding] = []
    r = await client.get(target)
    h = {k.lower(): v for k, v in r.headers.items()}

    for header, key, sev, effort in CHECKS:
        if header in h:
            if key in ("hsts", "csp"):
                out.append(Finding(
                    finding_key=f"ok.headers.{key}",
                    layer="surface", source="headers",
                    severity="info", confidence="confirmed", effort="low",
                    evidence={"header": header, "value": h[header][:120]},
                ))
        else:
            out.append(Finding(
                finding_key=f"headers.missing.{key}",
                layer="surface", source="headers",
                severity=sev, confidence="confirmed", effort=effort,
                evidence={"header": header, "url": str(r.url)},
            ))

    # Cabeceras que filtran informacion del stack
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        if header in h and any(c.isdigit() for c in h[header]):
            out.append(Finding(
                finding_key="headers.version_disclosure",
                layer="surface", source="headers",
                severity="low", confidence="confirmed", effort="low",
                evidence={"header": header, "value": h[header]},
            ))

    # Sin redireccion a HTTPS
    if str(r.url).startswith("http://"):
        out.append(Finding(
            finding_key="headers.no_https_redirect",
            layer="surface", source="headers",
            severity="high", confidence="confirmed", effort="low",
            evidence={"final_url": str(r.url)},
        ))
    return out
