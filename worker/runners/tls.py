"""Runner: certificado TLS. Usa solo la libreria estandar."""
import ssl, socket, asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse
from ..schema import Finding


def _inspect(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return {"cert": ssock.getpeercert(), "version": ssock.version()}


async def run(target: str, client) -> list[Finding]:
    host = urlparse(target).hostname
    out: list[Finding] = []
    if not host:
        return out

    try:
        info = await asyncio.to_thread(_inspect, host)
    except ssl.SSLCertVerificationError as e:
        return [Finding(
            finding_key="tls.cert.invalid",
            layer="surface", source="tls",
            severity="critical", confidence="confirmed", effort="low",
            evidence={"error": str(e), "host": host},
        )]
    except Exception as e:
        return [Finding(
            finding_key="tls.unreachable",
            layer="surface", source="tls",
            severity="info", confidence="tentative", effort="low",
            evidence={"error": str(e), "host": host},
        )]

    cert = info["cert"]
    issuer = dict(x[0] for x in cert.get("issuer", []))
    org = issuer.get("organizationName", "?")

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days

    # Let's Encrypt y similares renuevan solo a los 30 dias. Si alertamos
    # a 30 dias, casi todos los sitios saltarian durante su renovacion normal.
    short_lived = any(k in org for k in ("Let's Encrypt", "ZeroSSL", "Google Trust"))
    high_at, med_at = (7, 14) if short_lived else (15, 30)

    if days < 0:
        sev = "critical"
    elif days < high_at:
        sev = "high"
    elif days < med_at:
        sev = "medium"
    else:
        sev = None

    if sev:
        out.append(Finding(
            finding_key="tls.cert.expiring",
            layer="surface", source="tls",
            severity=sev, confidence="confirmed", effort="low",
            evidence={"days_left": days, "expires": cert["notAfter"], "issuer": org},
        ))
    else:
        out.append(Finding(
            finding_key="ok.tls.cert_valid",
            layer="surface", source="tls",
            severity="info", confidence="confirmed", effort="low",
            evidence={"days_left": days, "issuer": org, "auto_renew": short_lived},
        ))

    if info["version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding(
            finding_key="tls.protocol.obsolete",
            layer="surface", source="tls",
            severity="high", confidence="confirmed", effort="medium",
            evidence={"negotiated": info["version"]},
        ))
    elif info["version"] == "TLSv1.3":
        out.append(Finding(
            finding_key="ok.tls.modern",
            layer="surface", source="tls",
            severity="info", confidence="confirmed", effort="low",
            evidence={"negotiated": info["version"]},
        ))

    return out
