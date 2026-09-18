"""Runner: ficheros y rutas expuestas que no deberian ser publicas."""
import asyncio
import httpx
from ..schema import Finding

PATHS = [
    ("/.git/config", "git_repo", "critical", "[core]"),
    ("/.env", "env_file", "critical", "="),
    ("/wp-config.php.bak", "wp_config_backup", "critical", "DB_"),
    ("/backup.sql", "sql_dump", "critical", None),
    ("/.svn/entries", "svn_repo", "high", None),
    ("/phpinfo.php", "phpinfo", "high", "phpinfo()"),
    ("/server-status", "apache_status", "medium", "Apache Server Status"),
    ("/xmlrpc.php", "wp_xmlrpc", "medium", "XML-RPC"),
    ("/.DS_Store", "ds_store", "low", None),
]


async def _probe(client: httpx.AsyncClient, base: str, path: str,
                 key: str, sev: str, marker: str | None) -> Finding | None:
    try:
        r = await client.get(base.rstrip("/") + path)
    except Exception:
        return None
    if r.status_code != 200:
        return None

    # Un .env, un dump SQL o un .DS_Store NUNCA son HTML. Si llega HTML
    # es una pagina de error, un redirect o una interceptacion.
    ctype = r.headers.get("content-type", "").lower()
    head = r.text[:200].lstrip().lower()
    if "text/html" in ctype or head.startswith(("<!doctype", "<html")):
        return None

    body = r.text[:400]
    if marker and marker not in r.text[:4000]:
        return None
    return Finding(
        finding_key=f"exposure.{key}",
        layer="surface", source="exposure",
        severity=sev, confidence="confirmed" if marker else "firm",
        effort="low",
        evidence={"path": path, "status": r.status_code, "snippet": body[:200]},
    )


async def run(target: str, client: httpx.AsyncClient) -> list[Finding]:
    tasks = [_probe(client, target, p, k, s, m) for p, k, s, m in PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    found = [r for r in results if isinstance(r, Finding)]
    if not found:
        found.append(Finding(
            finding_key="ok.exposure.clean",
            layer="surface", source="exposure",
            severity="info", confidence="firm", effort="low",
            evidence={"checked": len(PATHS)},
        ))
    return found
