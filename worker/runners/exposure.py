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
    ("/.DS_Store", "ds_store", "low", None),
]

# WordPress responde a un GET en xmlrpc.php con 405 y este texto exacto.
# Por eso la sonda generica (que exige 200) nunca lo detectaba.
XMLRPC_MARK = "xml-rpc server accepts post requests only"


async def _probe_xmlrpc(client: httpx.AsyncClient, base: str) -> Finding | None:
    try:
        r = await client.get(base.rstrip("/") + "/xmlrpc.php")
    except Exception:
        return None
    if r.status_code in (200, 405) and XMLRPC_MARK in r.text[:500].lower():
        return Finding(
            finding_key="exposure.wp_xmlrpc",
            layer="surface", source="exposure",
            severity="medium", confidence="confirmed", effort="low",
            evidence={"path": "/xmlrpc.php", "status": r.status_code,
                      "snippet": r.text[:120]},
        )
    return None


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
    tasks.append(_probe_xmlrpc(client, target))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    found = [r for r in results if isinstance(r, Finding)]
    if not found:
        found.append(Finding(
            finding_key="ok.exposure.clean",
            layer="surface", source="exposure",
            severity="info", confidence="firm", effort="low",
            evidence={"checked": len(PATHS) + 1},
        ))
    return found
