"""Runner: versiones del stack del servidor y su ciclo de vida.

Un PHP fuera de soporte no recibe parches NUNCA MAS. Es de los
hallazgos con mejor relacion valor/esfuerzo de todo el escaneo.
"""
import re
from datetime import date
import httpx
from ..schema import Finding

# Fechas oficiales de fin de vida. Revisar una vez al ano (cada noviembre
# sale una rama nueva de PHP).
PHP_EOL: dict[str, date] = {
    "5.6": date(2018, 12, 31),
    "7.0": date(2019, 1, 10),
    "7.1": date(2019, 12, 1),
    "7.2": date(2020, 11, 30),
    "7.3": date(2021, 12, 6),
    "7.4": date(2022, 11, 28),
    "8.0": date(2023, 11, 26),
    "8.1": date(2025, 12, 31),
    "8.2": date(2026, 12, 31),
    "8.3": date(2027, 12, 31),
    "8.4": date(2028, 12, 31),
    "8.5": date(2029, 12, 31),
}

PHP_RE = re.compile(r"PHP/(\d+\.\d+)(?:\.(\d+))?", re.I)


def _php_finding(branch: str, full: str) -> Finding:
    today = date.today()
    eol = PHP_EOL.get(branch)

    if eol is None:
        return Finding("stack.php.unknown_branch", "infra", "stack",
                       "info", "tentative", "low",
                       evidence={"version": full})

    if today > eol:
        years = (today - eol).days / 365.25
        sev = "critical" if years >= 3 else "high"
        return Finding("stack.php.eol", "infra", "stack",
                       sev, "confirmed", "medium",
                       evidence={"version": full, "branch": branch,
                                 "eol_date": eol.isoformat(),
                                 "years_unsupported": round(years, 1)})

    days_left = (eol - today).days
    if days_left < 180:
        return Finding("stack.php.eol_soon", "infra", "stack",
                       "medium", "confirmed", "medium",
                       evidence={"version": full, "branch": branch,
                                 "eol_date": eol.isoformat(),
                                 "days_left": days_left})

    return Finding("ok.stack.php_supported", "infra", "stack",
                   "info", "confirmed", "low",
                   evidence={"version": full, "eol_date": eol.isoformat()})


async def run(target: str, client: httpx.AsyncClient) -> list[Finding]:
    out: list[Finding] = []
    r = await client.get(target)
    h = {k.lower(): v for k, v in r.headers.items()}

    blob = " ".join(h.get(k, "") for k in ("x-powered-by", "server"))
    m = PHP_RE.search(blob)
    if m:
        branch = m.group(1)
        full = m.group(0).split("/", 1)[1]
        out.append(_php_finding(branch, full))

    if "server" in h:
        out.append(Finding("meta.server", "infra", "stack",
                           "info", "confirmed", "low",
                           evidence={"server": h["server"]}))
    return out
