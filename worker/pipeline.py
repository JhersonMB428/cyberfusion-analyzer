"""Orquesta los runners EN PARALELO y normaliza el resultado."""
import asyncio, time, json, uuid
from datetime import datetime, timezone
import httpx
from .runners import ALL_RUNNERS
from .netguard import ClienteSeguro
from .runners.nuclei import run as nuclei_run
from . import brand
from .schema import Finding, score, grade

ENGINE_VERSION = "0.13.1"

HEADERS = {"User-Agent": brand.USER_AGENT}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
EFFORT_ORDER = {"low": 0, "medium": 1, "high": 2}


# CDN que ocultan el origen: si hay uno delante, las cabeceras del
# servidor real no llegan y hay capas que NO se pueden determinar.
CDN_SERVERS = ("cloudflare", "sucuri", "akamai", "fastly", "cloudfront",
               "incapsula", "vercel", "netlify", "openresty")

# Que runner alimenta cada capa del informe, y si depende de HTTP.
# (capa, runner, necesita_http, que cuenta como "determinado")
#
# La ultima columna importa: que un runner devuelva ALGO no significa
# que determinara lo que la capa promete. El runner de stack emite
# meta.server siempre, pero la capa solo esta cubierta si vio el PHP.
AREAS = (
    ("tls",      "tls",       False, None),
    ("dns",      "dns_mail",  False, None),
    ("headers",  "headers",   True,  None),
    ("exposure", "exposure",  True,  None),
    ("cms",      "wordpress", True,  None),
    ("stack",    "stack",     True,  "php"),
)


APP_STATES = {
    "not_requested": ("undetermined", "deep_scan_not_requested"),
    "throttled":     ("undetermined", "throttled_during_scan"),
    "incomplete":    ("partial",      "budget_exhausted"),
    "generic_only":  ("partial",      "cms_unknown_no_cve_pass"),
    "error":         ("error",        None),
    "ok":            ("ok",           None),
}


def _coverage(findings, errors, site, http_blocked: str | None,
              app_state: str = "not_requested") -> dict:
    """Declara que se reviso, que se pudo determinar y que no, y por que.

    Sin esto, el informe no distingue "no lo encontre" de "no existe",
    y el cliente asume que la capa no se reviso.
    """
    server = str((site.get("server") or {}).get("server", "")).lower()
    cdn_reason = ("origin_behind_cdn"
                  if any(c in server for c in CDN_SERVERS) else None)

    by_source: dict[str, list] = {}
    for f in findings:
        by_source.setdefault(f.source, []).append(f)

    fallback = {
        "cms": cdn_reason or "cms_not_recognised",
        "stack": cdn_reason or "version_not_disclosed",
    }

    cov: dict[str, dict] = {}
    for area, source, needs_http, key_marker in AREAS:
        produced = by_source.get(source, [])
        if key_marker:
            produced = [f for f in produced if key_marker in f.finding_key]

        if needs_http and http_blocked:
            cov[area] = {"checked": False, "result": "undetermined",
                         "reason": http_blocked}
        elif source in errors:
            cov[area] = {"checked": True, "result": "error",
                         "reason": errors[source]}
        elif produced:
            cov[area] = {"checked": True, "result": "ok"}
        else:
            cov[area] = {"checked": True, "result": "undetermined",
                         "reason": fallback.get(area, "no_data")}

    result, reason = APP_STATES[app_state]
    cov["app"] = {"checked": app_state not in ("not_requested",),
                  "result": result}
    if reason:
        cov["app"]["reason"] = reason
    elif app_state == "error":
        cov["app"]["reason"] = errors.get("nuclei", "error")
    return cov


async def _integrity_check(target: str, client) -> dict:
    """Comprueba que el servidor responde de forma honesta.

    Pide una ruta aleatoria que no puede existir. Si devuelve 200, o bien
    el sitio responde 200 a todo (soft 404), o alguien esta interceptando
    el trafico. En ambos casos NADA de lo que llegue por HTTP es fiable:
    un 200 en /.env no significaria que el archivo existe.
    """
    nonce = uuid.uuid4().hex[:16]
    probe = f"{target.rstrip('/')}/{brand.PROBE_PREFIX}-{nonce}"
    try:
        r = await client.get(probe)
    except Exception as e:
        return {"ok": False, "reason": "probe_failed", "detail": str(e)}

    # Un WAF o proteccion anti-bots devuelve una pagina de desafio a
    # cualquier ruta. Eso NO es un fallo del sitio: es proteccion activa,
    # y para el cliente es una buena noticia que hay que contarle.
    # OJO: cf-ray o cf-edge-cache aparecen en CUALQUIER sitio detras de
    # Cloudflare, tambien cuando responde con normalidad. No sirven como
    # senal de bloqueo. Solo cuentan las cabeceras que indican MITIGACION.
    waf_headers = ("cf-mitigated", "x-sucuri-block", "x-iinfo")
    hits = [h for h in waf_headers if h in r.headers]
    body_lc = r.text[:8000].lower()

    # Firmas de paginas de desafio por producto. Imunify360 WebShield es
    # el mas comun en hosting compartido con cPanel, muy extendido en
    # Latinoamerica, asi que va a aparecer a menudo.
    PRODUCTS = {
        "imunify360": ("wsidchk", "your request is being verified",
                       "z0f76a1d14fd21a8fb5fd0d03e0fdc3d3cedae52f"),
        "cloudflare": ("checking your browser", "just a moment",
                       "cf-challenge", "attention required"),
        "sucuri": ("sucuri website firewall", "access denied - sucuri"),
        "generic": ("enable javascript", "verifying you are human",
                    "ddos protection"),
    }
    product = next((name for name, sigs in PRODUCTS.items()
                    if any(sig in body_lc for sig in sigs)), None)
    challenge = product is not None

    # Un 200 solo cuenta como bloqueo si el CUERPO es una pagina de
    # desafio. Si no, es un soft 404 y se trata como tal mas abajo.
    if r.status_code in (403, 429, 503) or (r.status_code == 200 and challenge):
        return {
            "ok": False,
            "reason": "waf_blocked",
            "detail": ("El sitio esta protegido por un firewall de aplicacion "
                       "que bloqueo el escaneo automatizado."),
            "signals": hits,
            "product": product,
            "challenge_page": challenge,
            "status": r.status_code,
            "server": r.headers.get("server"),
        }

    if r.status_code == 200:
        return {
            "ok": False,
            "reason": "responds_200_to_everything",
            "detail": ("El servidor devuelve 200 a rutas inexistentes. "
                       "Puede ser un soft 404 o interceptacion de red."),
            "probe_url": probe,
            "server": r.headers.get("server"),
            "body_preview": r.text[:160],
        }
    return {"ok": True, "probe_status": r.status_code}


async def scan(target: str, deep: bool = False) -> dict:
    started = time.time()
    errors: dict[str, str] = {}

    limits = httpx.Limits(max_connections=10)
    async with ClienteSeguro(
        timeout=15, headers=HEADERS,
        limits=limits, verify=True,
    ) as client:
        async def guarded(name, fn):
            try:
                return await fn(target, client)
            except Exception as e:
                errors[name] = f"{type(e).__name__}: {e}"
                return []

        integrity = await _integrity_check(target, client)
        http_ok = integrity["ok"]
        http_blocked = None if http_ok else integrity["reason"]

        # Si no podemos confiar en HTTP, corremos SOLO los runners que no
        # dependen de el. Mejor un informe parcial y honesto que ninguno.
        # Fase 1: todos los runners pasivos, en paralelo.
        selected = [(n, fn) for n, fn, needs_http in ALL_RUNNERS
                    if n != "nuclei" and (http_ok or not needs_http)]
        results = await asyncio.gather(*[guarded(n, fn) for n, fn in selected])
        findings: list[Finding] = [f for group in results for f in group]

        # Fase 2: nuclei, alimentado con el CMS que acabamos de detectar.
        # Sin esa pista lanzaria miles de CVEs de productos irrelevantes.
        app_state = "not_requested"
        if deep and http_ok:
            cms = next((f.evidence.get("cms") for f in findings
                        if f.finding_key == "meta.cms"), None)
            try:
                found = await nuclei_run(target, client, deep=True, cms=cms)
                findings += found

                # Cero hallazgos puede significar "limpio" o "nos
                # bloquearon a mitad". Reintentamos la prueba de
                # integridad: si ahora nos rechazan, fue lo segundo.
                after = await _integrity_check(target, client)
                if not after["ok"]:
                    app_state = "throttled"
                elif any(f.finding_key == "nuclei.timed_out" for f in found):
                    app_state = "incomplete"
                elif not cms:
                    # Sin CMS conocido no corrimos la pasada de CVEs. Decir
                    # "sin vulnerabilidades" aqui seria una tranquilidad
                    # falsa: lo unico que sabemos es que la pasada generica
                    # no encontro nada.
                    app_state = "generic_only"
                else:
                    app_state = "ok"
            except Exception as e:
                errors["nuclei"] = f"{type(e).__name__}: {e}"
                app_state = "error"

        # Sin vulnerabilidades es una fortaleza, pero solo puede afirmarse
        # con el alcance que realmente se cubrio.
        clean = not any(f.source == "nuclei" and f.severity != "info"
                        for f in findings)
        if clean and app_state in ("ok", "generic_only"):
            key = ("ok.app.no_known_vulns" if app_state == "ok"
                   else "ok.app.no_generic_vulns")
            findings.append(Finding(
                key, "app", "nuclei", "info", "firm", "low",
                evidence={"cms": cms, "scope": app_state}))

    if http_blocked == "waf_blocked":
        findings.append(Finding(
            "ok.waf.protected", "surface", "integrity",
            "info", "firm", "low",
            evidence={"product": integrity.get("product"),
                      "status": integrity.get("status")},
        ))

    # Prioriza por riesgo alto + esfuerzo bajo. Eso es lo que hace
    # que un informe se sienta util en vez de aterrador.
    findings.sort(key=lambda f: (ORDER[f.severity], EFFORT_ORDER[f.effort]))

    # Un informe que solo enumera problemas se lee como venta por miedo.
    # Separamos lo que el sitio hace BIEN para que el PDF abra con eso.
    site = {f.finding_key[5:]: f.evidence
            for f in findings if f.finding_key.startswith("meta.")}
    strengths = [f for f in findings if f.finding_key.startswith("ok.")]
    issues = [f for f in findings
              if not f.finding_key.startswith(("ok.", "meta."))]

    # Solo puntuamos un analisis completo. Una nota calculada sobre dos
    # capas de seis seria enganosa: parece buena por lo que no se vio.
    value = score([f for f in issues if f.severity != "info"]) if http_ok else None

    out = {
        "engine_version": ENGINE_VERSION,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "scan_mode": ("deep" if deep else "full") if http_ok else "partial",
        "reliable": http_ok,
        "score": value,
        "grade": grade(value) if value is not None else None,
        "duration_s": round(time.time() - started, 2),
        "counts": {s: sum(1 for f in issues if f.severity == s) for s in ORDER},
        "site": site,
        "coverage": _coverage(findings, errors, site, http_blocked, app_state),
        "strengths": [f.to_dict() for f in strengths],
        "findings": [f.to_dict() for f in issues],
        "errors": errors,
    }
    if not http_ok:
        out["integrity"] = integrity
    return out


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    deep = "--deep" in sys.argv
    print(json.dumps(asyncio.run(scan(url, deep=deep)), indent=2, ensure_ascii=False))
