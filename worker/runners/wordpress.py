"""Runner: deteccion de WordPress, version, plugins y temas.

Esta es la capa donde Cyberfusion tiene ventaja sobre la competencia:
ya conocen el ecosistema WordPress a fondo.
"""
import re, asyncio
import httpx
from ..schema import Finding
from ..wpversion import latest_version, comparar

PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9\-_]+)/", re.I)
THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9\-_]+)/", re.I)
GEN_RE = re.compile(r'name="generator"\s+content="WordPress\s+([0-9.]+)"', re.I)
VER_RE = re.compile(r"Stable tag:\s*([0-9.]+)", re.I)
# Los plugins de pago (elementor-pro, addons comerciales) NO publican
# readme.txt. Pero WordPress cuelga la version en los CSS/JS que carga.
ASSET_VER_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9\-_]+)/[^\"\'\s]+?\?ver=([0-9][0-9.]*)", re.I)




async def _plugin_version(client, base, slug):
    try:
        r = await client.get(f"{base}/wp-content/plugins/{slug}/readme.txt")
        if r.status_code == 200:
            m = VER_RE.search(r.text[:3000])
            if m:
                return slug, m.group(1)
    except Exception:
        pass
    return slug, None


async def run(target: str, client: httpx.AsyncClient) -> list[Finding]:
    base = target.rstrip("/")
    out: list[Finding] = []
    try:
        r = await client.get(base)
    except Exception:
        return out
    html = r.text

    is_wp = "/wp-content/" in html or "/wp-includes/" in html
    if not is_wp:
        return out

    m = GEN_RE.search(html)
    out.append(Finding(
        finding_key="meta.cms",
        layer="cms", source="wordpress",
        severity="info", confidence="confirmed", effort="low",
        evidence={"cms": "WordPress", "version": m.group(1) if m else "unknown"},
    ))

    if m:
        version = m.group(1)
        ultima = await latest_version()
        veredicto = comparar(version, ultima) if ultima else {"estado": "indeterminado"}
        estado = veredicto["estado"]
        ev = {"version": version, "latest": ultima}

        out.append(Finding(
            finding_key="cms.version_disclosure",
            layer="cms", source="wordpress",
            severity="info" if estado in ("al_dia", "adelantada") else "low",
            confidence="confirmed", effort="low",
            evidence={"version": version, "via": "meta generator"},
        ))

        if estado in ("al_dia", "adelantada"):
            out.append(Finding(
                finding_key="ok.cms.up_to_date",
                layer="cms", source="wordpress",
                severity="info", confidence="firm", effort="low",
                evidence=ev,
            ))
        elif estado == "parche_pendiente":
            # Las versiones de parche son las de seguridad. Faltar una no
            # es "un poco atrasado": son vulnerabilidades sin corregir.
            out.append(Finding(
                finding_key="cms.core_security_patch_missing",
                layer="cms", source="wordpress",
                severity="high", confidence="firm", effort="low",
                evidence=ev,
            ))
        elif estado == "rama_atrasada":
            # Una rama anterior puede seguir recibiendo parches
            # retroportados, asi que no afirmamos que este sin parchear:
            # por eso la confianza baja cuando solo es una rama.
            dos_o_mas = veredicto["ramas_detras"] >= 2
            out.append(Finding(
                finding_key="cms.core_outdated",
                layer="cms", source="wordpress",
                severity="high" if dos_o_mas else "medium",
                confidence="firm" if dos_o_mas else "tentative",
                effort="medium",
                evidence=ev,
            ))
        # estado 'indeterminado': no sabemos cual es la ultima version,
        # asi que NO emitimos veredicto. Callar es correcto; decir
        # "esta al dia" sin poder comprobarlo, no.
        
    slugs = sorted(set(PLUGIN_RE.findall(html)))[:25]
    versions = await asyncio.gather(*[_plugin_version(client, base, s) for s in slugs])
    plugins = {s: v for s, v in versions}
    from_readme = {s for s, v in plugins.items() if v}

    # Rellena las versiones que readme.txt no dio, leyendo los ?ver=
    # de los recursos que carga la pagina. Cubre los plugins de pago.
    #
    # OJO: cuando un plugin encola un asset SIN declarar version propia,
    # WordPress le pone la version del CORE. Si aceptamos ese valor
    # inventamos versiones que no existen, y luego buscariamos CVEs de
    # una version fantasma. Por eso descartamos las que coincidan.
    core_version = m.group(1) if m else None
    for slug, ver in ASSET_VER_RE.findall(html):
        if plugins.get(slug) is not None:
            continue
        if core_version and ver == core_version:
            continue
        plugins[slug] = ver
    if plugins:
        out.append(Finding(
            finding_key="meta.plugins",
            layer="cms", source="wordpress",
            severity="info", confidence="firm", effort="low",
            evidence={"count": len(plugins), "plugins": plugins},
        ))
    # readme.txt legible = version del plugin publica
    readable = sorted(from_readme)
    if readable:
        out.append(Finding(
            finding_key="cms.plugin_readme_exposed",
            layer="cms", source="wordpress",
            severity="low", confidence="confirmed", effort="low",
            evidence={"plugins": readable[:10]},
        ))

    themes = sorted(set(THEME_RE.findall(html)))
    if themes:
        out.append(Finding(
            finding_key="meta.themes",
            layer="cms", source="wordpress",
            severity="info", confidence="firm", effort="low",
            evidence={"themes": themes},
        ))

    # Enumeracion de usuarios via REST API
    try:
        ru = await client.get(f"{base}/wp-json/wp/v2/users")
        if ru.status_code == 200 and ru.json():
            names = [u.get("slug") for u in ru.json()][:10]
            out.append(Finding(
                finding_key="cms.user_enumeration",
                layer="cms", source="wordpress",
                severity="medium", confidence="confirmed", effort="low",
                evidence={"endpoint": "/wp-json/wp/v2/users", "users": names},
            ))
    except Exception:
        pass

    return out
