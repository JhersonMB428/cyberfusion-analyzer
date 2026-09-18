"""Convierte el JSON de un escaneo en el PDF de Cyberfusion.

Regla que gobierna esta plantilla: cada afirmacion lleva detras el
alcance con el que se hizo. Por eso la tabla de cobertura esta en la
segunda pagina, no en un anexo.

Uso:
    python -m report.render escaneo.json informe.pdf [es|en]
"""
import json, sys, datetime
from pathlib import Path
from jinja2 import Template
from weasyprint import HTML

BASE = Path(__file__).parent

# El renderizador puede correr fuera del worker, asi que lee la marca
# sin importar el paquete entero.
BRAND: dict = {}
exec((BASE.parent / "worker" / "brand.py").read_text(encoding="utf-8"), BRAND)
LOCALES = BASE.parent / "locales"

SEV_COLOR = {"critical": "#8b0d08", "high": "#f63b2f", "medium": "#b8730a",
             "low": "#7a7a86", "info": "#9b9ba6"}

UI = {
    "es": {
        "brand": "Cyberfusion Technologies",
        "engine": "Motor",
        "report_kind": "Informe de seguridad web",
        "scanned_on": "Analizado el",
        "verdict_sub_full": "Sobre las 7 capas analizadas.",
        "verdict_sub_partial": "Sobre las {ok} de 7 capas que pudimos analizar.",
        "no_score_headline": "No emitimos puntuación: el análisis no cubrió "
                             "suficientes capas para calificar este sitio.",
        "summary": "Resumen ejecutivo",
        "coverage": "Alcance del análisis",
        "coverage_intro": "Qué se revisó, qué se pudo determinar y qué no. "
                          "Las capas sin determinar no significan que estén "
                          "bien: significan que no pudimos verlas.",
        "findings": "Hallazgos",
        "findings_intro": "Ordenados por riesgo y, a igual riesgo, por "
                          "facilidad de corrección. Empiece por arriba.",
        "strengths": "Lo que este sitio hace bien",
        "notes": "Observaciones",
        "tier": "Análisis automatizado · Nivel básico",
        "cta_title": "¿Quiere que nos encarguemos nosotros?",
        "cta_body": "Este es nuestro análisis automatizado de nivel básico: "
                    "cubre la superficie pública de su sitio. Si necesita ir "
                    "más a fondo, o prefiere que corrijamos los hallazgos en "
                    "lugar de hacerlo usted, escríbanos y le preparamos una "
                    "cotización para su caso.",
        "cta_items": [
            "Análisis profundo: vulnerabilidades conocidas de su CMS y sus extensiones, "
            "configuración del servidor y revisión manual por un especialista.",
            "Corrección de los hallazgos de este informe, con validación posterior.",
            "Monitoreo continuo con aviso cuando aparezca un problema nuevo.",
        ],
        "cta_contact": "Escríbanos a",
        "site_url": BRAND["SITE_URL"],
        "contact": BRAND["CONTACT_EMAIL"],
        "effort": "Esfuerzo",
        "evidence": "Evidencia",
        "tentative": "requiere verificación manual",
        "limits_note": "Este informe es una evaluación automatizada. Detecta "
                       "vulnerabilidades conocidas, versiones sin soporte y "
                       "errores de configuración. No sustituye a una auditoría "
                       "manual, que además cubre lógica de negocio y control "
                       "de acceso.",
        # La caducidad es una limitación real y, a la vez, el argumento del
        # monitoreo continuo. La misma frase hace los dos trabajos.
        "validity_note": "Este análisis refleja el estado del sitio el {fecha}. "
                         "La seguridad de una web cambia con cada actualización "
                         "de software y cada vulnerabilidad publicada, así que "
                         "conviene repetirlo periódicamente.",
        "sev": {"critical": "Crítico", "high": "Alto", "medium": "Medio",
                "low": "Bajo", "info": "Informativo"},
        "effort_l": {"low": "bajo", "medium": "medio", "high": "alto"},
        "state": {"ok": "Analizado", "partial": "Parcial",
                  "undetermined": "No determinado", "error": "Error"},
        "layer": {"tls": "Certificado y cifrado",
                  "dns": "DNS y protección de correo",
                  "headers": "Cabeceras de seguridad",
                  "exposure": "Archivos sensibles expuestos",
                  "cms": "Gestor de contenidos y extensiones",
                  "stack": "Software del servidor",
                  "app": "Vulnerabilidades conocidas"},
    }
}
UI["en"] = UI["es"]  # pendiente de traducir

STATE_CSS = {"ok": "state-ok", "partial": "state-partial",
             "undetermined": "state-undet", "error": "state-error"}


def _load_locale(lang: str) -> dict:
    path = LOCALES / f"{lang}.json"
    if not path.exists():
        path = LOCALES / "es.json"
    return json.loads(path.read_text(encoding="utf-8"))


EV_LABEL = {
    "days_left":         lambda v: f"Vence en {v} días",
    "years_unsupported": lambda v: f"{v} años sin recibir parches",
    "checked":           lambda v: f"{v} rutas sensibles comprobadas",
    "header":            lambda v: f"Cabecera ausente: {v}",
    "record":            lambda v: f"Registro publicado: {v}",
    "policy":            lambda v: f"Política actual: p={v}",
    "sp":                lambda v: f"Política de subdominios: sp={v}",
    "version":           lambda v: f"Versión detectada: {v}",
    "negotiated":        lambda v: f"Protocolo negociado: {v}",
    "issuer":            lambda v: f"Emisor: {v}",
    "domain":            lambda v: f"Dominio: {v}",
    "path":              lambda v: f"Ruta accesible: {v}",
    "endpoint":          lambda v: f"Endpoint: {v}",
    "matched_at":        lambda v: f"Detectado en: {v}",
    "product":           lambda v: f"Producto: {v}",
    "value":             lambda v: str(v),
    "name":              lambda v: str(v),
    "eol_date":          lambda v: f"Fin de soporte: {v}",
    "users":             lambda v: f"Usuarios visibles: {', '.join(map(str, v))}",
    "plugins":           lambda v: (f"{len(v)} extensiones" if isinstance(v, dict)
                                    else f"{', '.join(map(str, v[:6]))}"),
}
# Claves internas que no aportan nada al lector del informe.
EV_HIDE = {"url", "auto_renew", "scope", "status", "signals", "cms",
           "via", "detail", "latest_branch", "checked_at", "tags",
           "matcher", "extracted", "reference", "remediation"}

ORDER_EV = ("days_left", "years_unsupported", "eol_date", "version",
            "negotiated", "issuer", "header", "record", "policy", "sp",
            "path", "matched_at", "endpoint", "users", "plugins",
            "domain", "product", "checked", "value", "name")


def _evidence_line(ev: dict) -> str:
    """Una linea legible por una persona. El JSON crudo no va en un
    informe que se vende: 'days_left: 87' no es evidencia, es depuracion."""
    if not ev:
        return ""
    parts = []
    for k in ORDER_EV:
        if k in EV_HIDE or k not in ev:
            continue
        v = ev[k]
        if v in (None, "", [], {}):
            continue
        fmt = EV_LABEL.get(k)
        parts.append(fmt(v) if fmt else f"{k}: {v}")
    return " · ".join(parts)[:320]


def _summary(res: dict, ui: dict) -> str:
    c = res.get("counts") or {}
    urgent = c.get("critical", 0) + c.get("high", 0)
    n = sum(c.get(k, 0) for k in ("critical", "high", "medium", "low"))
    host = res["target"].split("://")[-1].rstrip("/")
    undet = [k for k, v in (res.get("coverage") or {}).items()
             if v.get("result") in ("undetermined", "partial")]

    if res.get("score") is None:
        s = (f"El análisis de {host} no pudo completarse. "
             f"Se revisaron {7 - len(undet)} de 7 capas.")
    elif urgent:
        verbo = "requiere" if urgent == 1 else "requieren"
        s = (f"Se detectaron {n} puntos de mejora en {host}, de los cuales "
             f"{urgent} {verbo} atención prioritaria.")
    elif n:
        s = (f"No se detectaron riesgos altos ni críticos en {host}. "
             f"Quedan {n} {'punto' if n == 1 else 'puntos'} de mejora "
             f"de menor urgencia.")
    else:
        s = f"No se detectaron problemas en las capas analizadas de {host}."

    if undet:
        cap = "capa no pudo" if len(undet) == 1 else "capas no pudieron"
        s += (f" {len(undet)} de 7 {cap} determinarse por completo; "
              f"el detalle está en el alcance.")
    return s


def build_context(res: dict, lang: str = "es") -> dict:
    ui, loc = dict(UI.get(lang, UI["es"])), _load_locale(lang)

    # La nota se calcula sobre lo que se vio. Decir "global" cuando tres
    # capas quedaron sin determinar es prometer un alcance que no hubo.
    cov = res.get("coverage") or {}
    n_ok = sum(1 for c in cov.values() if c.get("result") == "ok")
    ui["verdict_sub"] = (ui["verdict_sub_full"] if n_ok == len(cov) and cov
                         else ui["verdict_sub_partial"].format(ok=n_ok))

    def txt(key, default=""):
        return loc.get(key, default)

    findings, notes = [], []
    for f in res.get("findings", []):
        (notes if f["severity"] == "info" else findings).append({
            "severity": f["severity"],
            "sev_label": ui["sev"].get(f["severity"], f["severity"]),
            "effort_label": ui["effort_l"].get(f["effort"], f["effort"]),
            "tentative": f.get("confidence") == "tentative",
            "cve": f.get("cve") or [],
            "title": txt(f["title_key"], f["finding_key"]),
            "fix": txt(f["remediation_key"]),
            "evidence_line": _evidence_line(f.get("evidence")),
        })

    strengths = [{"title": txt(s["title_key"], s["finding_key"]),
                  "evidence_line": _evidence_line(s.get("evidence"))}
                 for s in res.get("strengths", [])]

    counts_rows = [{"label": ui["sev"][k], "n": v, "color": SEV_COLOR[k]}
                   for k, v in (res.get("counts") or {}).items()
                   if v and k != "info"]

    coverage_rows = []
    for layer, c in (res.get("coverage") or {}).items():
        why = c.get("reason", "")
        coverage_rows.append({
            "label": ui["layer"].get(layer, layer),
            "state": ui["state"].get(c["result"], c["result"]),
            "css": STATE_CSS.get(c["result"], "state-undet"),
            "why": txt(f"coverage.reason.{why}", "") if why else "",
        })

    dt = datetime.datetime.fromisoformat(res["scanned_at"])
    return {
        "lang": lang, "t": ui,
        "tokens": (BASE / "tokens.css").read_text(encoding="utf-8"),
        "target": res["target"],
        "host": res["target"].split("://")[-1].rstrip("/"),
        "score": res.get("score"), "grade": res.get("grade"),
        "engine_version": res.get("engine_version", "?"),
        "scanned_at": res["scanned_at"],
        "scanned_human": dt.strftime("%d/%m/%Y %H:%M UTC"),
        "validity_note": ui["validity_note"].format(fecha=dt.strftime("%d/%m/%Y")),
        "contact_email": BRAND["SALES_EMAIL_PUBLIC"],
        "contact_page": BRAND["CONTACT_PAGE"],
        "summary_text": _summary(res, ui),
        "counts_rows": counts_rows, "coverage_rows": coverage_rows,
        "findings": findings, "notes": notes, "strengths": strengths,
        "logo": (BASE / "assets" / "logo.png").exists(),
    }


def render(res: dict, out: str, lang: str = "es") -> str:
    tpl = Template((BASE / "template.html").read_text(encoding="utf-8"))
    html = tpl.render(**build_context(res, lang))
    HTML(string=html, base_url=str(BASE)).write_pdf(out)
    return out


def filename_for(res: dict) -> str:
    """Mismo nombre que sirve la API, para que no diverjan."""
    import re
    host = res.get("target", "informe").split("://")[-1].strip("/").split("/")[0]
    host = re.sub(r'[<>:"/\\|?*]', "-", host)[:80]
    try:
        fecha = datetime.datetime.fromisoformat(res["scanned_at"]).date()
    except (KeyError, ValueError):
        fecha = datetime.date.today()
    return f"{host} - Reporte generado {fecha.strftime('%d-%m-%Y')}.pdf"


if __name__ == "__main__":
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    res = data.get("result", data)
    lang = sys.argv[3] if len(sys.argv) > 3 else "es"
    # Sin segundo argumento, usa el nombre comercial.
    out = sys.argv[2] if len(sys.argv) > 2 else filename_for(res)
    print(render(res, out, lang))
