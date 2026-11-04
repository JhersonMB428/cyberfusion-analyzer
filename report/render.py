"""Convierte el resultado del motor 0.15 en el informe PDF de CYBERFUSION.

Formato: portada + 3 hojas. Hoja 1, resumen, capas y aciertos; hojas 2 y 3,
hallazgos. Lo de riesgo alto y medio va completo (impacto y accion); lo
bajo y las observaciones, en una lista compacta.

Terminologia (revisar con legal): el analisis es pasivo y no confirma
vulnerabilidades. El informe habla de "hallazgos", "riesgos visibles" y
"configuraciones mejorables", nunca de que el sitio "es vulnerable".

Uso:
    python -m report.render resultado.json informe.pdf
"""
import datetime
import json
import re
import sys
from pathlib import Path

from jinja2 import Template
from weasyprint import HTML

BASE = Path(__file__).parent
BRAND: dict = {}
exec((BASE.parent / "worker" / "brand.py").read_text(encoding="utf-8"), BRAND)

MAX_DETAILED = 10
MAX_MINOR = 18
SEV_COLOR = {"alto": "#E5161F", "medio": "#c26a0c", "bajo": "#7a6e70", "observ": "#a69b9d"}
SEV_LABEL = {"alto": "Riesgo alto", "medio": "Riesgo medio", "bajo": "Riesgo bajo", "observ": "Observaciones"}
STATE_LABEL = {"ok": "Correcto", "attention": "Requiere atención",
               "undetermined": "No determinado", "needs_verification": "Requiere verificar propiedad"}
LAYER_NAME = {"L1": "Certificado y cifrado", "L2": "DNS y protección de correo",
              "L3": "Cabeceras de seguridad", "L4": "Archivos sensibles expuestos",
              "L5": "Gestor de contenidos y extensiones", "L6": "Software del servidor",
              "L7": "Vulnerabilidades conocidas", "L8": "Reputación y listas negras",
              "L9": "Dominio y marca", "L10": "Superficie visible (subdominios)"}

LIMITS_NOTE = ("Evaluación automatizada y pasiva de la información que tu sitio expone "
               "públicamente: identifica configuraciones mejorables y riesgos visibles, "
               "no confirma vulnerabilidades ni intenta aprovecharlas, y no sustituye una "
               "auditoría de seguridad.")


def _summary(res: dict) -> str:
    host = res["domain"]
    f = res.get("findings", [])
    altos = sum(1 for x in f if x["severity"] == "alto")
    n = sum(1 for x in f if x["severity"] != "observ")
    cov = res["coverage"]
    if res.get("score") is None:
        return f"No pudimos completar el análisis de {host}."
    if altos:
        s = (f"Encontramos {n} puntos por mejorar en {host}; "
             f"{altos} {'es' if altos == 1 else 'son'} de riesgo alto y conviene atenderlos primero.")
    elif n:
        s = (f"No encontramos riesgos altos en {host}. Quedan {n} "
             f"{'punto' if n == 1 else 'puntos'} por mejorar de menor urgencia.")
    else:
        s = f"No encontramos puntos por mejorar en las capas analizadas de {host}."
    if cov["determined"] < cov["total"]:
        s += (f" El puntaje se calculó sobre las {cov['determined']} de {cov['total']} capas "
              f"que pudimos revisar desde fuera.")
    return s


def build_context(res: dict) -> dict:
    when = datetime.datetime.fromisoformat(res["analyzedAt"].replace("Z", "+00:00"))
    findings = res.get("findings", [])
    for f in findings:
        f["layer_name"] = LAYER_NAME.get(f["layerId"], f["layerId"])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_COLOR}
    tally = [{"label": SEV_LABEL[s], "n": counts[s], "color": SEV_COLOR[s]} for s in SEV_COLOR]

    blocked_note = ""
    n_blocked = sum(1 for l in res["layers"] if l["reason"] == "waf_blocked")
    if n_blocked:
        prod = res.get("waf", {}).get("product") or "firewall"
        blocked_note = (f"Un firewall de aplicación ({prod}) protege tu sitio y detuvo nuestro "
                        f"análisis automatizado, lo cual es positivo. Por eso el puntaje se calculó "
                        f"con las capas que no dependen del acceso web. Para revisar las "
                        f"{n_blocked} restantes, podemos verificar contigo la propiedad del dominio.")

    layers = [{**l, "state_label": STATE_LABEL.get(l["state"], l["state"])} for l in res["layers"]]
    return {
        "tokens": (BASE / "tokens.css").read_text(encoding="utf-8"),
        "host": res["domain"],
        "score": res.get("score"), "level": res.get("level"),
        "cov": res["coverage"],
        "analyzed_human": when.strftime("%d/%m/%Y · %H:%M UTC"),
        "analyzed_date": when.strftime("%d/%m/%Y"),
        "analyzed_at": res["analyzedAt"],
        "engine_version": res.get("engineVersion", "?"),
        "summary_text": _summary(res),
        "tally": tally if findings else [],
        "blocked_note": blocked_note,
        "layers": layers,
        "positives": res.get("positives", []),
        # Detalle solo para los mas importantes: el informe debe caber en
        # portada + 3 paginas. El resto va en la lista compacta.
        "major": [f for f in findings if f["severity"] in ("alto", "medio")][:MAX_DETAILED],
        "minor": ([f for f in findings if f["severity"] in ("alto", "medio")][MAX_DETAILED:]
                  + [f for f in findings if f["severity"] in ("bajo", "observ")])[:MAX_MINOR],
        "contact_email": BRAND["SALES_EMAIL_PUBLIC"],
        "contact_page": BRAND["CONTACT_PAGE"].split("://")[-1],
        "limits_note": LIMITS_NOTE,
    }


def render(res: dict, out: str, lang: str = "es") -> str:
    tpl = Template((BASE / "template.html").read_text(encoding="utf-8"))
    html = tpl.render(**build_context(res))
    HTML(string=html, base_url=str(BASE)).write_pdf(out)
    return out


def filename_for(res: dict) -> str:
    """Mismo nombre que sirve la API, para que no diverjan."""
    host = (res.get("domain") or res.get("target", "informe")).split("://")[-1].strip("/").split("/")[0]
    host = re.sub(r'[<>:"/\\|?*]', "-", host)[:80]
    try:
        fecha = datetime.datetime.fromisoformat(res["analyzedAt"].replace("Z", "+00:00")).date()
    except (KeyError, ValueError):
        fecha = datetime.date.today()
    return f"{host} - Reporte generado {fecha.strftime('%d-%m-%Y')}.pdf"


if __name__ == "__main__":
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    res = data.get("result", data)
    out = sys.argv[2] if len(sys.argv) > 2 else filename_for(res)
    print(render(res, out))
