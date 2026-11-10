"""API publica. Recibe una URL, la valida, encola y devuelve el estado."""
import json, os, re, uuid
from urllib.parse import urlparse
import redis
import base64, csv, datetime, io
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from urllib.parse import quote
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

# En produccion el esquema de la API no aporta nada al cliente y si le
# dice a cualquiera que ruta atacar. En local sigue disponible, que es
# donde /docs realmente sirve para probar endpoints a mano.
OCULTAR_DOCS = os.getenv("HIDE_DOCS", "").strip().lower() in ("1", "true", "yes")
app = FastAPI(
    title="Cyberfusion Analyzer API",
    docs_url=None if OCULTAR_DOCS else "/docs",
    redoc_url=None if OCULTAR_DOCS else "/redoc",
    openapi_url=None if OCULTAR_DOCS else "/openapi.json",
)
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
QUEUE = "scans:queue"
PUBLIC_URL = os.getenv("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")

# --- Proteccion antiabuso ---------------------------------------------
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET", "")
TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
# Detras de Azure o Cloudflare la IP real llega en X-Forwarded-For. Solo
# se confia en esa cabecera si lo declaramos: si no, cualquiera la falsea
# y se salta el limite por IP poniendo una IP distinta en cada peticion.
TRUST_PROXY = os.getenv("TRUST_PROXY", "").lower() in ("1", "true", "yes")
OPEN_REPORTS = os.getenv("OPEN_REPORTS", "").strip().lower() in ("1", "true", "yes")
SCANS_PER_IP_PER_HOUR = int(os.getenv("SCANS_PER_IP_PER_HOUR", "3"))


def client_ip(request: Request) -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "desconocida"


def check_captcha(token: str, ip: str) -> None:
    """Sin captcha configurado no bloqueamos: permite desarrollar en local.
    En produccion hay que definir TURNSTILE_SECRET."""
    if not TURNSTILE_SECRET:
        return
    if not token:
        raise HTTPException(400, "Falta la verificacion antirrobot")
    try:
        resp = httpx.post(TURNSTILE_URL, timeout=10, data={
            "secret": TURNSTILE_SECRET, "response": token, "remoteip": ip})
        ok = resp.json().get("success") is True
    except Exception as e:
        # Si Cloudflare no responde, dejamos pasar antes que caernos.
        # El limite por IP sigue protegiendo.
        print(f"[captcha] no verificable: {e}", flush=True)
        return
    if not ok:
        raise HTTPException(403, "La verificacion antirrobot no fue valida")


def check_rate(ip: str) -> None:
    hora = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H")
    key = f"rate:ip:{ip}:{hora}"
    n = r.incr(key)
    if n == 1:
        r.expire(key, 3600)
    if n > SCANS_PER_IP_PER_HOUR:
        raise HTTPException(429, f"Alcanzaste el límite de {SCANS_PER_IP_PER_HOUR} "
                                 f"análisis por hora. Inténtalo más tarde o escríbenos "
                                 f"si necesitas analizar más dominios.")

from worker.verification import Store, normalize_domain
from worker import mailer
store = Store(r)

# --- Proteccion contra abuso -------------------------------------------
BLOCKED_SUFFIXES = (".gob.pe", ".gov", ".mil", ".gouv.fr", ".gov.br")
BLOCKED_DOMAINS = {"google.com", "facebook.com", "cloudflare.com"}
RATE_PER_IP_PER_DAY = 3
DOMAIN_COOLDOWN_S = 86400


UTM_KEYS = ("utm_source", "utm_medium", "utm_campaign", "utm_content")


def _audit(ip, target, host, job_id, deep, utm, cached=False):
    """Registro antiabuso (si alguien reclama por un escaneo, hay
    trazabilidad) y base del panel de "webs analizadas"."""
    r.rpush("audit:scans", json.dumps({
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "ip": ip, "target": target, "host": host, "deep": deep,
        "job_id": job_id, "cached": cached, **utm}))
    r.ltrim("audit:scans", -20000, -1)


class ScanRequest(BaseModel):
    url: str
    captcha: str = ""
    authorized: bool = False
    force: bool = False   # ignora la cache de 24h. Solo para desarrollo.
    deep: bool = False    # escaneo ACTIVO con nuclei. Exige dominio verificado.
    # Origen de la visita (campanas). Solo para el panel de "webs analizadas".
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""
    utm_content: str = ""

from worker.netguard import validar_o_fallar, DestinoNoPermitido, NoResuelve

def normalize(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname:
        raise HTTPException(400, "URL invalida")
    if len(p.hostname) > 253 or re.fullmatch(r"[0-9.]+|\[?[0-9a-f:]+\]?", p.hostname, re.I):
        raise HTTPException(400, "Ingresa un nombre de dominio, no una dirección IP")

    try:
        host, _ips = validar_o_fallar(p.hostname)
    except NoResuelve as e:
        raise HTTPException(400, str(e))
    except DestinoNoPermitido as e:
        raise HTTPException(403, str(e))

    if host.endswith(BLOCKED_SUFFIXES) or host in BLOCKED_DOMAINS:
        raise HTTPException(403, "Dominio excluido del escaneo")

    return f"https://{host}"

@app.post("/scans")
def create_scan(req: ScanRequest, request: Request):
    ip = client_ip(request)
    check_captcha(req.captcha, ip)
    check_rate(ip)

    if not req.authorized:
        raise HTTPException(400, "Debe declarar autorizacion para analizar el dominio")

    target = normalize(req.url)
    host = urlparse(target).hostname

    # El escaneo profundo lanza cientos de peticiones de prueba contra el
    # sitio. Nunca debe poder pedirse sin verificacion de propiedad.
    if req.deep and not store.is_verified(host) and not os.getenv("ALLOW_UNVERIFIED_DEEP"):
        raise HTTPException(403, {
            "error": "domain_not_verified",
            "detail": "El analisis profundo requiere verificar la propiedad "
                      "del dominio.",
            "next": "POST /verify/start con {\"domain\": \"" + (host or "") + "\"}",
        })

    # Cache: un escaneo por dominio cada 24h.
    # Protege de abuso en produccion, pero estorba al desarrollar:
    # por eso force=true la ignora.
    utm = {k: (getattr(req, k) or "")[:100] for k in UTM_KEYS}
    if not req.force:
        cached = r.get(f"domain:{host}")
        if cached:
            # Tambien se registra: otra persona pudo pedir el mismo dominio.
            _audit(ip, target, host, cached.decode(), req.deep, utm, cached=True)
            return {"id": cached.decode(), "cached": True}

    job_id = uuid.uuid4().hex[:12]
    r.set(f"domain:{host}", job_id, ex=DOMAIN_COOLDOWN_S)
    r.set(f"scan:{job_id}", json.dumps({"status": "queued"}), ex=86400)
    _audit(ip, target, host, job_id, req.deep, utm)

    r.rpush(QUEUE, json.dumps({"id": job_id, "target": target, "deep": req.deep}))
    return {"id": job_id, "cached": False}


@app.get("/scans/{job_id}")
def get_scan(job_id: str):
    raw = r.get(f"scan:{job_id}")
    if not raw:
        raise HTTPException(404, "No encontrado")
    return json.loads(raw)


def _report_filename(job_id: str) -> str:
    """'www.kioscosia.com - Reporte generado 14-09-2026.pdf'

    El nombre del archivo es lo primero que ve el cliente en su carpeta
    de descargas y lo que aparece adjunto en un correo. Un job_id ahi
    no le dice nada a nadie.
    """
    host, fecha = "informe", datetime.date.today()
    raw = r.get(f"scan:{job_id}")
    if raw:
        res = (json.loads(raw) or {}).get("result") or {}
        if res.get("target"):
            host = res["target"].split("://")[-1].strip("/").split("/")[0]
        when = res.get("analyzedAt") or res.get("scanned_at")
        if when:
            try:
                fecha = datetime.datetime.fromisoformat(when.replace("Z", "+00:00")).date()
            except ValueError:
                pass
    # Windows y macOS rechazan estos caracteres en nombres de archivo.
    host = re.sub(r'[<>:"/\\|?*]', "-", host)[:80]
    return f"{host} - Reporte generado {fecha.strftime('%d-%m-%Y')}.pdf"


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
# Dominios desechables mas comunes. Un lead con correo temporal no es
# un lead: no puedes hacer seguimiento ni enviarle el monitoreo mensual.
DISPOSABLE = {"mailinator.com", "yopmail.com", "guerrillamail.com",
              "10minutemail.com", "tempmail.com", "trashmail.com",
              "sharklasers.com", "getnada.com", "maildrop.cc"}


# Telefono internacional laxo: 7-15 digitos con + y separadores opcionales.
# Validar mas estricto rechaza numeros legitimos de otros paises.
PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")


class LeadRequest(BaseModel):
    job_id: str
    email: str
    name: str
    company: str
    phone: str = ""
    consent: bool = False
    # Opcionales: la pagina de cyberfusion.global los pide; la anterior no.
    role: str = ""
    country: str = ""
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""
    utm_content: str = ""


LEADS_FILE = pathlib.Path(os.getenv("LEADS_PATH", "/data/leads.jsonl"))
LEADS_TOKEN = os.getenv("LEADS_TOKEN", "")
SALES_EMAIL = os.getenv("SALES_EMAIL", "")


def _read_leads() -> list[dict]:
    out = []
    if LEADS_FILE.exists():
        for line in LEADS_FILE.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def _auth(token: str) -> None:
    if not LEADS_TOKEN or token != LEADS_TOKEN:
        raise HTTPException(403, "Token invalido")

@app.get("/leads/list.json")
def list_leads(request: Request, limit: int = 500):
    """Para el panel. El token viaja en la cabecera, no en la URL: asi no
    queda en el historial del navegador ni en los registros del servidor."""
    _auth(request.headers.get("x-leads-token", ""))
    leads = _read_leads()
    return {"total": len(leads), "leads": list(reversed(leads))[:limit]}


@app.get("/leads/export.csv")
def export_leads(token: str = ""):
    """Descarga de los leads para pasarlos al CRM o a una hoja de calculo."""
    _auth(token)

    import csv, io
    cols = ["at", "name", "role", "email", "phone", "company", "country",
            "domain", "score", "level", "status", "coverage",
            "utm_source", "utm_medium", "utm_campaign", "utm_content", "job_id"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for lead in _read_leads():
        w.writerow(lead)
    return Response(
        # BOM para que Excel en Windows abra las tildes correctamente.
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="leads.csv"'},
    )


def _scans(limit: int) -> list[dict]:
    """Webs que se pusieron a analizar, hayan llenado o no el formulario.
    La IP del visitante no sale del registro antiabuso."""
    with_lead = {l.get("job_id") for l in _read_leads()}
    rows = []
    for raw in r.lrange("audit:scans", -limit, -1)[::-1]:
        try:
            a = json.loads(raw)
        except (ValueError, TypeError):
            continue
        jid = a.get("job_id", "")
        summ = r.get(f"scansum:{jid}")
        if summ:
            s = json.loads(summ)
        else:                              # analisis de antes de este cambio
            s = {}
            sc = r.get(f"scan:{jid}")
            res = (json.loads(sc).get("result") or {}) if sc else {}
            if res:
                cov = res.get("coverage") or {}
                s = {"score": res.get("score"), "level": res.get("level"), "status": res.get("status"),
                     "coverage": f"{cov.get('determined', '')}/{cov.get('total', '')}" if cov else ""}
        host = a.get("host") or (urlparse(a.get("target", "")).hostname or "")
        rows.append({"at": a.get("at"), "host": host, "job_id": jid, "cached": a.get("cached", False),
                     "score": s.get("score"), "level": s.get("level"), "status": s.get("status"),
                     "coverage": s.get("coverage", ""), "waf": s.get("waf"),
                     "lead": jid in with_lead,
                     **{k: a.get(k, "") for k in UTM_KEYS}})
    return rows


@app.get("/leads/scans.json")
def list_scans(request: Request, limit: int = 2000):
    _auth(request.headers.get("x-leads-token", ""))
    rows = _scans(min(max(limit, 1), 20000))
    return {"total": r.llen("audit:scans"), "scans": rows}


@app.get("/leads/scans.csv")
def export_scans(token: str = ""):
    _auth(token)
    import csv, io
    cols = ["at", "host", "score", "level", "status", "coverage", "waf", "lead", "cached",
            *UTM_KEYS, "job_id"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for row in _scans(20000):
        row["lead"] = "si" if row["lead"] else "no"
        w.writerow(row)
    return Response(content="\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="webs-analizadas.csv"'})


@app.post("/leads")
def create_lead(req: LeadRequest, bg: BackgroundTasks):
    """Libera el PDF a cambio del correo.

    Los resultados se muestran en pantalla sin pedir nada; lo que se
    entrega a cambio del correo es el informe y el seguimiento. Pedir
    el correo ANTES de escanear hunde la conversion: el visitante aun
    no sabe si esto le sirve.
    """
    name = (req.name or "").strip()
    company = (req.company or "").strip()
    phone = (req.phone or "").strip()
    email = (req.email or "").strip().lower()

    if len(name) < 2:
        raise HTTPException(400, "Indique su nombre")
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Correo no valido")
    if phone and (not PHONE_RE.match(phone) or sum(c.isdigit() for c in phone) < 7):
        raise HTTPException(400, "Telefono no valido")
    if len(company) < 2:
        raise HTTPException(400, "Indique el nombre de su empresa")
    if email.split("@")[-1] in DISPOSABLE:
        raise HTTPException(400, "Use un correo corporativo o personal "
                                 "permanente para recibir el informe")
    if not req.consent:
        raise HTTPException(400, "Falta aceptar el tratamiento de datos")

    raw = r.get(f"scan:{req.job_id}")
    if not raw:
        raise HTTPException(404, "Analisis no encontrado")
    res = (json.loads(raw) or {}).get("result") or {}

    lead = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "name": name[:120], "company": company[:120],
        "email": email, "phone": phone[:30],
        "role": (req.role or "").strip()[:80],
        "country": (req.country or "").strip()[:60],
        "domain": res.get("domain") or res.get("target"),
        "score": res.get("score"), "level": res.get("level"),
        "status": res.get("status"),
        "coverage": "{determined}/{total}".format(**(res.get("coverage") or {"determined": 0, "total": 10})),
        "urgent": sum(1 for f in res.get("findings", []) if f.get("severity") == "alto"),
        **{k: (getattr(req, k) or "").strip()[:80] for k in
           ("utm_source", "utm_medium", "utm_campaign", "utm_content")},
        "job_id": req.job_id,
    }
    payload = json.dumps(lead, ensure_ascii=False)

    # Tres copias a proposito. Un lead perdido es dinero perdido, y hasta
    # ahora vivian solo en memoria: un reinicio se los llevaba todos.
    r.rpush("leads", payload)                      # 1. Redis, ahora con volumen
    try:                                           # 2. archivo en disco
        LEADS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LEADS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    except OSError as e:
        print(f"[leads] no se pudo escribir el archivo: {e}", flush=True)
    r.set(f"released:{req.job_id}", "1", ex=86400)

    filename = _report_filename(req.job_id)
    host = (res.get("domain") or res.get("target") or "").split("://")[-1].strip("/")
    urgent = sum(1 for f in res.get("findings", []) if f.get("severity") == "alto")
    pdf_raw = r.get(f"pdf:{req.job_id}")
    if not pdf_raw:
        # El worker genera el PDF al terminar el escaneo. Si falta aqui,
        # el renderizado fallo: revisar los logs del worker.
        print(f"[leads] SIN PDF para {req.job_id}: el correo ira sin adjunto",
              flush=True)

    # En segundo plano: el usuario ya tiene su boton de descarga y no
    # debe esperar a que el servidor SMTP responda.
    if mailer.configured and pdf_raw:
        bg.add_task(
            mailer.send_report,
            to=email, host=host, pdf=base64.b64decode(pdf_raw),
            filename=filename, score=res.get("score"), level=res.get("level"),
            urgent=urgent, coverage=res.get("coverage"),
            report_url=f"{PUBLIC_URL}/scans/{req.job_id}/report.pdf",
        )

    # Aviso a comercial. Va en segundo plano igual que el del cliente.
    if mailer.configured and SALES_EMAIL:
        bg.add_task(mailer.send_lead_notice, to=SALES_EMAIL, lead=lead,
                    pdf=base64.b64decode(pdf_raw) if pdf_raw else None,
                    filename=filename)

    return {"ok": True,
            "download_url": f"/scans/{req.job_id}/report.pdf",
            "filename": filename,
            # La pagina usa esto para no prometer un correo que no salio.
            "email_sent": bool(mailer.configured and pdf_raw)}


@app.get("/i18n/{lang}.json")
def get_i18n(lang: str):
    """Los textos que la pagina necesita para mostrar los hallazgos.

    Viven en el mismo sitio que los del PDF, asi no divergen.
    """
    if lang not in ("es", "en", "fr", "pt"):
        raise HTTPException(404, "Idioma no disponible")
    path = pathlib.Path(__file__).parent / "locales" / f"{lang}.json"
    if not path.exists():
        path = path.with_name("es.json")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/scans/{job_id}/report.pdf")
def get_report(job_id: str):
    if not r.get(f"released:{job_id}") and not OPEN_REPORTS:
        raise HTTPException(402, "Indique un correo para recibir el informe")
    raw = r.get(f"pdf:{job_id}")
    if not raw:
        raise HTTPException(404, "Informe no disponible todavia")
    name = _report_filename(job_id)
    return Response(
        content=base64.b64decode(raw),
        media_type="application/pdf",
        # filename* con UTF-8 para que tildes y espacios lleguen intactos.
        headers={"Content-Disposition":
                 f"inline; filename*=UTF-8\'\'{quote(name)}"},
    )


class VerifyRequest(BaseModel):
    domain: str


@app.post("/verify/start")
def verify_start(req: VerifyRequest):
    """Genera el token y devuelve las instrucciones para el cliente."""
    try:
        return store.issue(req.domain)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/verify/check")
def verify_check(req: VerifyRequest):
    """Comprueba si el cliente ya publico el token."""
    try:
        return store.confirm(req.domain)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/verify/status")
def verify_status(domain: str):
    try:
        return {"domain": normalize_domain(domain),
                "verified": store.is_verified(domain)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/config")
def get_config():
    """La pagina lee de aqui su configuracion publica, para no tener que
    editar el HTML cada vez que cambie una clave."""
    return {"turnstile_site_key": TURNSTILE_SITE_KEY,
            "scans_per_hour": SCANS_PER_IP_PER_HOUR}


@app.get("/health")
def health():
    return {"ok": True}
