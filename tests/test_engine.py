"""Pruebas del motor 0.15 sin red: DNS, HTTP y fuentes externas simulados.

Cubren los casos de aceptacion de la especificacion (seccion 9) que se
pueden reproducir fuera de Azure. Ejecutar:  python -m pytest tests -q
"""
import asyncio
import json

import httpx
import pytest

from worker.engine import common, core, m2_dns, m3_m6_http as http, m7_m9_external as ext, m1_tls
from worker.engine.common import ModuleResult


# --------------------------------------------------------------- dobles
class FakeDNS:
    def __init__(self, records):
        self.records = records          # {(name, type): [values]}

    def query(self, name, rtype, resolver=None):
        return list(self.records.get((name, rtype), []))


def resp(url, status=200, text="", headers=None, content=None):
    req = httpx.Request("GET", url)
    if content is None:
        content = text.encode()
    return httpx.Response(status, content=content, headers=headers or {}, request=req)


def install(monkeypatch, dnsrec, pages, tls=None, rep=None, dom=None, subs=None, latest="6.8.2", plugins=None):
    fd = FakeDNS(dnsrec)
    monkeypatch.setattr(common, "dns_query", fd.query)
    monkeypatch.setattr(m2_dns, "dns_query", fd.query)
    monkeypatch.setattr(common, "dns_safe", fd.query)
    monkeypatch.setattr(m2_dns, "dns_safe", fd.query)
    monkeypatch.setattr(ext, "dns_safe", fd.query)

    async def adns(n, t):
        return fd.query(n, t)
    monkeypatch.setattr(core, "adns", adns)

    async def tls_run(host):
        return tls or ModuleResult("L1").finish()
    monkeypatch.setattr(m1_tls, "run", tls_run)

    async def get(self, url, max_read=None):
        self.requests += 1
        for key, val in pages.items():
            if url.endswith(key) or url == key:
                return val(url) if callable(val) else resp(url, *val) if isinstance(val, tuple) else val
        return resp(url, 404, "<html>no existe</html>", {"content-type": "text/html"})
    monkeypatch.setattr(http.SiteClient, "get", get)

    async def nosleep(_):
        return None
    monkeypatch.setattr(http.asyncio, "sleep", nosleep)

    async def lv():
        return latest
    monkeypatch.setattr(http, "latest_version", lv)

    async def pinfo(slug):
        return (plugins or {}).get(slug)
    monkeypatch.setattr(http, "_plugin_info", pinfo)

    monkeypatch.setattr(ext, "_reputation", rep or (lambda d: _rep_ok()))
    monkeypatch.setattr(ext, "_domain_info", lambda d: dom or {"expires": None, "locked": None, "source": None})
    monkeypatch.setattr(ext, "_lookalikes", lambda d: ([], []))
    monkeypatch.setattr(ext, "_subdomains", lambda d: subs if subs is not None else [])


def _rep_ok():
    from worker.engine.catalog import positive
    m = ModuleResult("L8")
    m.positives.append(positive("P-REP-001", n=2))
    m.note = "Sin registros en las 2 fuentes consultadas"
    return m.finish()


def run(host="empresa.com"):
    return asyncio.run(core.analyze(host))


BASE_DNS = {("empresa.com", "A"): ["93.184.216.34"], ("empresa.com", "NS"): ["ns1.x.", "ns2.x."],
            ("empresa.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
            ("_dmarc.empresa.com", "TXT"): ["v=DMARC1; p=reject"],
            ("empresa.com", "MX"): ["10 mx.empresa.com."],
            ("default._domainkey.empresa.com", "TXT"): ["v=DKIM1; p=MIIB"],
            ("empresa.com", "CAA"): ["0 issue letsencrypt.org"]}
SECURE_HEADERS = {"content-type": "text/html", "strict-transport-security": "max-age=31536000",
                  "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
                  "x-content-type-options": "nosniff", "referrer-policy": "strict-origin",
                  "permissions-policy": "camera=()"}


# ------------------------------------------------------------ casos 1..10
def test_1_bloqueado_por_imunify(monkeypatch):
    install(monkeypatch, BASE_DNS, {
        "https://empresa.com/": (200, "<html><script>wsidchk</script>Your request is being verified</html>",
                                 {"content-type": "text/html"})},
        dom={"expires": __import__("datetime").datetime(2027, 6, 1, tzinfo=__import__("datetime").timezone.utc),
             "locked": True, "source": "WHOIS"})
    r = run()
    assert r["status"] == "blocked"
    assert r["coverage"] == {"determined": 5, "total": 10}   # L1, L2, L8, L9, L10
    states = {l["id"]: l for l in r["layers"]}
    for L in ("L3", "L4", "L5", "L6"):
        assert states[L]["state"] == "undetermined" and states[L]["reason"] == "waf_blocked"
    assert r["waf"] == {"detected": True, "product": "imunify360"}
    assert any(p["id"] == "P-WAF-001" for p in r["positives"])
    assert r["score"] is not None          # decision: puntaje parcial
    assert states["L7"]["state"] == "needs_verification"


def test_2_wordpress_desactualizado(monkeypatch):
    html = ('<html><head><meta name="generator" content="WordPress 6.6.1"></head>'
            '<link href="/wp-content/plugins/contact-form-7/style.css?ver=5.1">'
            '<script src="/wp-content/themes/x/a.js"></script></html>')
    install(monkeypatch, BASE_DNS, {
        "https://empresa.com/": (200, html, {"content-type": "text/html"}),
        "/wp-json/wp/v2/users": (200, json.dumps([{"slug": "admin"}]), {"content-type": "application/json"}),
    }, plugins={"contact-form-7": {"version": "6.1", "updated": "2026-10-01 10:00am GMT"}})
    r = run()
    ids = {f["id"]: f for f in r["findings"]}
    assert "F-CMS-002" in ids and ids["F-CMS-002"]["severity"] == "alto"
    assert ids["F-CMS-002"]["title"] == "Tu gestor de contenidos (WordPress 6.6.1) está desactualizado"
    assert "F-CMS-003" in ids and ids["F-CMS-003"]["title"].endswith(": 1")
    assert "F-CMS-005" in ids
    assert r["status"] == "complete" and r["score"] is not None
    assert r["level"] in ("medio", "alto")         # hay hallazgo alto: nunca "bajo"


def test_3_correo_sin_dmarc(monkeypatch):
    d = dict(BASE_DNS)
    d.pop(("_dmarc.empresa.com", "TXT"))
    install(monkeypatch, d, {"https://empresa.com/": (200, "<html>ok</html>", SECURE_HEADERS)})
    f = {x["id"]: x for x in run()["findings"]}["F-MAIL-001"]
    assert f["severity"] == "alto"
    assert f["impact"].startswith("Un tercero puede enviar correos con tu dominio")


def test_4_dominio_inexistente(monkeypatch):
    install(monkeypatch, {}, {})
    r = run("noexiste-abc123.com")
    assert r["status"] == "error" and r["layers"] == [] and r["error"]["code"] == "dns_error"
    assert r["meta"]["durationMs"] < 5000


def test_6_fuente_de_reputacion_caida(monkeypatch):
    install(monkeypatch, BASE_DNS, {"https://empresa.com/": (200, "<html>ok</html>", SECURE_HEADERS)},
            rep=lambda d: ModuleResult("L8").undetermined("source_unavailable"))
    l8 = {l["id"]: l for l in run()["layers"]}["L8"]
    assert l8["state"] == "undetermined" and l8["reason"] == "source_unavailable"


def test_10_env_expuesto_fuerza_alto(monkeypatch):
    install(monkeypatch, BASE_DNS, {
        "https://empresa.com/": (200, "<html>ok</html>", SECURE_HEADERS),
        "/.env": (200, "APP_KEY=base64:xxx\nDB_PASSWORD=secreto\n", {"content-type": "text/plain"}),
    })
    r = run()
    ids = {f["id"] for f in r["findings"]}
    assert "F-FILE-001" in ids and r["level"] == "alto"
    ev = json.dumps(r["findings"])
    assert "secreto" not in ev and "APP_KEY" not in ev       # nunca se guarda contenido


def test_404_blando_no_inventa_archivos(monkeypatch):
    install(monkeypatch, BASE_DNS, {
        "https://empresa.com/": (200, "<html>ok</html>", SECURE_HEADERS),
        "cyberfusion-probe": (200, "<html>inicio</html>", {"content-type": "text/html"}),
    })
    # Toda ruta devuelve la portada en HTML con 200: no debe salir ningun archivo.
    monkeypatch.setattr(http.SiteClient, "get", _all_200)
    ids = {f["id"] for f in run()["findings"]}
    assert not any(i.startswith("F-FILE-00") and i != "F-FILE-007" for i in ids)


async def _all_200(self, url, max_read=None):
    self.requests += 1
    return resp(url, 200, "<!doctype html><html>inicio</html>", SECURE_HEADERS)


def test_403_sin_firma_no_es_firewall(monkeypatch):
    install(monkeypatch, BASE_DNS, {"https://empresa.com/": (403, "Forbidden", {"server": "LiteSpeed"})})
    r = run()
    assert r["waf"]["detected"] is False
    assert {l["id"]: l for l in r["layers"]}["L3"]["reason"] == "http_error"


def test_puntaje_y_topes():
    f = [{"id": "X", "layerId": "L3", "severity": "alto"}] * 5      # 75 en una capa
    assert core.score_of(f) == 70                                   # tope de 30 por capa
    assert core.level_of(95, [{"id": "Y", "layerId": "L1", "severity": "alto"}]) == "medio"


def test_spf_cuenta_consultas(monkeypatch):
    rec = {("a.com", "TXT"): ["v=spf1 include:b.com include:c.com -all"],
           ("b.com", "TXT"): ["v=spf1 " + " ".join(f"include:x{i}.com" for i in range(6)) + " -all"],
           ("c.com", "TXT"): ["v=spf1 a mx -all"]}
    monkeypatch.setattr(m2_dns, "dns_safe", FakeDNS(rec).query)
    assert m2_dns._spf_lookups(rec[("a.com", "TXT")][0]) == 10
