"""Verificacion de propiedad del dominio.

Por que existe: el escaneo profundo lanza cientos de peticiones de prueba
contra un sitio. Hacer eso sin permiso del dueno es, en el mejor caso,
abusivo, y en Peru puede caer bajo la Ley 30096 de delitos informaticos.

El cliente demuestra que controla el dominio de una de dos formas:

  1. Registro TXT en su DNS         cyberfusion-verify=<token>
  2. Archivo en la raiz del sitio   /.well-known/cyberfusion-<token>.txt

La primera es mas fuerte (controlar el DNS implica controlar el dominio).
La segunda es mas facil para quien no toca su DNS. Aceptamos ambas y
registramos cual se uso.

Ademas de lo legal, este paso convierte un visitante anonimo en un lead
identificado, y es el momento natural para pedirle que anada nuestra IP
a su lista blanca.
"""
import hashlib
import hmac
import json
import os
import secrets
import socket
import time
from urllib.parse import urlparse

import dns.resolver
import httpx

from . import brand

# Vida del token desde que se genera hasta que caduca sin usarse.
TOKEN_TTL_S = int(os.getenv("VERIFY_TOKEN_TTL", str(7 * 86400)))
# Cuanto dura la verificacion una vez conseguida, antes de repetirla.
VERIFIED_TTL_S = int(os.getenv("VERIFIED_TTL", str(90 * 86400)))

SECRET = os.getenv("VERIFY_SECRET", "")


def normalize_domain(raw: str) -> str:
    """Un dominio, sin esquema, sin www, en minusculas."""
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/")[0].split(":")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    if not raw or "." not in raw:
        raise ValueError("Dominio invalido")
    return raw


def make_token(domain: str) -> str:
    """Token ligado al dominio.

    No es un aleatorio suelto: lleva dentro una firma del dominio. Asi un
    token emitido para un sitio no sirve para verificar otro, aunque
    alguien lo copie de una respuesta de la API.
    """
    nonce = secrets.token_hex(8)
    if SECRET:
        sig = hmac.new(SECRET.encode(), f"{domain}:{nonce}".encode(),
                       hashlib.sha256).hexdigest()[:24]
    else:
        # Sin secreto configurado seguimos siendo funcionales, pero el
        # token deja de estar ligado criptograficamente al dominio.
        sig = hashlib.sha256(f"{domain}:{nonce}".encode()).hexdigest()[:24]
    return f"{nonce}{sig}"


def instructions(domain: str, token: str) -> dict:
    """Lo que se le muestra al cliente. En su idioma, no en el nuestro."""
    return {
        "domain": domain,
        "token": token,
        "methods": [
            {
                "id": "dns",
                "recommended": True,
                "title": "Registro TXT en su DNS",
                "steps": [
                    f"Entre al panel de DNS de {domain}.",
                    "Cree un registro TXT.",
                    f"Nombre o host: {brand.VERIFY_TXT_PREFIX}.{domain} "
                    f"(algunos paneles piden solo '{brand.VERIFY_TXT_PREFIX}').",
                    f"Valor: {brand.VERIFY_TXT_PREFIX}={token}",
                    "Guarde y espere unos minutos a que propague.",
                ],
                "record_name": f"{brand.VERIFY_TXT_PREFIX}.{domain}",
                "record_value": f"{brand.VERIFY_TXT_PREFIX}={token}",
            },
            {
                "id": "file",
                "recommended": False,
                "title": "Archivo en su servidor",
                "steps": [
                    f"Cree un archivo de texto con este contenido: {token}",
                    f"Subalo a https://{domain}/{brand.VERIFY_FILE_PREFIX}-{token}.txt",
                    "Compruebe que puede abrirlo en el navegador.",
                ],
                "file_url": f"https://{domain}/{brand.VERIFY_FILE_PREFIX}-{token}.txt",
                "file_content": token,
            },
        ],
        "expires_in_days": TOKEN_TTL_S // 86400,
        "whitelist_note": (
            f"Si su sitio usa un firewall (Cloudflare, Imunify360, Sucuri), "
            f"anada nuestra IP de salida a su lista blanca para que el "
            f"analisis sea completo. Detalles en {brand.SCANNER_PAGE}"
        ),
    }


def _check_dns(domain: str, token: str) -> bool:
    expected = f"{brand.VERIFY_TXT_PREFIX}={token}"
    for name in (f"{brand.VERIFY_TXT_PREFIX}.{domain}", domain):
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=10)
        except Exception:
            continue
        for rr in answers:
            # Un TXT largo llega partido en varias cadenas; hay que unirlas.
            value = "".join(p.decode() if isinstance(p, bytes) else str(p)
                            for p in getattr(rr, "strings", [])) or \
                    rr.to_text().strip('"')
            if value.strip() == expected:
                return True
    return False


def _check_file(domain: str, token: str) -> bool:
    url = f"https://{domain}/{brand.VERIFY_FILE_PREFIX}-{token}.txt"
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True,
                      headers={"User-Agent": brand.USER_AGENT})
    except Exception:
        return False
    if r.status_code != 200:
        return False
    # Si el servidor devuelve HTML es una pagina de error, no nuestro
    # archivo. Mismo error que ya nos mordio en el runner de exposicion.
    ctype = r.headers.get("content-type", "").lower()
    if "html" in ctype or r.text.lstrip()[:9].lower().startswith("<!doctype"):
        return False
    return r.text.strip() == token


def verify(domain: str, token: str) -> dict:
    """Comprueba ambos metodos. Devuelve cual funciono."""
    if _check_dns(domain, token):
        return {"verified": True, "method": "dns"}
    if _check_file(domain, token):
        return {"verified": True, "method": "file"}
    return {"verified": False, "method": None,
            "detail": "No encontramos el token. Si acaba de crear el "
                      "registro DNS, espere unos minutos e intentelo de nuevo."}


# --------------------------------------------------------------- persistencia
class Store:
    """Guarda tokens y verificaciones en Redis."""

    def __init__(self, redis_client):
        self.r = redis_client

    def issue(self, domain: str) -> dict:
        domain = normalize_domain(domain)
        token = make_token(domain)
        self.r.set(f"verify:token:{domain}", token, ex=TOKEN_TTL_S)
        return instructions(domain, token)

    def pending_token(self, domain: str) -> str | None:
        raw = self.r.get(f"verify:token:{normalize_domain(domain)}")
        return raw.decode() if raw else None

    def confirm(self, domain: str) -> dict:
        domain = normalize_domain(domain)
        token = self.pending_token(domain)
        if not token:
            return {"verified": False,
                    "detail": "No hay verificacion pendiente para este "
                              "dominio. Solicite un token nuevo."}
        result = verify(domain, token)
        if result["verified"]:
            self.r.set(f"verify:ok:{domain}",
                       json.dumps({"method": result["method"],
                                   "at": int(time.time())}),
                       ex=VERIFIED_TTL_S)
            self.r.delete(f"verify:token:{domain}")
        return result

    def is_verified(self, host: str) -> bool:
        """Verificar un dominio cubre sus subdominios.

        Quien controla el DNS de ejemplo.com controla tienda.ejemplo.com.
        Pedir un token por subdominio seria friccion sin seguridad extra.
        """
        try:
            host = normalize_domain(host)
        except ValueError:
            return False
        parts = host.split(".")
        for i in range(len(parts) - 1):
            if self.r.get(f"verify:ok:{'.'.join(parts[i:])}"):
                return True
        return False
