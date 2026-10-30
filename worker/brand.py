"""Identidad del producto. Un solo sitio.

Se desincronizo una vez entre el user-agent, el colofon del PDF y el
token de verificacion. Todo lo que mencione el dominio importa aqui.
"""
DOMAIN        = "cyberfusion.global"
SITE_URL      = f"https://{DOMAIN}"
SCANNER_PAGE  = f"{SITE_URL}/scanner"
ANALYZER_HOST = f"analyzer.{DOMAIN}"
ABUSE_EMAIL   = f"abuse@{DOMAIN}"
CONTACT_EMAIL = f"scanner@{DOMAIN}"
SALES_EMAIL_PUBLIC = f"contacto@{DOMAIN}"
CONTACT_PAGE = f"{SITE_URL}/contacto"

# Logo de la portada del PDF. Vacio = usa report/assets/logo.png, que va
# dentro del contenedor. Cargarlo desde la web fallaba al generar el PDF
# en Azure (el sitio no entregaba la imagen al servidor).
LOGO_URL = ""

SCANNER_NAME  = "CyberfusionScanner"
VERSION       = "1.0"
USER_AGENT    = f"{SCANNER_NAME}/{VERSION} (+{SCANNER_PAGE})"

# Verificacion de propiedad del dominio
VERIFY_TXT_PREFIX  = "cyberfusion-verify"
VERIFY_FILE_PREFIX = ".well-known/cyberfusion"
PROBE_PREFIX       = "cyberfusion-probe"
