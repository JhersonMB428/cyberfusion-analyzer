"""Envio de correo del analizador.

HTML compatible con Outlook de escritorio, que renderiza con el motor de
Word: solo tablas, estilos en linea, anchos en pixeles, colores de fondo
sobre <td> y nunca sobre <div>. Nada de flexbox, grid, border-radius ni
hojas de estilo externas.

SMTP a proposito: funciona igual con Microsoft 365, Google Workspace o el
correo del hosting. Si no hay SMTP configurado no falla: registra el
motivo y devuelve False, y la API usa ese valor para no prometer al
usuario un correo que no salio.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from . import brand

HOST = os.getenv("SMTP_HOST", "")
PORT = int(os.getenv("SMTP_PORT", "587"))
USER = os.getenv("SMTP_USER", "")
PASS = os.getenv("SMTP_PASS", "")
FROM = os.getenv("SMTP_FROM", brand.CONTACT_EMAIL)
FROM_NAME = os.getenv("SMTP_FROM_NAME", "Cyberfusion Technologies")
# 465 = SSL directo. 587 = STARTTLS. Es el error de configuracion mas
# comun, asi que se deduce del puerto en vez de pedir otra variable.
USE_SSL = os.getenv("SMTP_SSL", "").lower() in ("1", "true", "yes") or PORT == 465

configured = bool(HOST and USER and PASS)

INK = "#08080b"
RED = "#f63b2f"
TXT = "#17171c"
MUT = "#6a6a76"
LINE = "#e3e3e8"
WARM = "#faf9f9"
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"


def _shell(inner: str, preheader: str = "") -> str:
    """Estructura exterior comun. Tabla de 600px centrada.

    El preheader es el texto que Gmail y Outlook muestran junto al asunto
    en la bandeja. Sin el, muestran el primer texto que encuentren, que
    suele ser basura.
    """
    return f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<!--[if mso]><xml><o:OfficeDocumentSettings>
<o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->
<title>Cyberfusion</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f1f4;">
<div style="display:none;font-size:1px;color:#f1f1f4;max-height:0;overflow:hidden;">{preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
 style="background-color:#f1f1f4;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
 style="width:600px;max-width:600px;background-color:#ffffff;">
  <tr><td style="background-color:{INK};padding:22px 28px;">
    <span style="font-family:{FONT};font-size:17px;font-weight:bold;color:#ffffff;">Cyber</span><span
     style="font-family:{FONT};font-size:17px;font-weight:bold;color:{RED};">Fusion</span>
  </td></tr>
  {inner}
  <tr><td style="background-color:{WARM};padding:18px 28px;border-top:1px solid {LINE};
   font-family:{FONT};font-size:12px;line-height:1.6;color:#8a8a96;">
    <a href="{brand.SITE_URL}" style="color:{RED};text-decoration:none;">{brand.DOMAIN}</a>
    &nbsp;&middot;&nbsp; {brand.CONTACT_EMAIL}
  </td></tr>
</table>
</td></tr></table></body></html>"""


def _button(url: str, label: str) -> str:
    """Boton que tambien se ve en Outlook de escritorio.

    Outlook ignora el padding de un <a>, asi que el bloque VML de dentro
    del comentario condicional dibuja el rectangulo; los demas clientes
    lo ignoran y usan el enlace normal.
    """
    return f"""<!--[if mso]>
<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word"
 href="{url}" style="height:44px;v-text-anchor:middle;width:230px;" arcsize="12%"
 stroke="f" fillcolor="{RED}">
<w:anchorlock/><center style="color:#ffffff;font-family:{FONT};font-size:15px;font-weight:bold;">
{label}</center></v:roundrect><![endif]-->
<!--[if !mso]><!-- -->
<a href="{url}" style="background-color:{RED};color:#ffffff;display:inline-block;
 font-family:{FONT};font-size:15px;font-weight:bold;line-height:44px;text-align:center;
 text-decoration:none;width:230px;-webkit-text-size-adjust:none;">{label}</a>
<!--<![endif]-->"""


def _row(label: str, value: str, link: str = "") -> str:
    v = f'<a href="{link}" style="color:{RED};text-decoration:none;">{value}</a>' if link else value
    return f"""<tr>
<td style="font-family:{FONT};font-size:14px;color:{MUT};padding:5px 16px 5px 0;
 white-space:nowrap;vertical-align:top;">{label}</td>
<td style="font-family:{FONT};font-size:14px;color:{TXT};padding:5px 0;
 vertical-align:top;">{v}</td></tr>"""


def _send(msg: EmailMessage, who: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        if USE_SSL:
            with smtplib.SMTP_SSL(HOST, PORT, context=ctx, timeout=25) as s:
                s.login(USER, PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(HOST, PORT, timeout=25) as s:
                s.starttls(context=ctx)
                s.login(USER, PASS)
                s.send_message(msg)
        print(f"[mail] enviado a {who}", flush=True)
        return True
    except Exception as e:
        print(f"[mail] fallo hacia {who}: {type(e).__name__}: {e}", flush=True)
        return False


# ------------------------------------------------ informe para el cliente
def send_report(to: str, host: str, pdf: bytes, filename: str,
                score=None, grade=None, urgent: int = 0,
                report_url: str = "") -> bool:
    if not configured:
        print("[mail] SMTP sin configurar: no se envia nada", flush=True)
        return False

    if score is None:
        titular = f"No pudimos completar el analisis de {host}"
        detalle = ("El sitio bloqueo el analisis automatizado. El informe "
                   "adjunto explica que se pudo revisar y que no.")
    elif urgent:
        n, verbo = ("punto", "requiere") if urgent == 1 else ("puntos", "requieren")
        titular = f"{host}: {urgent} {n} que {verbo} atencion"
        detalle = (f"Su sitio obtuvo {score} de 100 (nota {grade}). El informe "
                   f"adjunto detalla cada hallazgo y como corregirlo.")
    else:
        titular = f"{host}: sin riesgos altos ni criticos"
        detalle = (f"Su sitio obtuvo {score} de 100 (nota {grade}). El informe "
                   f"adjunto recoge los puntos de mejora pendientes y lo que "
                   f"su sitio ya hace bien.")

    url = report_url or brand.SITE_URL
    txt = f"""{titular}

{detalle}

Descargar el informe:
{url}

Que contiene:
- Resumen ejecutivo para direccion
- Cada hallazgo con su evidencia y como corregirlo
- Que capas se revisaron y cuales no, con el motivo
- Lo que su sitio ya hace bien

Este analisis refleja el estado del sitio en el momento de ejecutarlo. La
seguridad de una web cambia con cada actualizacion y cada vulnerabilidad
publicada, asi que conviene repetirlo periodicamente.

Si necesita un analisis mas profundo o que corrijamos los hallazgos,
escribanos a {brand.SALES_EMAIL_PUBLIC}

--
{FROM_NAME} · {brand.SITE_URL}
Recibe este correo porque solicito un analisis en nuestra web.
Para dejar de recibirlos, responda con "baja".
"""

    inner = f"""<tr><td style="padding:30px 28px 26px 28px;">
  <h1 style="margin:0 0 12px 0;font-family:{FONT};font-size:20px;line-height:1.3;
   color:{TXT};font-weight:bold;">{titular}</h1>
  <p style="margin:0 0 24px 0;font-family:{FONT};font-size:15px;line-height:1.6;color:#44444e;">
   {detalle}</p>
  {_button(url, "Descargar el informe")}
  <p style="margin:20px 0 0 0;font-family:{FONT};font-size:13px;color:{MUT};">
   Tambien lo tiene adjunto a este correo.</p>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
   <tr><td style="border-top:1px solid {LINE};padding-top:22px;">
    <p style="margin:0 0 10px 0;font-family:{FONT};font-size:14px;font-weight:bold;color:{TXT};">
     Que contiene</p>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
     {''.join(f'''<tr><td style="font-family:{FONT};font-size:14px;line-height:1.7;
      color:#44444e;padding:0 0 4px 0;">&bull;&nbsp; {x}</td></tr>''' for x in (
       "Resumen ejecutivo para direccion",
       "Cada hallazgo con su evidencia y como corregirlo",
       "Que capas se revisaron y cuales no, con el motivo",
       "Lo que su sitio ya hace bien"))}
    </table>
   </td></tr>
   <tr><td style="padding-top:22px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
     <tr><td style="background-color:{WARM};border-left:3px solid {RED};padding:14px 18px;
      font-family:{FONT};font-size:13.5px;line-height:1.6;color:#44444e;">
      &iquest;Necesita un analisis mas profundo o que corrijamos los hallazgos?
      Escribanos a <a href="mailto:{brand.SALES_EMAIL_PUBLIC}"
      style="color:{RED};text-decoration:none;font-weight:bold;">{brand.SALES_EMAIL_PUBLIC}</a>
      y le preparamos una cotizacion.</td></tr>
    </table>
   </td></tr>
  </table>
  <p style="margin:22px 0 0 0;font-family:{FONT};font-size:12px;line-height:1.6;color:#8a8a96;">
   Este analisis refleja el estado del sitio en el momento de ejecutarlo. La seguridad
   de una web cambia con cada actualizacion y cada vulnerabilidad publicada, asi que
   conviene repetirlo periodicamente.</p>
</td></tr>"""

    msg = EmailMessage()
    msg["Subject"] = f"Informe de seguridad de {host}"
    msg["From"] = formataddr((FROM_NAME, FROM))
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain=brand.DOMAIN)
    msg["List-Unsubscribe"] = f"<mailto:{brand.CONTACT_EMAIL}?subject=baja>"
    msg.set_content(txt)
    msg.add_alternative(_shell(inner, titular), subtype="html")
    if pdf:
        msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=filename)
    else:
        print("[mail] AVISO: informe sin PDF adjunto", flush=True)

    return _send(msg, to)


# ------------------------------------------------- aviso interno de lead
def send_lead_notice(to: str, lead: dict, pdf: bytes | None = None,
                     filename: str = "informe.pdf") -> bool:
    """Un comercial no entra a un panel cada dia: el lead tiene que
    llegarle donde ya mira, y con el informe adjunto para poder llamar
    sabiendo de que se habla."""
    if not configured:
        return False

    host = (lead.get("domain") or "").split("://")[-1].strip("/")
    nota = (f"{lead['score']}/100 (nota {lead['grade']})"
            if lead.get("score") is not None else "analisis parcial")
    email = lead.get("email", "")
    phone = lead.get("phone", "")

    txt = f"""Lead nuevo desde el analizador web

Contacto : {lead.get('name')}
Empresa  : {lead.get('company')}
Correo   : {email}
Telefono : {phone}

Sitio    : {host}
Resultado: {nota}
Fecha    : {lead.get('at')}

El informe que recibio el cliente va adjunto.
Responda a este correo para escribirle directamente.
"""

    inner = f"""<tr><td style="padding:28px 28px 8px 28px;">
  <h1 style="margin:0 0 4px 0;font-family:{FONT};font-size:19px;color:{TXT};font-weight:bold;">
   Lead nuevo desde el analizador</h1>
  <p style="margin:0 0 20px 0;font-family:{FONT};font-size:12.5px;color:{MUT};">
   {lead.get('at','')}</p>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
   {_row("Contacto", lead.get('name',''))}
   {_row("Empresa", lead.get('company',''))}
   {_row("Correo", email, f"mailto:{email}")}
   {_row("Telefono", phone, f"tel:{phone}")}
  </table>
</td></tr>
<tr><td style="padding:14px 28px 24px 28px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
   <tr><td style="background-color:{WARM};border-left:3px solid {RED};padding:16px 18px;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
     {_row("Sitio", host, lead.get('domain',''))}
     {_row("Resultado", nota)}
    </table>
   </td></tr>
  </table>
  <p style="margin:20px 0 0 0;font-family:{FONT};font-size:13px;line-height:1.6;color:{MUT};">
   El informe que recibio el cliente va adjunto.
   <b style="color:{TXT};">Responda a este correo</b> para escribirle directamente.</p>
</td></tr>"""

    msg = EmailMessage()
    msg["Subject"] = f"Lead: {lead.get('company')} - {host} ({nota})"
    msg["From"] = formataddr((FROM_NAME, FROM))
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain=brand.DOMAIN)
    # Responder lleva al cliente, no al buzon tecnico del escaner.
    if email:
        msg["Reply-To"] = email
    msg.set_content(txt)
    msg.add_alternative(_shell(inner, f"{lead.get('company')} - {host}"), subtype="html")
    if pdf:
        msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=filename)
        print(f"[mail] aviso con PDF ({len(pdf)} bytes)", flush=True)
    else:
        print("[mail] AVISO: lead sin PDF adjunto", flush=True)

    return _send(msg, to)
