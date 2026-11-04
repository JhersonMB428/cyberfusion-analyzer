"""Catalogo de hallazgos y aciertos en lenguaje de negocio (fase 1).

Los textos salen tal cual de la especificacion "Motor de analisis · Fase 1"
(seccion 5). El motor los copia a title, impact y fix; la interfaz y el PDF
solo los muestran. Si hay que cambiar una frase, se cambia aqui y en ningun
otro sitio.

Lo que va entre llaves ({n}, {cms}...) lo rellena el modulo que emite el
hallazgo. Las severidades son: alto, medio, bajo, observ.

Terminologia: el analisis pasivo NO confirma vulnerabilidades. Hablamos de
"hallazgos" y "riesgos visibles"; la unica mencion a vulnerabilidades es la
capa L7, que queda pendiente de verificar la propiedad del dominio.
"""

# id: (capa, titulo, impacto, que hacer, esfuerzo)
FINDINGS: dict[str, tuple[str, str, str, str, str]] = {
    # ---------------------------------------------------- L1 Certificado
    "F-TLS-001": ("L1", "Tu certificado venció",
                  "Los navegadores muestran una advertencia de seguridad y muchos clientes no entrarán a tu sitio.",
                  "Renueva el certificado hoy y activa la renovación automática.", "bajo"),
    "F-TLS-002": ("L1", "Tu certificado vence en {n} días",
                  "Si no se renueva a tiempo, tu sitio mostrará una advertencia y perderás visitas y confianza.",
                  "Programa la renovación y activa la renovación automática.", "bajo"),
    "F-TLS-003": ("L1", "Tu certificado es autofirmado",
                  "Los navegadores lo rechazan y tus clientes verán una advertencia.",
                  "Instala un certificado de una autoridad reconocida; hay opciones gratuitas.", "bajo"),
    "F-TLS-004": ("L1", "El certificado no corresponde a tu dominio",
                  "Los visitantes ven una advertencia de conexión no segura al entrar.",
                  "Emite un certificado que incluya este dominio y su versión con www.", "bajo"),
    "F-TLS-005": ("L1", "La cadena del certificado está incompleta",
                  "Algunos dispositivos, sobre todo móviles y sistemas antiguos, no confiarán en tu sitio.",
                  "Instala el certificado intermedio que entrega tu autoridad emisora.", "bajo"),
    "F-TLS-006": ("L1", "Aceptas protocolos de cifrado antiguos ({protocolos})",
                  "Alguien en la misma red podría leer o alterar lo que envían tus visitantes, y puede incumplir requisitos de auditorías y medios de pago.",
                  "Desactiva TLS 1.0 y 1.1 en el servidor o en el panel de tu hosting.", "bajo"),
    "F-TLS-007": ("L1", "Hay cifrados débiles habilitados",
                  "Reducen la protección de la información que viaja entre tu sitio y tus clientes.",
                  "Pide a tu proveedor el perfil de cifrado “moderno”.", "medio"),
    # ----------------------------------------------------- L2 DNS y correo
    "F-MAIL-001": ("L2", "No tienes DMARC: pueden suplantar tu correo",
                   "Un tercero puede enviar correos con tu dominio, como facturas o pedidos de pago falsos, y tus clientes los verán como tuyos.",
                   "Publica un registro DMARC; empieza en p=none con reportes y avanza hasta p=reject.", "medio"),
    "F-MAIL-002": ("L2", "Tu DMARC solo monitorea (p=none)",
                   "Detecta suplantaciones pero no las bloquea: los correos falsos siguen llegando a tus clientes.",
                   "Revisa los reportes y sube a p=quarantine y luego a p=reject.", "medio"),
    "F-MAIL-003": ("L2", "Tu DMARC está en cuarentena, aún no en rechazo",
                   "Ya protege, pero parte de los correos falsos aún puede llegar a spam en lugar de bloquearse.",
                   "Cuando los reportes muestren que tus envíos legítimos pasan, sube a p=reject.", "bajo"),
    "F-MAIL-004": ("L2", "No tienes SPF",
                   "Los servidores de correo no pueden verificar quién envía en tu nombre: tus mensajes pueden caer en spam y los falsos pasan.",
                   "Publica un registro SPF con los servicios que envían correo por ti.", "bajo"),
    "F-MAIL-005": ("L2", "Tu SPF permite que cualquiera envíe correo (+all)",
                   "Equivale a no tener protección: cualquier servidor puede enviar como tu empresa.",
                   "Cambia +all por -all o ~all.", "bajo"),
    "F-MAIL-006": ("L2", "Tu SPF es demasiado permisivo (?all)",
                   "No bloquea suplantaciones.",
                   "Cambia ?all por -all o ~all.", "bajo"),
    "F-MAIL-007": ("L2", "Tu SPF tiene errores",
                   "Con más de 10 consultas o registros duplicados, muchos servidores lo ignoran y la protección no funciona.",
                   "Simplifica el SPF a un solo registro con menos de 10 consultas.", "medio"),
    "F-MAIL-008": ("L2", "No detectamos DKIM en los nombres habituales",
                   "No es concluyente, porque puede usar otro nombre, pero firmar tus correos mejora su entrega y evita suplantaciones.",
                   "Confirma con tu proveedor de correo que DKIM está activo.", "bajo"),
    "F-DNS-001": ("L2", "No tienes registro CAA",
                  "Cualquier autoridad certificadora podría emitir un certificado para tu dominio.",
                  "Publica un registro CAA con la autoridad que usas.", "bajo"),
    "F-DNS-002": ("L2", "DNSSEC no está activo",
                  "Es una mejora deseable, no un riesgo inmediato: protege que tus visitantes lleguen al servidor real.",
                  "Actívalo desde tu registrador si lo soporta.", "medio"),
    "F-DNS-003": ("L2", "Tu dominio depende de un solo servidor DNS",
                  "Si falla, tu sitio y tu correo dejan de funcionar.",
                  "Agrega al menos un segundo servidor de nombres.", "bajo"),
    # ----------------------------------------------------- L3 Cabeceras
    "F-HDR-001": ("L3", "Tu sitio no redirige de http a https",
                  "Quien escribe tu dirección sin https entra a una versión sin cifrar.",
                  "Redirige todo el tráfico http a https con una redirección 301.", "bajo"),
    "F-HDR-002": ("L3", "Tu sitio no obliga al uso de HTTPS (falta HSTS)",
                  "Alguien en una red pública podría forzar a tus visitantes a usar la versión sin cifrar.",
                  "Activa HSTS con una vigencia de al menos 6 meses.", "bajo"),
    "F-HDR-003": ("L3", "Tu sitio no tiene política de contenido (CSP)",
                  "Si alguien logra inyectar un script en tu página, el navegador no lo bloqueará y podría robar datos de tus clientes.",
                  "Define una CSP; empieza en modo “solo reporte”.", "alto"),
    "F-HDR-004": ("L3", "Tu página carga recursos sin cifrar (contenido mixto)",
                  "El navegador puede mostrar un aviso de “no seguro” y esos recursos podrían ser alterados.",
                  "Cambia las direcciones http:// de scripts, imágenes y estilos por https://.", "bajo"),
    "F-HDR-005": ("L3", "Tu página puede mostrarse dentro de otro sitio",
                  "Un tercero puede incrustarla en una página falsa y engañar a tus clientes para que hagan clic.",
                  "Agrega X-Frame-Options o frame-ancestors.", "bajo"),
    "F-HDR-006": ("L3", "Tus cookies de sesión no tienen todas las protecciones",
                  "Las sesiones de tus usuarios podrían ser robadas o usadas desde otros sitios.",
                  "Marca las cookies con Secure, HttpOnly y SameSite.", "bajo"),
    "F-HDR-007": ("L3", "Falta la cabecera X-Content-Type-Options",
                  "El navegador puede interpretar archivos de forma insegura.",
                  "Agrega X-Content-Type-Options: nosniff.", "bajo"),
    "F-HDR-008": ("L3", "Faltan Referrer-Policy y Permissions-Policy",
                  "Son mejoras de privacidad: tus direcciones internas pueden filtrarse a otros sitios.",
                  "Agrégalas con los valores recomendados.", "bajo"),
    # ----------------------------------------------- L4 Archivos sensibles
    "F-FILE-001": ("L4", "Tu archivo de configuración (.env) es público",
                   "Puede contener claves de tu base de datos, correo y pagos; cualquiera podría usarlas para entrar a tus sistemas.",
                   "Bloquea el acceso ahora, cambia todas las claves que contenía y revisa los accesos recientes.", "bajo"),
    "F-FILE-002": ("L4", "Tu repositorio de código (.git) es accesible",
                   "Permite descargar tu código fuente y, a veces, claves y contraseñas.",
                   "Bloquea el acceso a .git y cambia las credenciales que hayan estado en el código.", "bajo"),
    "F-FILE-003": ("L4", "Hay respaldos o copias de base de datos públicos",
                   "Cualquiera podría descargar la información de tus clientes.",
                   "Retira los archivos de la carpeta pública y guárdalos fuera del servidor web.", "bajo"),
    "F-FILE-004": ("L4", "Hay un archivo que revela la configuración interna (phpinfo)",
                   "Muestra versiones y rutas que facilitan preparar un ataque.",
                   "Elimina el archivo.", "bajo"),
    "F-FILE-005": ("L4", "El listado de carpetas está habilitado",
                   "Cualquiera puede ver y descargar los archivos de esas carpetas.",
                   "Desactiva el listado de directorios en el servidor.", "bajo"),
    "F-FILE-006": ("L4", "Tu panel de base de datos (phpMyAdmin) es accesible desde Internet",
                   "Es un blanco frecuente de ataques que prueban contraseñas.",
                   "Restríngelo por IP o retíralo.", "bajo"),
    "F-FILE-007": ("L4", "No tienes archivo security.txt",
                   "Quien encuentre un fallo en tu sitio no sabe a quién avisar.",
                   "Publica /.well-known/security.txt con un correo de contacto.", "bajo"),
    # ---------------------------------------------------- L5 Gestor (CMS)
    "F-CMS-001": ("L5", "Tu sitio muestra qué sistema y versión usa",
                  "Facilita que un atacante busque fallos específicos de esa versión.",
                  "Oculta la versión del sistema en el código de la página.", "bajo"),
    "F-CMS-002": ("L5", "Tu gestor de contenidos ({cms} {version}) está desactualizado",
                  "Las versiones antiguas acumulan fallos públicos que se aprovechan de forma automática.",
                  "Haz un respaldo, actualiza y activa las actualizaciones automáticas de seguridad.", "medio"),
    "F-CMS-003": ("L5", "Hay extensiones (plugins) desactualizadas: {n}",
                  "Los plugins son la puerta de entrada más común en sitios WordPress.",
                  "Actualízalas o elimina las que no uses.", "bajo"),
    "F-CMS-004": ("L5", "Hay extensiones sin actualizaciones desde hace más de 2 años: {n}",
                  "Ya no reciben correcciones de seguridad.",
                  "Reemplázalas por alternativas que sigan mantenidas.", "medio"),
    "F-CMS-005": ("L5", "Tu sitio muestra la lista de tus usuarios",
                  "Quien la vea ya conoce tus nombres de usuario y solo le falta adivinar la contraseña.",
                  "Restringe esa ruta o desactiva la lista pública de usuarios.", "bajo"),
    # -------------------------------------------------- L6 Servidor y WAF
    "F-SRV-001": ("L6", "Tu servidor usa {software} {version}, una versión sin soporte",
                  "Ya no recibe correcciones de seguridad: cualquier fallo nuevo queda sin parche.",
                  "Migra a una versión con soporte; consulta a tu proveedor de hosting.", "medio"),
    "F-SRV-002": ("L6", "Tu servidor revela su versión exacta",
                  "Ayuda a un atacante a buscar fallos conocidos de esa versión.",
                  "Oculta las cabeceras de versión (Server y X-Powered-By).", "bajo"),
    "F-SRV-003": ("L6", "No detectamos un firewall de aplicación",
                  "Un firewall filtra ataques comunes antes de que lleguen a tu sitio. No es obligatorio, pero ayuda.",
                  "Evalúa activar uno; muchos hostings lo incluyen.", "medio"),
    # ------------------------------------------------- L8 Reputacion
    # Sin coste de licencias: la reputacion se consulta a filtros de DNS
    # publicos de seguridad (Quad9 y Cloudflare). Por eso el titulo no
    # nombra a Google Safe Browsing como la especificacion original.
    "F-REP-001": ("L8", "Tu dominio está bloqueado como peligroso en filtros de seguridad",
                  "Quienes navegan con esos filtros no pueden entrar a tu sitio y lo verán como peligroso: pierdes visitas y la confianza de tus clientes.",
                  "Haz revisar el sitio por un especialista, elimina el código malicioso y solicita la revisión a cada filtro.", "alto"),
    "F-REP-002": ("L8", "Tu dominio aparece en listas de malware (URLhaus)",
                  "Es posible que tu sitio esté distribuyendo software malicioso sin que lo sepas.",
                  "Haz revisar el sitio, elimina el código malicioso y cambia todas las contraseñas.", "alto"),
    # ------------------------------------------------- L9 Dominio y marca
    "F-DOM-001": ("L9", "Tu dominio vence en {n} días",
                  "Si vence, tu sitio y tu correo dejan de funcionar y un tercero podría registrarlo.",
                  "Renueva ahora y activa la renovación automática.", "bajo"),
    "F-DOM-002": ("L9", "Tu dominio vence en {n} días",
                  "Un descuido puede dejarte sin sitio ni correo.",
                  "Programa la renovación.", "bajo"),
    "F-DOM-003": ("L9", "Tu dominio no tiene bloqueo de transferencia",
                  "Alguien con acceso a tu cuenta del registrador podría transferirlo.",
                  "Activa el bloqueo en tu registrador.", "bajo"),
    "F-BRAND-001": ("L9", "Hay {n} dominios muy parecidos al tuyo, registrados y con correo activo",
                    "Pueden usarse para enviar correos falsos a tus clientes desde una dirección casi idéntica a la tuya. Confirma si alguno es tuyo.",
                    "Si no son tuyos, evalúa registrarlos de forma defensiva y reporta el uso indebido.", "medio"),
    "F-BRAND-002": ("L9", "Hay {n} dominios parecidos al tuyo registrados, sin correo activo",
                    "Por ahora no se usan para correo, pero conviene vigilarlos.",
                    "Revísalos de forma periódica.", "bajo"),
    # ------------------------------------------------ L10 Superficie
    "F-SURF-001": ("L10", "Hay subdominios de pruebas o administración visibles en Internet",
                   "Suelen tener menos protección que el sitio principal y son una vía de entrada frecuente.",
                   "Retíralos de Internet o restringe el acceso por IP o VPN.", "medio"),
    "F-SURF-002": ("L10", "Un subdominio apunta a un servicio que ya no existe",
                   "Un tercero podría tomar ese subdominio y publicar contenido falso con tu marca.",
                   "Elimina el registro DNS o recupera el servicio.", "bajo"),
}

# id: (capa, titulo, detalle)
POSITIVES: dict[str, tuple[str, str, str]] = {
    "P-TLS-001": ("L1", "Certificado SSL válido y vigente", "Vence en {n} días · Emisor: {emisor}"),
    "P-TLS-002": ("L1", "Cifrado moderno (TLS 1.3)", "Protocolo negociado: {protocolo}"),
    "P-MAIL-001": ("L2", "SPF configurado correctamente", "Registro publicado: {spf}"),
    "P-MAIL-002": ("L2", "DMARC en rechazo", "Política: p=reject"),
    "P-HDR-001": ("L3", "HSTS activo", "Vigencia: {n} días"),
    "P-FILE-001": ("L4", "No encontramos archivos sensibles expuestos", "Revisamos {n} rutas comunes"),
    "P-WAF-001": ("L6", "Sitio protegido por un firewall de aplicación", "Producto: {producto}"),
    "P-REP-001": ("L8", "Sin registros en listas negras", "Fuentes consultadas: {n}"),
    "P-DOM-001": ("L9", "Dominio con vigencia holgada y bloqueo de transferencia", "Vence en {n} días"),
}

SEVERITIES = ("alto", "medio", "bajo", "observ")


class _Safe(dict):
    """Deja la variable a la vista si falta, en vez de reventar el analisis."""
    def __missing__(self, k):
        return "{" + k + "}"


def finding(fid: str, severity: str, evidence: dict | None = None, **vars) -> dict:
    layer, title, impact, fix, effort = FINDINGS[fid]
    assert severity in SEVERITIES, severity
    v = _Safe(**{k: str(x) for k, x in vars.items()})
    return {"id": fid, "layerId": layer, "severity": severity,
            "title": title.format_map(v), "impact": impact.format_map(v),
            "fix": fix.format_map(v), "effort": effort,
            "evidence": evidence or {}}


def positive(pid: str, **vars) -> dict:
    layer, title, detail = POSITIVES[pid]
    v = _Safe(**{k: str(x) for k, x in vars.items()})
    return {"id": pid, "layerId": layer, "title": title.format_map(v),
            "detail": detail.format_map(v)}
