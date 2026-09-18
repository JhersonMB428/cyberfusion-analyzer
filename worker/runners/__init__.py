from .headers import run as headers_run
from .tls import run as tls_run
from .dns_mail import run as dns_run
from .exposure import run as exposure_run
from .wordpress import run as wordpress_run
from .stack import run as stack_run
from .nuclei import run as nuclei_run

# (nombre, funcion, necesita_http)
#
# tls y dns_mail NO usan HTTP: abren su propio socket TLS y consultan al
# resolver. Siguen siendo fiables aunque un WAF bloquee las peticiones
# web, asi que un sitio protegido igual recibe un informe parcial util.
ALL_RUNNERS = [
    ("tls",       tls_run,       False),
    ("dns_mail",  dns_run,       False),
    ("headers",   headers_run,   True),
    ("exposure",  exposure_run,  True),
    ("wordpress", wordpress_run, True),
    ("stack",     stack_run,     True),
    ("nuclei",    nuclei_run,    True),   # solo en modo profundo
]
