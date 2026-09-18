"""Validacion de destinos: evita que el escaner apunte a la red interna.

Se usa en TRES momentos a proposito:

  - la API valida al recibir la URL, para rechazar rapido y con un
    mensaje claro para el usuario;
  - el worker vuelve a validar justo antes de conectar, porque entre
    ambos momentos pueden pasar minutos en la cola y el DNS del
    objetivo puede haber cambiado (DNS rebinding);
  - ClienteSeguro valida cada peticion y cada redirect, porque un sitio
    publico puede responder 302 hacia una direccion interna y un cliente
    HTTP normal la seguiria sin preguntar.

Validar solo en la API no sirve: es un control sobre una respuesta DNS
que ya caduco cuando el escaneo realmente ocurre.
"""
import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

REDIRECCIONES = (301, 302, 303, 307, 308)


class DestinoNoPermitido(ValueError):
    """El host resuelve a una direccion que no debemos tocar."""


class NoResuelve(ValueError):
    """El host no resuelve a ninguna direccion."""


class DemasiadosRedirects(ValueError):
    """La cadena de redirects supero el limite."""


def _desenvolver(ip):
    """127.0.0.1 disfrazado de IPv6 sigue siendo 127.0.0.1.

    ::ffff:127.0.0.1 y 2002:7f00:1:: son formas validas de escribir
    direcciones IPv4 dentro de IPv6. Sin desenvolverlas, is_loopback
    devuelve False y el filtro no las ve.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip.teredo:
            return ip.teredo[1]
    return ip


def es_bloqueada(ip) -> bool:
    """True si la direccion pertenece a la infraestructura, no a internet.

    is_link_local cubre 169.254.0.0/16, que incluye 169.254.169.254:
    el endpoint de metadatos de Azure, AWS y GCP. Ese es el objetivo
    clasico de un SSRF contra un servicio en la nube, porque devuelve
    credenciales.
    """
    ip = _desenvolver(ip)
    return (ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified)


def normalizar_host(host: str) -> str:
    """Deja el host en una forma unica antes de compararlo con listas.

    Sin esto, 'WWW.GOB.PE.' con punto final no coincide con el sufijo
    '.gob.pe' y se salta la lista de exclusion. Lo mismo con dominios
    internacionalizados: hay que pasarlos a punycode para que la
    comparacion sea contra lo que realmente se va a resolver.
    """
    host = host.strip().rstrip(".").lower()
    if not host:
        raise DestinoNoPermitido("URL invalida")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise DestinoNoPermitido("Dominio no valido") from e


def resolver_publica(host: str) -> list[str]:
    """Devuelve TODAS las direcciones del host, o lanza si alguna es interna.

    getaddrinfo en lugar de gethostbyname: devuelve IPv4 e IPv6, y todas
    las direcciones en vez de la primera. Basta con que UNA sea interna
    para rechazar el destino entero; no sabemos a cual va a conectar el
    cliente HTTP.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise NoResuelve("El dominio no resuelve") from e

    direcciones = set()
    for info in infos:
        # fe80::1%eth0 -> fe80::1 ; ip_address rechaza el sufijo de zona
        direcciones.add(info[4][0].split("%")[0])

    if not direcciones:
        raise NoResuelve("El dominio no resuelve")

    for cruda in direcciones:
        if es_bloqueada(ipaddress.ip_address(cruda)):
            raise DestinoNoPermitido("Destino no permitido")

    return sorted(direcciones)


def validar_o_fallar(host: str) -> tuple[str, list[str]]:
    """Atajo: normaliza y resuelve. Devuelve (host_normalizado, ips)."""
    host = normalizar_host(host)
    return host, resolver_publica(host)


def validar_url(url: str) -> str:
    """Valida una URL entera: esquema y destino. Devuelve la URL tal cual.

    El esquema importa tanto como la direccion: un redirect hacia
    file:///etc/passwd o gopher://... no lo detiene ningun control sobre
    IPs, porque no hay resolucion DNS de por medio.
    """
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise DestinoNoPermitido(f"Esquema no permitido: {p.scheme or 'ninguno'}")
    if not p.hostname:
        raise DestinoNoPermitido("URL invalida")
    validar_o_fallar(p.hostname)
    return url


async def validar_url_async(url: str) -> str:
    """Igual que validar_url, fuera del hilo del bucle de eventos.

    getaddrinfo es bloqueante. Llamarlo directo dentro de una corrutina
    congela TODOS los runners que corren en paralelo mientras espera al
    DNS, que es justo lo que un objetivo lento puede provocar a proposito.
    """
    return await asyncio.to_thread(validar_url, url)


class ClienteSeguro(httpx.AsyncClient):
    """AsyncClient que valida el destino de cada peticion y cada redirect.

    Reemplaza a httpx.AsyncClient(follow_redirects=True). La diferencia
    esta en quien decide seguir un salto: con follow_redirects=True lo
    decide httpx, que no sabe nada de redes internas, asi que un sitio
    publico que responda 302 -> 169.254.169.254 se lleva por delante
    todos los controles anteriores. Aqui la cadena se recorre a mano y
    cada destino pasa por la misma validacion que el original.

    Los runners no cambian: httpx enruta get/post/head por request(),
    asi que basta con sobrescribir ese metodo.

    Limitacion conocida: entre validar y conectar httpx vuelve a
    resolver el nombre, asi que queda una ventana de rebinding de
    milisegundos. Cerrarla del todo exige fijar la IP con un transporte
    propio; la defensa completa es negar la salida a rangos privados a
    nivel de red (NSG en Azure).
    """

    max_redirects_seguros = 3

    async def request(self, method, url, **kwargs):
        # follow_redirects lo gestionamos nosotros: si un runner lo pasa,
        # se ignora en vez de devolverle el control a httpx.
        kwargs.pop("follow_redirects", None)
        url = str(url)

        for _ in range(self.max_redirects_seguros + 1):
            await validar_url_async(url)
            resp = await super().request(method, url,
                                         follow_redirects=False, **kwargs)

            if resp.status_code not in REDIRECCIONES:
                return resp

            destino = resp.headers.get("location")
            if not destino:
                # Redirect sin Location: no hay a donde ir.
                return resp

            # join resuelve rutas relativas ('/login') contra la URL actual.
            url = str(resp.url.join(destino))

        raise DemasiadosRedirects(
            f"Mas de {self.max_redirects_seguros} redirecciones")