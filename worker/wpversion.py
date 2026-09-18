"""Version actual de WordPress, consultada a la API oficial y cacheada.

Sustituye a la constante LATEST_WP_BRANCH escrita a mano. El problema de
la constante no era el valor, era el mecanismo: en cuanto sale una rama
nueva, TODO sitio actualizado empieza a reportarse como desactualizado
con severidad alta, y nadie se entera hasta que un cliente reclama. Un
informe que acusa de grave a quien hizo las cosas bien hace mas dano que
uno que se calla.

Comparamos contra la version COMPLETA, no contra la rama. Las versiones
de parche (7.1 -> 7.1.1) son precisamente las de seguridad: decir "esta
al dia" a un sitio al que le faltan doce parches es el tipo de falso
positivo tranquilizador que arruina la credibilidad del informe.
"""
import asyncio
import json
import os

import httpx
import redis.asyncio as aioredis

API_URL = "https://api.wordpress.org/core/version-check/1.7/"
CACHE_KEY = "wp:latest_version"
CACHE_TTL = 6 * 3600          # 6 horas: los releases no salen cada hora
FETCH_TIMEOUT = 8

_redis = None
_lock = asyncio.Lock()


def _cliente_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(
            os.getenv("REDIS_URL", "redis://redis:6379/0"))
    return _redis


def parse_version(v: str) -> tuple[int, ...]:
    """'7.1.1' -> (7, 1, 1). Sirve para comparar con < y >.

    Separado para poder probarlo sin red. Devuelve tupla vacia si el
    texto no es una version reconocible, y quien compare debe tratar la
    tupla vacia como 'no se': comparar contra (0,) diria que CUALQUIER
    version esta desactualizada.
    """
    partes = []
    for trozo in v.strip().split("."):
        if not trozo.isdigit():
            break
        partes.append(int(trozo))
    return tuple(partes)


async def _consultar_api() -> str | None:
    """Pide la version actual a wordpress.org. None si no se puede."""
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as c:
            r = await c.get(API_URL)
            r.raise_for_status()
            ofertas = (r.json() or {}).get("offers") or []
    except Exception as e:
        print(f"[wpversion] no se pudo consultar la API: {e}", flush=True)
        return None

    for oferta in ofertas:
        # 'upgrade' es la oferta de actualizacion al estable actual.
        # Algunas respuestas traen tambien ofertas de rama antigua.
        version = oferta.get("current") or oferta.get("version")
        if version:
            return str(version)
    return None


async def latest_version() -> str | None:
    """Version estable actual de WordPress, o None si no se pudo saber.

    None no es un fallo silencioso: quien llama DEBE abstenerse de emitir
    un veredicto de actualidad en vez de asumir que el sitio esta al dia.
    """
    r = _cliente_redis()

    try:
        cacheado = await r.get(CACHE_KEY)
        if cacheado:
            return cacheado.decode()
    except Exception as e:
        print(f"[wpversion] cache no disponible: {e}", flush=True)

    # El lock evita que diez escaneos en paralelo golpeen la API a la vez
    # cuando la cache acaba de expirar.
    async with _lock:
        try:
            cacheado = await r.get(CACHE_KEY)
            if cacheado:
                return cacheado.decode()
        except Exception:
            pass

        version = await _consultar_api()
        if version:
            try:
                await r.set(CACHE_KEY, version, ex=CACHE_TTL)
            except Exception as e:
                print(f"[wpversion] no se pudo cachear: {e}", flush=True)
        return version


def comparar(instalada: str, ultima: str) -> dict:
    """Decide el veredicto de actualidad. No emite Findings: solo juzga.

    Devuelve {'estado': ..., 'ramas_detras': int}. Estados:
      al_dia          la version instalada es la ultima
      parche_pendiente misma rama, le faltan parches (releases de seguridad)
      rama_atrasada   rama anterior a la actual
      adelantada      mas nueva que la ultima conocida (beta, RC, cache vieja)
      indeterminado   alguna de las dos no se pudo interpretar
    """
    a, b = parse_version(instalada), parse_version(ultima)
    if not a or not b:
        return {"estado": "indeterminado", "ramas_detras": 0}
    if a == b:
        return {"estado": "al_dia", "ramas_detras": 0}
    if a > b:
        # Cache vieja o el sitio corre una beta. No es para alarmar.
        return {"estado": "adelantada", "ramas_detras": 0}
    if a[:2] == b[:2]:
        return {"estado": "parche_pendiente", "ramas_detras": 0}

    # Distancia en ramas mayores/menores, aproximada: sirve para graduar
    # la severidad, no para afirmar nada preciso en el informe.
    ramas = 2 if (b[0] - a[0]) > 0 or (b[1] - a[1]) > 1 else 1
    return {"estado": "rama_atrasada", "ramas_detras": ramas}