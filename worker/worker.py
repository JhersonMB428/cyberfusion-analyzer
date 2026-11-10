"""Consume trabajos de la cola Redis y guarda el resultado."""
import asyncio, base64, datetime, json, os, tempfile, time
from urllib.parse import urlparse
import threading
import redis
from .engine.core import analyze
from .netguard import validar_o_fallar, DestinoNoPermitido, NoResuelve

# socket_timeout tiene que ser MAYOR que el timeout de blpop (30 s): si no,
# cada espera sin trabajo acaba en un TimeoutError falso.
r = redis.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379/0"),
    socket_timeout=45, socket_connect_timeout=10, socket_keepalive=True,
    health_check_interval=25, retry_on_timeout=True,
)
QUEUE = "scans:queue"
RETRY_S = 3
RETRY_MAX = 100   # ~5 minutos: cubre un reinicio de mantenimiento de Azure
# Analisis simultaneos por replica. El motor es casi todo espera de red,
# pero el PDF (WeasyPrint) es CPU: se renderiza de uno en uno.
CONCURRENCY = max(1, int(os.getenv("WORKER_CONCURRENCY", "2")))
_pdf_lock = threading.Lock()


def _redis(fn, *args, **kwargs):
    """Ejecuta una operacion de Redis reintentando mientras no responda
    (Redis Basic de Azure se reinicia por mantenimiento)."""
    for intento in range(1, RETRY_MAX + 1):
        try:
            return fn(*args, **kwargs)
        except redis.exceptions.RedisError as e:
            if intento == RETRY_MAX:
                raise
            print(f"[worker] Redis no responde ({type(e).__name__}), "
                  f"reintento {intento} en {RETRY_S}s", flush=True)
            time.sleep(RETRY_S)


def _render_pdf(job_id: str, result: dict) -> bool:
    """Genera el PDF y lo deja en Redis junto al resultado.

    Va aqui y no en la API porque renderizar es trabajo pesado y la API
    debe responder rapido. Si falla, el escaneo sigue siendo valido: el
    informe es un formato de salida, no el dato.
    """
    try:
        from report.render import render
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as fh:
            path = fh.name
        with _pdf_lock:
            render(result, path, "es")
        with open(path, "rb") as fh:
            _redis(r.set, f"pdf:{job_id}", base64.b64encode(fh.read()), ex=86400)
        os.unlink(path)
        return True
    except Exception as e:
        print(f"[worker] PDF fallido: {type(e).__name__}: {e}", flush=True)
        return False


def _registrar_rechazo(job_id: str, target: str, motivo: str) -> None:
    """Deja rastro de un destino rechazado en el segundo control.

    Si la API acepto la URL y aqui la rechazamos, no es un usuario
    despistado: o el DNS del objetivo cambio en el tiempo de cola, o
    alguien esta intentando rebinding. Es exactamente el evento que
    querriamos poder mostrar si algun dia hay una revision, y en un
    print se pierde con la rotacion de logs.
    """
    try:
        r.rpush("audit:rechazos", json.dumps({
            "at": datetime.datetime.now(datetime.timezone.utc)
                  .isoformat(timespec="seconds"),
            "job_id": job_id, "target": target, "motivo": motivo,
        }, ensure_ascii=False))
        r.ltrim("audit:rechazos", -5000, -1)
    except Exception as e:
        print(f"[worker] no se pudo registrar el rechazo: {e}", flush=True)


def _next_job():
    """Espera el siguiente trabajo de la cola. None si no hubo en 30 s."""
    try:
        return r.blpop(QUEUE, timeout=30)
    except redis.exceptions.RedisError as e:
        # Redis se reinicia (mantenimiento en Azure, despliegue local).
        # Reconectar es lo normal, no un fallo.
        print(f"[worker] Redis no disponible, reintento en 3s: {e}", flush=True)
        time.sleep(3)
        return None


def _save(job_id: str, payload: dict, target: str) -> None:
    try:
        _redis(r.set, f"scan:{job_id}",
               json.dumps(payload, ensure_ascii=False), ex=86400)
        print(f"[worker] listo {target} ({payload.get('result', {}).get('status', payload.get('status'))})",
              flush=True)
    except redis.exceptions.RedisError as e:
        # Redis lleva mas de 5 minutos caido: el resultado se pierde,
        # pero el worker sigue vivo para los siguientes escaneos.
        print(f"[worker] no se pudo guardar {target}: {e}", flush=True)


def _save_summary(job_id: str, payload: dict) -> None:
    """Resumen sin datos del sitio (solo puntaje y nivel) para el panel de
    webs analizadas. Dura mas que el resultado completo (24 h)."""
    res = payload.get("result") or {}
    cov = res.get("coverage") or {}
    summ = {"score": res.get("score"), "level": res.get("level"),
            "status": res.get("status") or payload.get("status"),
            "coverage": f"{cov.get('determined', '')}/{cov.get('total', '')}" if cov else "",
            "waf": (res.get("waf") or {}).get("product")}
    try:
        _redis(r.set, f"scansum:{job_id}", json.dumps(summ), ex=400 * 86400)
    except redis.exceptions.RedisError:
        pass


async def _handle(raw: bytes, sem: asyncio.Semaphore) -> None:
    try:
        job = json.loads(raw)
        job_id, target = job["id"], job["target"]
        host = urlparse(target).hostname or ""
        try:
            await asyncio.to_thread(validar_o_fallar, host)
        except (DestinoNoPermitido, NoResuelve) as e:
            print(f"[worker] RECHAZADO {target}: {e}", flush=True)
            _registrar_rechazo(job_id, target, str(e))
            await asyncio.to_thread(_save, job_id, {"status": "error", "error": str(e)}, target)
            return

        print(f"[worker] escaneando {target}", flush=True)
        await asyncio.to_thread(_redis, r.set, f"scan:{job_id}",
                                json.dumps({"status": "running"}), ex=86400)
        try:
            result = await analyze(host)
            payload = {"status": "done", "result": result}
            if result.get("status") != "error":
                payload["report_ready"] = await asyncio.to_thread(_render_pdf, job_id, result)
        except Exception as e:
            print(f"[worker] fallo analizando {target}: {type(e).__name__}: {e}", flush=True)
            payload = {"status": "error", "error": "No pudimos completar el análisis."}
        await asyncio.to_thread(_save, job_id, payload, target)
        await asyncio.to_thread(_save_summary, job_id, payload)
    except Exception as e:
        print(f"[worker] trabajo invalido: {type(e).__name__}: {e}", flush=True)
    finally:
        sem.release()


async def _main_async():
    print(f"[worker] esperando trabajos (hasta {CONCURRENCY} a la vez)...", flush=True)
    sem = asyncio.Semaphore(CONCURRENCY)
    while True:
        await sem.acquire()
        item = await asyncio.to_thread(_next_job)
        if item is None:
            sem.release()
            continue
        asyncio.create_task(_handle(item[1], sem))


def main():
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()