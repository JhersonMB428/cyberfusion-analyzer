"""Consume trabajos de la cola Redis y guarda el resultado."""
import asyncio, base64, datetime, json, os, tempfile, time
from urllib.parse import urlparse
import threading
import redis
from .engine.core import analyze
from .netguard import validar_o_fallar, DestinoNoPermitido, NoResuelve

r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
QUEUE = "scans:queue"


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
            r.set(f"pdf:{job_id}", base64.b64encode(fh.read()), ex=86400)
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