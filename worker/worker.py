"""Consume trabajos de la cola Redis y guarda el resultado."""
import asyncio, base64, datetime, json, os, tempfile, time
from urllib.parse import urlparse
import redis
from .pipeline import scan
from .netguard import validar_o_fallar, DestinoNoPermitido, NoResuelve

# socket_timeout tiene que ser MAYOR que el timeout de blpop (30 s): si no,
# cada espera sin trabajo acaba en un TimeoutError falso. keepalive y
# health_check evitan que una conexion que Azure cerro por inactividad
# se descubra justo al ir a guardar un resultado.
r = redis.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379/0"),
    socket_timeout=45, socket_connect_timeout=10, socket_keepalive=True,
    health_check_interval=25, retry_on_timeout=True,
)
QUEUE = "scans:queue"
RETRY_S = 3
RETRY_MAX = 100   # ~5 minutos: cubre un reinicio de mantenimiento de Azure


def _redis(fn, *args, **kwargs):
    """Ejecuta una operacion de Redis reintentando mientras no responda.

    En el plan Basic de Azure, Redis se reinicia de vez en cuando por
    mantenimiento. Antes, un TimeoutError en ese momento tumbaba el worker
    (exit 1) y el escaneo que tenia en curso se perdia: la pagina se
    quedaba esperando para siempre. Ahora el trabajo se queda en memoria
    y se guarda en cuanto Redis vuelve.
    """
    for intento in range(1, RETRY_MAX + 1):
        try:
            return fn(*args, **kwargs)
        except redis.exceptions.RedisError as e:
            # ConnectionError y TimeoutError heredan de RedisError: el
            # codigo anterior solo atrapaba el primero.
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


def main():
    print("[worker] esperando trabajos...", flush=True)
    while True:
        try:
            item = r.blpop(QUEUE, timeout=30)
        except redis.exceptions.RedisError as e:
            # Redis se reinicia (mantenimiento en Azure, despliegue local).
            # Reconectar es lo normal, no un fallo: reventar aqui deja el
            # worker caido hasta que el orquestador lo levante otra vez.
            print(f"[worker] Redis no disponible, reintento en 3s: {e}",
                  flush=True)
            time.sleep(3)
            continue
        if item is None:
            continue            # timeout de blpop: no hay trabajo, seguimos
        _, raw = item
        job = json.loads(raw)
        job_id, target = job["id"], job["target"]
        deep = job.get("deep", False)

        try:
            validar_o_fallar(urlparse(target).hostname or "")
        except (DestinoNoPermitido, NoResuelve) as e:
            print(f"[worker] RECHAZADO {target}: {e}", flush=True)
            _registrar_rechazo(job_id, target, str(e))
            _redis(r.set, f"scan:{job_id}",
                   json.dumps({"status": "error", "error": str(e)}), ex=86400)
            continue

        print(f"[worker] escaneando {target}", flush=True)
        _redis(r.set, f"scan:{job_id}", json.dumps({"status": "running"}), ex=86400)
        try:
            result = asyncio.run(scan(target, deep=deep))
            payload = {"status": "done", "result": result}
            payload["report_ready"] = _render_pdf(job_id, result)
        except Exception as e:
            payload = {"status": "error", "error": str(e)}
        try:
            _redis(r.set, f"scan:{job_id}",
                   json.dumps(payload, ensure_ascii=False), ex=86400)
        except redis.exceptions.RedisError as e:
            # Redis lleva mas de 5 minutos caido: el resultado se pierde,
            # pero el worker sigue vivo para los siguientes escaneos.
            print(f"[worker] no se pudo guardar {target}: {e}", flush=True)
            continue
        print(f"[worker] listo {target}", flush=True)


if __name__ == "__main__":
    main()