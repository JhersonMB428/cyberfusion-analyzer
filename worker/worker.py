"""Consume trabajos de la cola Redis y guarda el resultado."""
import asyncio, base64, datetime, json, os, tempfile, time
from urllib.parse import urlparse
import redis
from .pipeline import scan
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


def main():
    print("[worker] esperando trabajos...", flush=True)
    while True:
        try:
            item = r.blpop(QUEUE, timeout=30)
        except redis.exceptions.ConnectionError as e:
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
            r.set(f"scan:{job_id}",
                  json.dumps({"status": "error", "error": str(e)}), ex=86400)
            continue

        print(f"[worker] escaneando {target}", flush=True)
        r.set(f"scan:{job_id}", json.dumps({"status": "running"}), ex=86400)
        try:
            result = asyncio.run(scan(target, deep=deep))
            payload = {"status": "done", "result": result}
            payload["report_ready"] = _render_pdf(job_id, result)
        except Exception as e:
            payload = {"status": "error", "error": str(e)}
        r.set(f"scan:{job_id}", json.dumps(payload, ensure_ascii=False), ex=86400)
        print(f"[worker] listo {target}", flush=True)


if __name__ == "__main__":
    main()