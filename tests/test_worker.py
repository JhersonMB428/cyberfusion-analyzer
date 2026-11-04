"""El worker arranca, toma un trabajo de la cola, analiza y deja el PDF.

Esta prueba existe porque la 0.15.0 se desplego con nombres sin definir
(CONCURRENCY, _redis) y el worker se caia al arrancar.
"""
import asyncio
import json

import fakeredis

from worker import worker as W
from tests import test_engine as T


def test_worker_procesa_un_trabajo(monkeypatch):
    fake = fakeredis.FakeRedis()
    monkeypatch.setattr(W, "r", fake)
    monkeypatch.setattr(W, "validar_o_fallar", lambda h: None)
    T.install(monkeypatch, T.BASE_DNS, {"https://empresa.com/": (200, "<html>ok</html>", T.SECURE_HEADERS)})
    fake.rpush(W.QUEUE, json.dumps({"id": "abc123", "target": "https://empresa.com", "deep": False}))

    async def una_vuelta():
        sem = asyncio.Semaphore(W.CONCURRENCY)
        await sem.acquire()
        item = W._next_job()
        await W._handle(item[1], sem)
    asyncio.run(una_vuelta())

    out = json.loads(fake.get("scan:abc123"))
    assert out["status"] == "done"
    assert out["result"]["coverage"]["total"] == 10
    assert len(out["result"]["layers"]) == 10
    assert out["report_ready"] is True and fake.get("pdf:abc123")
