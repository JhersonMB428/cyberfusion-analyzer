"""Motor 0.15 · orquesta los modulos y arma el contrato de salida (seccion 3).

Diferencia deliberada con la especificacion: por decision de direccion, el
puntaje se emite tambien en estado "blocked", calculado solo sobre las
capas que se pudieron analizar. La interfaz y el PDF lo presentan siempre
junto a la cobertura ("calculado sobre 5 de 10 capas"), y el firewall que
bloqueo cuenta como acierto, nunca como penalizacion.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from . import m1_tls, m2_dns, m3_m6_http, m7_m9_external
from .common import LAYERS, LAYER_NAME, REASON_NOTE, ModuleResult, adns, registrable

ENGINE_VERSION = "0.15.0"
SCHEMA_VERSION = "1.0"
BUDGET_S = 60

PENALTY = {"alto": 15, "medio": 8, "bajo": 3, "observ": 0}
LAYER_CAP = 30
HALF = {"F-SURF-003", "F-SURF-004"}          # fuentes publicas sin validar
FORCE_HIGH = {"F-REP-001", "F-REP-002", "F-FILE-001"}
SEV_ORDER = {"alto": 0, "medio": 1, "bajo": 2, "observ": 3}
EFF_ORDER = {"bajo": 0, "medio": 1, "alto": 2}
COMPLETE_AT = 7


def score_of(findings: list[dict]) -> int:
    per_layer: dict[str, float] = {}
    for f in findings:
        p = PENALTY[f["severity"]] * (0.5 if f["id"] in HALF else 1)
        per_layer[f["layerId"]] = per_layer.get(f["layerId"], 0) + p
    total = sum(min(v, LAYER_CAP) for v in per_layer.values())
    return max(0, round(100 - total))


def level_of(score: int, findings: list[dict]) -> str:
    lvl = "bajo" if score >= 80 else "medio" if score >= 55 else "alto"
    ids = {f["id"] for f in findings}
    if ids & FORCE_HIGH:
        return "alto"
    if lvl == "bajo" and any(f["severity"] == "alto" for f in findings):
        return "medio"
    return lvl


async def _guard(name: str, coro, layer_ids: list[str], failed: list[str], timeout: float):
    """Ningun modulo tumba el analisis: excepcion o tiempo = capa no determinada."""
    try:
        return await asyncio.wait_for(coro, timeout)
    except asyncio.TimeoutError:
        failed.append(name)
        return {L: ModuleResult(L).undetermined("timeout") for L in layer_ids}
    except Exception as e:
        print(f"[engine] modulo {name} fallo: {type(e).__name__}: {e}", flush=True)
        failed.append(name)
        return {L: ModuleResult(L).undetermined("source_unavailable" if L in ("L8", "L9", "L10") else "http_error")
                for L in layer_ids}


async def analyze(host: str) -> dict:
    t0 = time.monotonic()
    host = host.strip().lower().rstrip(".")
    domain = registrable(host)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    base = {"schemaVersion": SCHEMA_VERSION, "engineVersion": ENGINE_VERSION,
            "domain": host, "target": f"https://{host}", "analyzedAt": now,
            "cached": False}

    # Estado error: el dominio no resuelve. Se decide en segundos.
    a = await adns(host, "A") or await adns(host, "AAAA")
    if not a and not await adns(domain, "NS"):
        return {**base, "status": "error", "score": None, "level": None,
                "coverage": {"determined": 0, "total": len(LAYERS)},
                "waf": {"detected": False, "product": None}, "layers": [],
                "positives": [], "findings": [],
                "error": {"code": "dns_error", "message": REASON_NOTE["dns_error"]},
                "meta": {"durationMs": int((time.monotonic() - t0) * 1000),
                         "scope": "passive", "modulesFailed": []}}

    failed: list[str] = []
    one = lambda L: (lambda r: {L: r})                       # noqa: E731

    async def wrap(coro, L):
        return one(L)(await coro)

    tasks = [
        _guard("M1", wrap(m1_tls.run(host), "L1"), ["L1"], failed, 40),
        _guard("M2", wrap(m2_dns.run(domain), "L2"), ["L2"], failed, 30),
        _guard("M3-M6", m3_m6_http.run(domain, host), ["L3", "L4", "L5", "L6"], failed, BUDGET_S - 5),
        _guard("M7", wrap(m7_m9_external.reputation(domain), "L8"), ["L8"], failed, 30),
        _guard("M8", wrap(m7_m9_external.domain_brand(domain), "L9"), ["L9"], failed, 45),
        _guard("M9", wrap(m7_m9_external.surface(domain), "L10"), ["L10"], failed, 40),
    ]
    results = await asyncio.gather(*tasks)

    layers: dict[str, ModuleResult] = {}
    waf = {"detected": False, "product": None}
    for r in results:
        if "layers" in r:                    # M3-M6
            layers.update(r["layers"])
            waf = r.get("waf", waf)
        else:
            layers.update(r)
    l7 = ModuleResult("L7")
    l7.state, l7.reason, l7.note = "needs_verification", "needs_verification", REASON_NOTE["needs_verification"]
    layers["L7"] = l7

    findings = [f for L, _ in LAYERS for f in layers[L].findings]
    positives = [p for L, _ in LAYERS for p in layers[L].positives]
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], EFF_ORDER.get(f["effort"], 1)))

    determined = sum(1 for L, _ in LAYERS if layers[L].state in ("ok", "attention"))
    status = "complete" if determined >= COMPLETE_AT else "blocked"
    score = score_of(findings) if determined else None
    level = level_of(score, findings) if score is not None else None

    return {**base, "status": status, "score": score, "level": level,
            "coverage": {"determined": determined, "total": len(LAYERS)},
            "waf": waf,
            "layers": [{"id": L, "name": LAYER_NAME[L], "state": layers[L].state,
                        "reason": layers[L].reason,
                        "note": layers[L].note or (REASON_NOTE.get(layers[L].reason) if layers[L].reason else None)}
                       for L, _ in LAYERS],
            "positives": positives, "findings": findings,
            "meta": {"durationMs": int((time.monotonic() - t0) * 1000),
                     "scope": "passive", "modulesFailed": failed}}
