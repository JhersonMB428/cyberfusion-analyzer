"""Prueba el motor contra dominios reales sin pasar por la cola ni la API.

    python -m worker.engine.cli cyberfusion.pe corevia.global
    python -m worker.engine.cli --json gtlabs.pe

Sirve para calibrar antes de la campana (seccion 6 de la especificacion).
"""
import asyncio
import json
import sys

from .core import analyze


async def main(domains, as_json):
    for d in domains:
        r = await analyze(d)
        if as_json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
            continue
        print(f"\n== {d}: {r['status']} · puntaje {r['score']} · nivel {r['level']} · "
              f"capas {r['coverage']['determined']}/{r['coverage']['total']} · "
              f"firewall {r['waf']['product'] or '-'} · {r['meta']['durationMs']} ms")
        for l in r["layers"]:
            print(f"   {l['id']:<4} {l['state']:<18} {l['note'] or ''}")
        for f in r["findings"]:
            print(f"   [{f['severity']:<6}] {f['id']:<11} {f['title']}")
        if r["meta"]["modulesFailed"]:
            print("   modulos con fallo:", r["meta"]["modulesFailed"])


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    asyncio.run(main(args, "--json" in sys.argv))
