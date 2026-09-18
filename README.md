# Cyberfusion Analyzer — motor de escaneo

Motor de escaneo pasivo. Recibe una URL, corre varios analizadores en
paralelo y devuelve hallazgos normalizados con puntuacion 0-100.

## Arrancar en local

    docker compose up --build

Probar:

    curl -X POST http://localhost:8000/scans \
      -H "Content-Type: application/json" \
      -d '{"url":"https://un-sitio-que-administras.com","authorized":true}'

    # devuelve {"id":"a1b2c3..."}

    curl http://localhost:8000/scans/a1b2c3...

## Probar un runner sin Docker

    pip install httpx dnspython
    python -m worker.pipeline https://un-sitio-que-administras.com

## Estructura

    api/                API publica (FastAPI). Valida, encola, consulta.
    worker/
      schema.py         Esquema normalizado de hallazgos + puntuacion
      pipeline.py       Corre todos los runners EN PARALELO
      worker.py         Bucle que consume la cola Redis
      runners/          Un archivo por analizador
    locales/            Textos por idioma (es, en, fr, pt)

## Anadir un analizador nuevo

1. Crear `worker/runners/mi_runner.py` con `async def run(target, client)`
   que devuelva una lista de `Finding`.
2. Registrarlo en `worker/runners/__init__.py`.
3. Anadir los textos en `locales/es.json`.

No hay nada mas. El resto del sistema no necesita cambios.

## Runners incluidos

| Runner | Que revisa |
|---|---|
| headers | HSTS, CSP, X-Frame-Options, fuga de version, redireccion HTTPS |
| tls | Validez del certificado, caducidad, protocolo negociado |
| dns_mail | SPF, DMARC, CAA, DNSSEC |
| exposure | .git, .env, wp-config.php.bak, phpinfo, xmlrpc |
| wordpress | Version del core, plugins, temas, enumeracion de usuarios |

## Siguientes pasos

- Anadir nuclei como runner (subprocess + parseo JSONL a `Finding`)
- Anadir wpscan con token de API para CVEs de plugins
- Plantilla HTML del informe -> PDF con Playwright o WeasyPrint
- Postgres para persistencia (ahora todo vive en Redis con TTL de 24h)
