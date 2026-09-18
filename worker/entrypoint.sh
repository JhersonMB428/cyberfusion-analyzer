#!/bin/sh
# Asegura que haya plantillas de nuclei antes de arrancar el worker.
#
# Las plantillas ya NO viven dentro de la imagen. Cambian a diario, asi
# que hornearlas significaba o reconstruir cada semana solo por eso, o
# escanear con plantillas viejas sin enterarse. Fuera de la imagen se
# actualizan solas y la imagen deja de cambiar por motivos ajenos al codigo.
#
# En local, el volumen de docker-compose las conserva entre reinicios.
# En Azure, un Azure Files compartido entre replicas del worker.
set -e

DIR="${NUCLEI_TEMPLATES:-/opt/nuclei-templates}"
mkdir -p "$DIR"

if [ -z "$(ls -A "$DIR" 2>/dev/null)" ]; then
    echo "[entrypoint] $DIR vacio: descargando plantillas de nuclei..."
    # -silent para no llenar los logs con miles de lineas de descarga.
    if nuclei -update-templates -update-template-dir "$DIR" -silent; 
    then        
        echo "[entrypoint] plantillas listas"
    else
        # No abortamos: sin plantillas el escaneo pasivo sigue funcionando
        # entero, y solo se degrada la pasada de nuclei del modo profundo.
        # Caerse aqui dejaria el servicio sin escanear NADA por un fallo
        # que solo afecta a una parte.
        echo "[entrypoint] AVISO: no se pudieron descargar plantillas." >&2
        echo "[entrypoint] El escaneo profundo dara resultados vacios." >&2
    fi
else
    echo "[entrypoint] plantillas encontradas en $DIR"
fi

exec "$@"