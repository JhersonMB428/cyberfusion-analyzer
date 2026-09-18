FROM python:3.12-slim

# Version fijada a proposito. Antes se resolvia desde /releases/latest, asi
# que dos builds del mismo commit daban imagenes distintas segun el dia. Si
# nuclei cambiaba el formato JSON o el nombre de una bandera, el escaner se
# rompia en un despliegue donde no se toco una linea de codigo. Y sin version
# fija no se puede decir con que motor se genero un informe de hace meses.
#
# Actualizar es un cambio consciente de esta linea, con su commit y su prueba.
ARG NUCLEI_VERSION=3.11.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip ca-certificates \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
        && rm -rf /var/lib/apt/lists/*

# Descarga verificada contra el checksum oficial. En una herramienta de
# seguridad, meter un binario a ciegas desde internet y despues ejecutarlo
# contra los sitios de los clientes es justo lo que el producto audita.
RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    curl -fsSL -o checksums.txt \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep " nuclei_${NUCLEI_VERSION}_linux_amd64.zip\$" checksums.txt > esperado.txt; \
    mv nuclei.zip "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    sha256sum -c esperado.txt; \
    unzip -o -q "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei; \
    rm -f /tmp/nuclei_* /tmp/checksums.txt /tmp/esperado.txt; \
    nuclei -version

# Las plantillas ya NO se hornean aqui: las resuelve entrypoint.sh en el
# arranque, contra un volumen. Ver el comentario de ese archivo.
ENV NUCLEI_TEMPLATES=/opt/nuclei-templates

WORKDIR /app
COPY worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY worker/ ./worker/
COPY report/ ./report/
COPY locales/ ./locales/
COPY worker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# nuclei procesa respuestas de sitios ajenos. Si algo sale mal ahi,
# que no salga mal como root.
RUN useradd -m -u 1000 scanner \
    && mkdir -p /opt/nuclei-templates \
    && chown -R scanner:scanner /app /opt/nuclei-templates
USER scanner

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "worker.worker"]