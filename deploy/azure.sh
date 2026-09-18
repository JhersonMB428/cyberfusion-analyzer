#!/usr/bin/env bash
# Despliegue de Cyberfusion Analyzer en Azure Container Apps.
#
# Por que Container Apps y no AKS: el worker escala a cero cuando nadie
# escanea. Con creditos de patrocinio eso es la diferencia entre que
# duren meses o anos.
#
# Ejecutar desde Azure Cloud Shell (bash) o con az cli instalado.
#
# ANTES DE EJECUTAR: exportar los secretos, o el script se detiene.
#   export VERIFY_SECRET=...  LEADS_TOKEN=...  SMTP_PASS=...
#   export TURNSTILE_SITE_KEY=...  TURNSTILE_SECRET=...
#   export SALES_EMAIL=...
set -euo pipefail

# ---------------------------------------------------------------- ajustes
RG=rg-cyberfusion-analyzer
LOC=eastus                      # region con creditos disponibles
ENVNAME=cae-analyzer
ACR=acrcyberfusion$RANDOM       # debe ser unico en todo Azure
APP_API=analyzer-api
APP_WORKER=analyzer-worker
REDIS=redis-analyzer-cf
VNET=vnet-analyzer
NATGW=natgw-analyzer
EGRESS_IP=pip-analyzer-egress   # LA IP que los clientes pondran en lista blanca
STORAGE=stcyberfusion$RANDOM    # debe ser unico en todo Azure, solo minusculas
SHARE=leads
ENVSTORAGE=leadsstore           # nombre del storage DENTRO del entorno
ORIGENES_WEB="https://cyberfusion.pe,https://www.cyberfusion.pe,https://analyzer.cyberfusion.pe"

# Fallar temprano y con un mensaje claro es mejor que desplegar una API
# sin captcha y descubrirlo con la factura de trafico automatizado.
: "${VERIFY_SECRET:?exporta VERIFY_SECRET antes de ejecutar}"
: "${LEADS_TOKEN:?exporta LEADS_TOKEN antes de ejecutar}"
: "${SMTP_PASS:?exporta SMTP_PASS antes de ejecutar}"
: "${TURNSTILE_SITE_KEY:?exporta TURNSTILE_SITE_KEY antes de ejecutar}"
: "${TURNSTILE_SECRET:?exporta TURNSTILE_SECRET antes de ejecutar}"
: "${SALES_EMAIL:?exporta SALES_EMAIL antes de ejecutar}"

az group create -n $RG -l $LOC

# ------------------------------------------------- red con IP de salida fija
# Sin esto, la IP de salida cambia sola y ningun cliente puede ponerte en
# lista blanca en su Cloudflare o su Imunify360.
az network vnet create -g $RG -n $VNET --address-prefix 10.20.0.0/16 \
  --subnet-name snet-apps --subnet-prefix 10.20.0.0/23

az network public-ip create -g $RG -n $EGRESS_IP --sku Standard --allocation-method Static
az network nat gateway create -g $RG -n $NATGW --public-ip-addresses $EGRESS_IP \
  --idle-timeout 10
az network vnet subnet update -g $RG --vnet-name $VNET -n snet-apps --nat-gateway $NATGW

SUBNET_ID=$(az network vnet subnet show -g $RG --vnet-name $VNET -n snet-apps --query id -o tsv)

echo ">>> IP DE SALIDA (documentar en cyberfusion.pe/scanner):"
az network public-ip show -g $RG -n $EGRESS_IP --query ipAddress -o tsv

# ------------------------------------------------------------------ registro
az acr create -g $RG -n $ACR --sku Basic --admin-enabled true
az acr build -r $ACR -t analyzer-api:latest  -f api/Dockerfile    ./api
az acr build -r $ACR -t analyzer-worker:latest -f worker/Dockerfile .

ACR_SERVER=$(az acr show -n $ACR --query loginServer -o tsv)
ACR_PASS=$(az acr credential show -n $ACR --query "passwords[0].value" -o tsv)

# --------------------------------------------------------------------- redis
# OJO con el tier Basic: un solo nodo, sin replica, SIN PERSISTENCIA y sin
# SLA. Azure lo reinicia para parchear y al volver esta vacio. Se pierden
# las verificaciones de dominio (el cliente tiene que volver a poner el
# TXT) y los leads que aun esten solo en Redis. Por eso los leads se
# escriben TAMBIEN al recurso compartido de mas abajo, y por eso el aviso
# por correo a comercial deja de ser un lujo: esa copia vive fuera de
# Azure. Cuando haya presupuesto, Standard (replica) o Premium (persistencia).
az redis create -g $RG -n $REDIS -l $LOC --sku Basic --vm-size c0
REDIS_HOST=$(az redis show -g $RG -n $REDIS --query hostName -o tsv)
REDIS_KEY=$(az redis list-keys -g $RG -n $REDIS --query primaryKey -o tsv)
REDIS_URL="rediss://:${REDIS_KEY}@${REDIS_HOST}:6380/0"

# ------------------------------------------------ almacenamiento persistente
# El disco de un contenedor en Azure es efimero: lo que escriba en /data
# desaparece en cada reinicio o despliegue. Los leads son el objetivo
# entero de la campana gratuita, asi que necesitan vivir fuera del
# contenedor. Azure Files se monta como una carpeta normal, asi que el
# codigo no cambia: LEADS_PATH ya apunta a /data/leads.jsonl.
az storage account create -g $RG -n $STORAGE -l $LOC \
  --sku Standard_LRS --kind StorageV2

STORAGE_KEY=$(az storage account keys list -g $RG -n $STORAGE --query "[0].value" -o tsv)

az storage share-rm create -g $RG --storage-account $STORAGE -n $SHARE --quota 5

# Registra el recurso compartido en el ENTORNO. Todavia no lo monta en
# ninguna app: eso es el paso del YAML de mas abajo.
az containerapp env storage set -g $RG -n $ENVNAME --storage-name $ENVSTORAGE \
  --azure-file-account-name $STORAGE \
  --azure-file-account-key "$STORAGE_KEY" \
  --azure-file-share-name $SHARE \
  --access-mode ReadWrite

# ----------------------------------------------------------------- entorno
az containerapp env create -g $RG -n $ENVNAME -l $LOC \
  --infrastructure-subnet-resource-id "$SUBNET_ID"

# --------------------------------------------------------------------- API
# min-replicas 1: la landing no puede tener arranque en frio.
#
# max-replicas 1 a proposito, no por falta de ambicion: los leads se
# escriben con 'append' sobre un archivo en SMB, y dos replicas
# escribiendo a la vez pueden entrelazar lineas y dejar el JSONL
# corrupto. Cuando el volumen justifique escalar, el paso siguiente es
# mover los leads a Azure Table Storage y entonces subir este numero.
#
# TRUST_PROXY=1 es obligatorio aqui: detras del ingress de Container Apps
# request.client.host es SIEMPRE la IP del ingress. Sin esto, el limite
# de escaneos por IP se comparte entre todos los visitantes del mundo:
# cinco al dia en total, no cinco por persona.
az containerapp create -g $RG -n $APP_API --environment $ENVNAME \
  --image $ACR_SERVER/analyzer-api:latest \
  --registry-server $ACR_SERVER --registry-username $ACR --registry-password "$ACR_PASS" \
  --target-port 8000 --ingress external \
  --min-replicas 1 --max-replicas 1 \
  --cpu 0.5 --memory 1Gi \
  --secrets redis-url="$REDIS_URL" \
            verify-secret="$VERIFY_SECRET" \
            leads-token="$LEADS_TOKEN" \
            smtp-pass="$SMTP_PASS" \
            turnstile-secret="$TURNSTILE_SECRET" \
  --env-vars REDIS_URL=secretref:redis-url \
             VERIFY_SECRET=secretref:verify-secret \
             LEADS_TOKEN=secretref:leads-token \
             SMTP_PASS=secretref:smtp-pass \
             TURNSTILE_SECRET=secretref:turnstile-secret \
             TURNSTILE_SITE_KEY="$TURNSTILE_SITE_KEY" \
             SALES_EMAIL="$SALES_EMAIL" \
             LEADS_PATH=/data/leads.jsonl \
             ALLOWED_ORIGINS="$ORIGENES_WEB" \
             TRUST_PROXY=1 \
             SCANS_PER_IP_PER_DAY=5 \
             SMTP_HOST=mail.cyberfusion.pe \
             SMTP_PORT=465 \
             SMTP_USER=scanner@cyberfusion.pe \
             SMTP_FROM=scanner@cyberfusion.pe
  # NO definir ALLOW_UNVERIFIED_DEEP aqui. Ausente = escaneo profundo
  # rechazado con 403, que es lo correcto hasta que exista verificacion.
  # NO definir OPEN_REPORTS aqui: ausente = el PDF exige correo, que es
  # el mecanismo entero de captacion.

# ------------------------------------------- montar el volumen en la API
# Los volumenes no se pueden anadir con banderas sueltas de
# 'az containerapp update': hay que pasar por el YAML completo. Se
# exporta la definicion, se le inyectan volumes/volumeMounts y se
# vuelve a aplicar.
TMP_YAML=$(mktemp /tmp/analyzer-api-XXXX.yaml)
az containerapp show -g $RG -n $APP_API -o yaml > "$TMP_YAML"

python3 - "$TMP_YAML" "$ENVSTORAGE" <<'PY'
import sys, yaml

ruta, nombre_storage = sys.argv[1], sys.argv[2]
with open(ruta) as fh:
    app = yaml.safe_load(fh)

plantilla = app["properties"]["template"]

plantilla["volumes"] = [{
    "name": "leads-vol",
    "storageType": "AzureFile",
    "storageName": nombre_storage,
}]

for contenedor in plantilla["containers"]:
    contenedor["volumeMounts"] = [{
        "volumeName": "leads-vol",
        "mountPath": "/data",
    }]

with open(ruta, "w") as fh:
    yaml.safe_dump(app, fh, sort_keys=False)
print(f"YAML preparado con el volumen montado en /data: {ruta}")
PY

az containerapp update -g $RG -n $APP_API --yaml "$TMP_YAML"
rm -f "$TMP_YAML"

# ------------------------------------------------------------------ worker
# App normal, no job: worker.py es un bucle infinito con blpop, y un job
# espera que el proceso termine. Como app, el bucle es exactamente lo que
# se quiere, y KEDA levanta y apaga replicas segun la cola.
#
# min-replicas 0: sin escaneos en marcha no se paga nada. El arranque en
# frio anade unos segundos al primer escaneo, que es invisible para el
# usuario porque la pagina ya muestra "analizando".
#
# REDIS_URL si o si: sin esta variable el contenedor cae al valor por
# defecto 'redis://redis:6379/0', que en Azure no existe.
az containerapp create -g $RG -n $APP_WORKER --environment $ENVNAME \
  --image $ACR_SERVER/analyzer-worker:latest \
  --registry-server $ACR_SERVER --registry-username $ACR --registry-password "$ACR_PASS" \
  --min-replicas 0 --max-replicas 10 \
  --cpu 1 --memory 2Gi \
  --secrets redis-conn="${REDIS_HOST}:6380,password=${REDIS_KEY},ssl=True" \
            redis-url="$REDIS_URL" \
  --env-vars REDIS_URL=secretref:redis-url \
             NUCLEI_TIMEOUT=600 \
             NUCLEI_TEMPLATES=/opt/nuclei-templates \
  --scale-rule-name queue --scale-rule-type redis \
  --scale-rule-metadata listName=scans:queue listLength=1 \
      address="${REDIS_HOST}:6380" enableTLS=true \
  --scale-rule-auth password=redis-conn

# --------------------------------- margen para que no lo maten escaneando
# blpop saca el trabajo de la cola al EMPEZAR, no al terminar. Asi que
# mientras el worker escanea, la cola esta vacia y KEDA cree que sobra.
# Con el cooldown por defecto (300s) un deep scan de hasta 600s se queda
# a medias. 900s da margen sobre NUCLEI_TIMEOUT mas el renderizado del PDF.
TMP_W=$(mktemp /tmp/analyzer-worker-XXXX.yaml)
az containerapp show -g $RG -n $APP_WORKER -o yaml > "$TMP_W"

python3 - "$TMP_W" <<'PY'
import sys, yaml

ruta = sys.argv[1]
with open(ruta) as fh:
    app = yaml.safe_load(fh)

escala = app["properties"]["template"].setdefault("scale", {})
escala["cooldownPeriod"] = 900
escala["pollingInterval"] = 15

with open(ruta, "w") as fh:
    yaml.safe_dump(app, fh, sort_keys=False)
print("cooldownPeriod=900s aplicado al worker")
PY

az containerapp update -g $RG -n $APP_WORKER --yaml "$TMP_W"
rm -f "$TMP_W"

API_FQDN=$(az containerapp show -g $RG -n $APP_API \
  --query properties.configuration.ingress.fqdn -o tsv)

# PUBLIC_API_URL se usa para construir el enlace de descarga que va en el
# correo al cliente. Solo se conoce despues de crear la app, asi que se
# aplica ahora. Cuando analyzer.cyberfusion.pe apunte aqui, cambiarlo por
# el dominio propio: un enlace a *.azurecontainerapps.io en un correo
# comercial no inspira la confianza que el informe necesita.
az containerapp update -g $RG -n $APP_API \
  --set-env-vars PUBLIC_API_URL="https://${API_FQDN}"

echo
echo ">>> URL de la API: https://${API_FQDN}"
echo ">>> Recurso compartido de leads: $STORAGE/$SHARE"
echo
echo "Comprobar el montaje antes de dar por bueno el despliegue:"
echo "  az containerapp exec -g $RG -n $APP_API --command 'sh -c \"touch /data/prueba && ls -la /data\"'"
echo
echo "Siguiente paso: apuntar analyzer.cyberfusion.pe a ese FQDN y"
echo "ejecutar 'az containerapp hostname add' para el certificado gestionado."