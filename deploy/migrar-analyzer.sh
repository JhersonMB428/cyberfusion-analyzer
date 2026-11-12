#!/usr/bin/env bash
# Traslada el analizador de la suscripcion vieja (Patrocinio, hoy pago por
# uso) a la MCPP Subscription, la de los creditos del Partner Program.
#
# El entorno con red propia y el NAT Gateway no se pueden mover entre
# suscripciones, asi que se RECREAN. Redis y el almacenamiento de los leads
# si se mueven: conservan nombre, claves y datos, y el analizador viejo
# sigue funcionando con ellos mientras dura el cambio.
#
# Ejecutar en Azure Cloud Shell (bash), desde la carpeta del repositorio,
# una fase a la vez y revisando la salida antes de seguir:
#
#   bash deploy/migrar-analyzer.sh fase1   # mueve Redis y el almacenamiento (sin corte)
#   bash deploy/migrar-analyzer.sh fase2   # crea red, IP fija, entorno y apps nuevas (sin corte)
#   bash deploy/migrar-analyzer.sh fase3   # muestra los cambios de DNS para el dominio de la API
#   bash deploy/migrar-analyzer.sh fase4   # enlaza el dominio de la API y su certificado a la API nueva
#   bash deploy/migrar-analyzer.sh fase5   # apaga y borra lo viejo (solo cuando todo funcione)
set -euo pipefail
set +H

SRC=7401a050-63dc-431e-935b-d8bf6d6452d2      # Patrocinio de Microsoft Azure (pago por uso)
DST=3c583f4d-e7f0-47d5-82c6-ff6d6e1dc2ae      # MCPP Subscription (creditos)
RG=growvia-app-rg
# Region del entorno nuevo. La suscripcion nueva solo admite 1 entorno de
# Container Apps por region y East US ya tiene el de Growvia: por eso eastus2.
# Redis y el almacenamiento se quedan en eastus; la latencia entre ambas es minima.
LOC=${LOC:-eastus2}
ENVNAME=cae-analyzer
VNET=vnet-analyzer
NATGW=natgw-analyzer
PIP=pip-analyzer-egress
REDIS=redis-analyzer-cf
STORAGE=stcyberfusion26891
SHARE=leads
ENVSTORAGE=leadsstore
APPS="analyzer-api analyzer-worker"
# El analizador es de cyberfusion.global: la API pasa a api.cyberfusion.global.
DOMINIO=${DOMINIO:-api.cyberfusion.global}
WORK=${WORK:-$HOME/migracion-analyzer}
mkdir -p "$WORK"

paso() { echo; echo "=== $*"; }

fase1() {
  paso "Validando el traslado de Redis y del almacenamiento de leads"
  IDS=$(az resource list -g $RG --subscription $SRC -o json \
        | jq -r --arg r "$REDIS" --arg s "$STORAGE" '.[] | select(.name==$r or .name==$s) | .id')
  [ "$(echo "$IDS" | grep -c .)" = 2 ] || { echo "No encontre $REDIS y $STORAGE en la suscripcion vieja"; exit 1; }
  BODY=$(echo "$IDS" | jq -R . | jq -s --arg t "/subscriptions/$DST/resourceGroups/$RG" '{resources:.,targetResourceGroup:$t}')
  az resource invoke-action --action validateMoveResources \
     --ids "/subscriptions/$SRC/resourceGroups/$RG" --request-body "$BODY" >/dev/null
  echo "Validacion OK"

  paso "Moviendo (5-20 min). El analizador sigue funcionando: nombres y claves no cambian."
  az resource move --destination-group $RG --destination-subscription-id $DST --ids $IDS
  az redis show -n $REDIS -g $RG --subscription $DST --query "{redis:name,estado:provisioningState}" -o table
  az storage account show -n $STORAGE -g $RG --subscription $DST --query "{storage:name,estado:provisioningState}" -o table
  echo; echo "FASE 1 LISTA. Prueba un analisis en la pagina antes de seguir con la fase 2."
}

fase2() {
  paso "Guardando la configuracion actual de las apps (con secretos, en $WORK; se borra en la fase 5)"
  for a in $APPS; do
    az containerapp show -n $a -g $RG --subscription $SRC -o json > "$WORK/$a.json"
    az containerapp secret list -n $a -g $RG --subscription $SRC --show-values -o json > "$WORK/$a.secrets.json"
  done
  chmod 600 "$WORK"/*.json

  paso "Workspace de registros que usa el entorno viejo (para no perder el historial)"
  CUST=$(az containerapp env show -n $ENVNAME -g $RG --subscription $SRC \
         --query properties.appLogsConfiguration.logAnalyticsConfiguration.customerId -o tsv)
  WS=$(az monitor log-analytics workspace list --subscription $DST -o json \
       | jq -r --arg c "$CUST" '.[] | select(.customerId==$c) | .name' | head -1)
  [ -n "$WS" ] || { echo "No encontre el workspace $CUST en la suscripcion nueva"; exit 1; }
  WSKEY=$(az monitor log-analytics workspace get-shared-keys -g $RG -n $WS --subscription $DST --query primarySharedKey -o tsv)
  echo "Workspace: $WS"

  paso "Comprobando que $LOC no tenga ya un entorno (limite: 1 por region)"
  az containerapp env list --subscription $DST --query "[].{entorno:name,region:location}" -o table
  OCUPADA=$(az containerapp env list --subscription $DST -o json \
            | jq -r --arg l "$LOC" '.[] | select((.location|ascii_downcase|gsub(" ";""))==$l) | .name' | head -1)
  if [ -n "$OCUPADA" ] && [ "$OCUPADA" != "$ENVNAME" ]; then
    echo "La region $LOC ya tiene el entorno $OCUPADA. Elige otra, por ejemplo:"
    echo "  LOC=centralus bash deploy/migrar-analyzer.sh fase2"
    exit 1
  fi

  paso "Red con IP de salida fija en $LOC"
  # Restos de un intento anterior en otra region: la red debe estar en la region del entorno.
  OLDLOC=$(az network vnet show -g $RG -n $VNET --subscription $DST --query location -o tsv 2>/dev/null || true)
  if [ -n "$OLDLOC" ] && [ "$OLDLOC" != "$LOC" ]; then
    echo "Borrando la red de un intento anterior en $OLDLOC"
    az network vnet delete -g $RG -n $VNET --subscription $DST
    az network nat gateway delete -g $RG -n $NATGW --subscription $DST
    az network public-ip delete -g $RG -n $PIP --subscription $DST
  fi
  az network vnet create -g $RG -n $VNET --subscription $DST -l $LOC --address-prefix 10.20.0.0/16 \
     --subnet-name snet-apps --subnet-prefix 10.20.0.0/23 -o none
  az network public-ip create -g $RG -n $PIP --subscription $DST -l $LOC --sku Standard --allocation-method Static -o none
  az network nat gateway create -g $RG -n $NATGW --subscription $DST -l $LOC --public-ip-addresses $PIP --idle-timeout 10 -o none
  # Los entornos actuales exigen la subred delegada a Container Apps.
  az network vnet subnet update -g $RG --vnet-name $VNET -n snet-apps --subscription $DST \
     --nat-gateway $NATGW --delegations Microsoft.App/environments -o none
  SUBNET_ID=$(az network vnet subnet show -g $RG --vnet-name $VNET -n snet-apps --subscription $DST --query id -o tsv)
  NUEVA_IP=$(az network public-ip show -g $RG -n $PIP --subscription $DST --query ipAddress -o tsv)
  echo "$NUEVA_IP" > "$WORK/ip-nueva.txt"

  paso "Entorno de Container Apps (5-15 min)"
  az containerapp env create -g $RG -n $ENVNAME --subscription $DST -l $LOC \
     --infrastructure-subnet-resource-id "$SUBNET_ID" \
     --logs-workspace-id "$CUST" --logs-workspace-key "$WSKEY" -o none
  ENV_ID=$(az containerapp env show -g $RG -n $ENVNAME --subscription $DST --query id -o tsv)
  # Los entornos nuevos usan perfiles de carga: las apps van al perfil "Consumption".
  WPN=$(az containerapp env show -g $RG -n $ENVNAME --subscription $DST \
        --query "length(properties.workloadProfiles || \`[]\`)" -o tsv)
  [ "${WPN:-0}" -gt 0 ] && WPROFILE=Consumption || WPROFILE=""

  paso "Montaje de la carpeta de leads"
  SKEY=$(az storage account keys list -g $RG -n $STORAGE --subscription $DST --query "[0].value" -o tsv)
  az containerapp env storage set -g $RG -n $ENVNAME --subscription $DST --storage-name $ENVSTORAGE \
     --azure-file-account-name $STORAGE --azure-file-account-key "$SKEY" \
     --azure-file-share-name $SHARE --access-mode ReadWrite -o none

  for a in $APPS; do
    paso "Creando $a en el entorno nuevo"
    python3 - "$WORK/$a.json" "$WORK/$a.secrets.json" "$ENV_ID" "$WORK/$a.yaml" "$WPROFILE" "$LOC" <<'PY'
import json, sys, yaml
app_p, sec_p, env_id, out, wprofile, loc = sys.argv[1:]
app = json.load(open(app_p))
secrets = json.load(open(sec_p))
p = app["properties"]
conf = p["configuration"]
conf["secrets"] = [{"name": s["name"], "value": s["value"]} for s in secrets]
for reg in conf.get("registries") or []:
    if not reg.get("identity"):
        reg.pop("identity", None)
ing = conf.get("ingress")
if ing:
    for k in ("fqdn", "customDomains"):
        ing.pop(k, None)
p["template"]["revisionSuffix"] = "m1"
nuevo = {
    "location": loc,                      # la app va en la region del entorno nuevo
    "name": app["name"],
    "type": "Microsoft.App/containerApps",
    "properties": {
        "environmentId": env_id,
        "workloadProfileName": p.get("workloadProfileName") or wprofile,
        "configuration": conf,
        "template": p["template"],
    },
}
if not nuevo["properties"]["workloadProfileName"]:
    nuevo["properties"].pop("workloadProfileName")
with open(out, "w") as fh:
    yaml.safe_dump(nuevo, fh, sort_keys=False, allow_unicode=True)
print("YAML listo:", out)
PY
    chmod 600 "$WORK/$a.yaml"
    az containerapp create -n $a -g $RG --subscription $DST --yaml "$WORK/$a.yaml" -o none
  done

  paso "Estado de las apps nuevas"
  az containerapp list -g $RG --subscription $DST -o json \
    | jq -r '.[] | select(.name|startswith("analyzer")) | "\(.name)  \(.properties.runningStatus)  https://\(.properties.configuration.ingress.fqdn // "-")"'
  echo
  echo ">>> IP DE SALIDA NUEVA: $NUEVA_IP"
  echo "    (actualizar cyberfusion.global/scanner y avisar a Rumihost)"
  echo
  echo "FASE 2 LISTA. La pagina sigue usando la API vieja hasta la fase 4."
}

fase3() {
  FQDN=$(az containerapp show -n analyzer-api -g $RG --subscription $DST --query properties.configuration.ingress.fqdn -o tsv)
  VID=$(az containerapp env show -n $ENVNAME -g $RG --subscription $DST \
        --query properties.customDomainConfiguration.customDomainVerificationId -o tsv)
  paso "Prueba directa de la API nueva"
  curl -s "https://$FQDN/config" && echo
  ZONA=${DOMINIO#*.}; SUB=${DOMINIO%%.*}
  paso "Cambios de DNS en la zona de $ZONA (Zone Editor del cPanel)"
  echo "  1) TXT   asuid.$SUB   ->  $VID"
  echo "  2) CNAME $SUB         ->  $FQDN"
  echo
  echo "Haz primero el TXT. El CNAME, cuando vayas a correr la fase 4."
}

fase4() {
  paso "Enlazando $DOMINIO a la API nueva con certificado gestionado (5-20 min)"
  az containerapp hostname add -n analyzer-api -g $RG --subscription $DST --hostname $DOMINIO -o none
  az containerapp hostname bind -n analyzer-api -g $RG --subscription $DST --hostname $DOMINIO \
     --environment $ENVNAME --validation-method CNAME -o table
  # Los enlaces de descarga de los correos usan este dominio.
  az containerapp update -n analyzer-api -g $RG --subscription $DST \
     --set-env-vars PUBLIC_API_URL="https://$DOMINIO" -o none
  curl -s "https://$DOMINIO/config" && echo
  echo "FASE 4 LISTA. Prueba un analisis completo y el formulario en la pagina."
}

fase5() {
  paso "Apagando y borrando el analizador viejo en la suscripcion de pago por uso"
  echo "Esto borra: $APPS, $ENVNAME, $NATGW, $PIP y $VNET de la suscripcion vieja."
  read -r -p "Escribe BORRAR para continuar: " ok
  [ "$ok" = "BORRAR" ] || { echo "Cancelado"; exit 1; }
  for a in $APPS; do az containerapp delete -n $a -g $RG --subscription $SRC --yes; done
  az containerapp env delete -n $ENVNAME -g $RG --subscription $SRC --yes
  # Orden: la red primero (suelta el NAT), luego el NAT (suelta la IP), luego la IP.
  az network vnet delete -g $RG -n $VNET --subscription $SRC
  az network nat gateway delete -g $RG -n $NATGW --subscription $SRC
  az network public-ip delete -g $RG -n $PIP --subscription $SRC
  rm -rf "$WORK"
  paso "Lo que queda en la suscripcion vieja (deberia estar vacio)"
  az resource list --subscription $SRC --query "[].{nombre:name,tipo:type,grupo:resourceGroup}" -o table
}

case "${1:-}" in
  fase1|fase2|fase3|fase4|fase5) "$1" ;;
  *) sed -n '2,18p' "$0"; exit 1 ;;
esac
