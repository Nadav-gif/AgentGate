#!/usr/bin/env bash
#
# Deploy the AgentGate proxy to Azure Container Instances (ACI).
#
# It builds the Docker image, pushes it to an Azure Container Registry,
# and runs it as a public container. When it finishes you get a public
# URL like  http://agentgate-proxy.eastus.azurecontainer.io:8000
# that your agents (or the live-mode simulator) can send traffic to.
#
# Prerequisites:
#   - Azure CLI installed and logged in:  az login
#   - Docker installed
#
# Usage:
#   ./deploy/deploy-azure.sh
#
set -euo pipefail

# --- Configuration (edit these) ---
RESOURCE_GROUP="agentgate-rg"
LOCATION="eastus"
CONTAINER_NAME="agentgate-proxy"
DNS_LABEL="agentgate-proxy"                 # -> agentgate-proxy.eastus.azurecontainer.io
ACR_NAME="agentgateacr$RANDOM"              # ACR names must be globally unique
IMAGE_TAG="agentgate:latest"
MODE="mock"                                 # "mock" or "real"

echo "==> Creating resource group '$RESOURCE_GROUP' in '$LOCATION'..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

echo "==> Creating Azure Container Registry '$ACR_NAME'..."
az acr create --resource-group "$RESOURCE_GROUP" --name "$ACR_NAME" \
  --sku Basic --admin-enabled true --output none

LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer --output tsv)
IMAGE="$LOGIN_SERVER/$IMAGE_TAG"

echo "==> Building and pushing image to $IMAGE..."
az acr build --registry "$ACR_NAME" --image "$IMAGE_TAG" .

ACR_USER=$(az acr credential show --name "$ACR_NAME" --query username --output tsv)
ACR_PASS=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" --output tsv)

echo "==> Deploying container '$CONTAINER_NAME' to ACI..."
az container create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CONTAINER_NAME" \
  --image "$IMAGE" \
  --registry-login-server "$LOGIN_SERVER" \
  --registry-username "$ACR_USER" \
  --registry-password "$ACR_PASS" \
  --os-type Linux \
  --cpu 1 --memory 1.5 \
  --ports 8000 \
  --ip-address Public \
  --dns-name-label "$DNS_LABEL" \
  --environment-variables AGENTGATE_MODE="$MODE" \
  --output none
  # For real mode, add AWS creds as secrets, e.g.:
  #   --secure-environment-variables AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AGENTGATE_API_KEYS='...'

FQDN=$(az container show --resource-group "$RESOURCE_GROUP" --name "$CONTAINER_NAME" \
  --query ipAddress.fqdn --output tsv)

echo
echo "==> Deployed. The proxy is live at:"
echo "    http://$FQDN:8000"
echo
echo "Test it:"
echo "    curl -X POST http://$FQDN:8000/execute-tool \\"
echo "      -H 'X-API-Key: alice-key' -H 'Content-Type: application/json' \\"
echo "      -d '{\"tool_name\": \"read_file\", \"tool_args\": {\"bucket\": \"reports\", \"key\": \"q4.csv\"}}'"
echo
echo "Or point the simulator at it:"
echo "    python -m agentgate.simulator --mode live --url http://$FQDN:8000"
