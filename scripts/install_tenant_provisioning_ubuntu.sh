#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${OPTIVERSE_APP_DIR:-/opt/optiverse/oltportal}"
ENV_FILE="${OPTIVERSE_ENV_FILE:-$APP_DIR/.env}"
TENANT_BASE_DIR="${OPTIVERSE_TENANT_BASE_DIR:-/opt/optiverse/tenants}"
WG_CONFIG="${OPTIVERSE_WG_SERVER_CONFIG:-/etc/wireguard/wg0.conf}"
WG_PORT="${OPTIVERSE_WG_PORT:-51820}"
WG_ADDRESS="${OPTIVERSE_WG_ADDRESS:-10.200.0.1/16}"
SERVICE_USER="${OPTIVERSE_SERVICE_USER:-optiverse}"
PUBLIC_API_URL="${OPTIVERSE_PUBLIC_API_URL:-}"

require_root_or_sudo() {
  if ! command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    echo "sudo is required, or run this script as root."
    exit 1
  fi
}

set_env_value() {
  local key="$1"
  local value="$2"
  if [ ! -f "$ENV_FILE" ]; then
    sudo mkdir -p "$(dirname "$ENV_FILE")"
    sudo touch "$ENV_FILE"
  fi
  if sudo grep -q "^${key}=" "$ENV_FILE"; then
    sudo sed -i "s#^${key}=.*#${key}=${value}#" "$ENV_FILE"
  else
    echo "${key}=${value}" | sudo tee -a "$ENV_FILE" >/dev/null
  fi
}

require_root_or_sudo

echo "Installing Docker, WireGuard and verification tools..."
sudo apt-get update
sudo apt-get install -y docker.io wireguard wireguard-tools iproute2 iptables curl netcat-openbsd snmp
sudo apt-get install -y docker-compose-plugin || sudo apt-get install -y docker-compose || true

echo "Enabling Docker..."
sudo systemctl enable docker
sudo systemctl start docker

echo "Preparing /dev/net/tun..."
sudo modprobe tun || true
if [ ! -e /dev/net/tun ]; then
  echo "Warning: /dev/net/tun not found. Docker WireGuard containers may fail until TUN is available."
fi

echo "Preparing tenant base directory..."
sudo mkdir -p "$TENANT_BASE_DIR"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$TENANT_BASE_DIR" || true
sudo chmod 750 "$TENANT_BASE_DIR" || true

echo "Preparing WireGuard server keys/config..."
sudo mkdir -p /etc/wireguard
if [ ! -f /etc/wireguard/server_private.key ]; then
  wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key >/dev/null
  sudo chmod 600 /etc/wireguard/server_private.key
fi

SERVER_PRIVATE_KEY="$(sudo cat /etc/wireguard/server_private.key)"
SERVER_PUBLIC_KEY="$(sudo cat /etc/wireguard/server_public.key)"

if [ ! -f "$WG_CONFIG" ]; then
  sudo tee "$WG_CONFIG" >/dev/null <<EOF
[Interface]
Address = $WG_ADDRESS
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = false
EOF
  sudo chmod 600 "$WG_CONFIG"
fi

echo "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-optiverse-forwarding.conf >/dev/null
sudo sysctl --system >/dev/null

if command -v ufw >/dev/null 2>&1; then
  echo "Allowing WireGuard UDP port in UFW..."
  sudo ufw allow "$WG_PORT/udp" || true
fi

echo "Adding service user to docker group..."
sudo usermod -aG docker "$SERVICE_USER" || true

if [ -f "$APP_DIR/agent/Dockerfile" ]; then
  echo "Building Phase-1 OptiVerse tenant agent image..."
  sudo docker build -t optiverse-agent:latest "$APP_DIR/agent"
fi

echo "Updating OptiVerse .env provisioning values..."
set_env_value "OPTIVERSE_TENANT_AUTO_PROVISION" "True"
set_env_value "OPTIVERSE_TENANT_BASE_DIR" "$TENANT_BASE_DIR"
set_env_value "OPTIVERSE_WG_SERVER_CONFIG" "$WG_CONFIG"
set_env_value "OPTIVERSE_WG_RESTART_AFTER_PROVISION" "True"
if [ -n "$PUBLIC_API_URL" ]; then
  set_env_value "OPTIVERSE_PUBLIC_API_URL" "$PUBLIC_API_URL"
fi

echo "Starting WireGuard..."
sudo systemctl enable wg-quick@wg0
sudo systemctl restart wg-quick@wg0

echo
echo "Tenant provisioning install complete."
echo
echo "VPS WireGuard public key. Paste this into OptiVerse tenant form:"
echo "$SERVER_PUBLIC_KEY"
echo
echo "Verify with:"
echo "  sudo systemctl status docker"
echo "  sudo systemctl status wg-quick@wg0"
echo "  sudo wg show"
echo "  sudo docker ps"
echo
echo "Important: log out/in or restart optiverse service so docker group/env changes apply."
echo "  sudo systemctl restart optiverse"
