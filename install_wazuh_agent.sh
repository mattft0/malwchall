#!/usr/bin/env bash
# =============================================================================
# Wazuh Agent Installer — Run on the AGENT machine (not the server)
# This script installs the Wazuh agent and enrolls it to the manager.
# Usage: sudo bash install_wazuh_agent.sh <MANAGER_IP>
# =============================================================================
set -euo pipefail

MANAGER_IP="${1:-}"
[[ -z "$MANAGER_IP" ]] && { echo "Usage: sudo bash $0 <WAZUH_MANAGER_IP>"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

echo "[*] Adding Wazuh repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
apt-get update -y

echo "[*] Installing Wazuh Agent..."
WAZUH_MANAGER="$MANAGER_IP" apt-get install -y wazuh-agent

echo "[*] Enabling and starting Wazuh Agent..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "[OK] Agent installed and connected to: $MANAGER_IP"
systemctl status wazuh-agent --no-pager
