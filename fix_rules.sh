#!/usr/bin/env bash
# =============================================================================
# fix_rules.sh — Déploie uniquement les règles et redémarre wazuh-manager
# À utiliser pour itérer rapidement SANS relancer l'install complète
# Usage: sudo bash fix_rules.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/wazuh_rules"
WAZUH_RULES_PATH="/var/ossec/etc/rules"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
err()  { echo -e "${RED}[ERR]${NC}   $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }

[[ $EUID -eq 0 ]] || { echo "sudo bash $0"; exit 1; }

echo "=============================="
echo "  Fix Rules — $(date +%H:%M:%S)"
echo "=============================="

# ── 1. git pull pour récupérer les derniers fixes ─────────────────────────────
info "git pull..."
git -C "$SCRIPT_DIR" pull 2>&1 || warn "git pull échoué (continué)"

# ── 2. Copier les règles ───────────────────────────────────────────────────────
info "Déploiement des règles dans $WAZUH_RULES_PATH ..."
for f in "$RULES_DIR"/*.xml; do
    [[ -f "$f" ]] || continue
    cp "$f" "$WAZUH_RULES_PATH/$(basename "$f")"
    ok "  → $(basename "$f")"
done

# ── 3. Test de syntaxe Wazuh AVANT de redémarrer ──────────────────────────────
info "Test de syntaxe wazuh-analysisd..."
if /var/ossec/bin/wazuh-analysisd -t 2>&1; then
    ok "Syntaxe OK"
else
    err "Erreur de syntaxe — wazuh-manager NON redémarré"
    err "Corriger les règles et relancer: sudo bash fix_rules.sh"
    exit 1
fi

# ── 4. Redémarrer uniquement wazuh-manager ────────────────────────────────────
info "Redémarrage de wazuh-manager..."
systemctl restart wazuh-manager
sleep 3

if systemctl is-active --quiet wazuh-manager; then
    ok "wazuh-manager opérationnel !"
    echo ""
    echo "→ Alertes en temps réel:"
    echo "  tail -f /var/ossec/logs/alerts/alerts.log"
else
    err "wazuh-manager en erreur — voir: journalctl -u wazuh-manager -n 30"
    exit 1
fi
