#!/usr/bin/env bash
# =============================================================================
# Wazuh Auto-Deploy + Custom Rules  — BlueTeam Challenge
# Services: MariaDB11, Jinja2, MongoDB7, pymongo, httpx, Pickle,
#           requests, JWT, libxml2, REST/JSON, Redis7, Docker, k3s/k8s
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/wazuh_rules"
LOG="$SCRIPT_DIR/deploy_wazuh.log"
WAZUH_RULES_PATH="/var/ossec/etc/rules"
WAZUH_DECODERS_PATH="/var/ossec/etc/decoders"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*" | tee -a "$LOG"; }
success() { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || error "Please run as root: sudo bash $0"
}

# ─── STEP 1 — System Update ───────────────────────────────────────────────────
system_update() {
    info "Step 1/6 — System update..."
    apt-get update -y  >> "$LOG" 2>&1
    apt-get upgrade -y >> "$LOG" 2>&1
    success "System up to date."
}

# ─── STEP 2 — Install Wazuh All-in-One ────────────────────────────────────────
install_wazuh() {
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        warn "Wazuh Manager already running — skipping install."
        return
    fi
    info "Step 2/6 — Downloading and installing Wazuh (all-in-one)..."
    curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh
    bash ./wazuh-install.sh -a --ignore-check 2>&1 | tee -a "$LOG"
    success "Wazuh installed."

    info "Extracting credentials..."
    if [[ -f wazuh-install-files.tar ]]; then
        tar -xvf wazuh-install-files.tar >> "$LOG" 2>&1
        if [[ -f wazuh-install-files/wazuh-passwords.txt ]]; then
            success "=== WAZUH CREDENTIALS ==="
            cat wazuh-install-files/wazuh-passwords.txt
            cp wazuh-install-files/wazuh-passwords.txt "$SCRIPT_DIR/wazuh-passwords.txt"
        fi
    fi
}

# ─── STEP 3 — Deploy Custom Rules ─────────────────────────────────────────────
deploy_rules() {
    info "Step 3/6 — Deploying custom detection rules..."
    mkdir -p "$WAZUH_RULES_PATH" "$WAZUH_DECODERS_PATH"

    for f in "$RULES_DIR"/*.xml; do
        name=$(basename "$f")
        cp "$f" "$WAZUH_RULES_PATH/$name"
        success "Rule deployed: $name"
    done

    for f in "$RULES_DIR"/decoders/*.xml 2>/dev/null; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f")
        cp "$f" "$WAZUH_DECODERS_PATH/$name"
        success "Decoder deployed: $name"
    done
}

# ─── STEP 4 — Configure ossec.conf ────────────────────────────────────────────
configure_ossec() {
    info "Step 4/6 — Patching /var/ossec/etc/ossec.conf..."
    local conf="/var/ossec/etc/ossec.conf"
    [[ -f "$conf" ]] || error "ossec.conf not found — is Wazuh installed?"

    # Backup
    cp "$conf" "${conf}.bak.$(date +%s)"

    # ── Log sources to monitor ────────────────────────────────────────────────
    local LOGFILES='
  <!-- ===== BlueTeam Challenge – monitored log files ===== -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/error.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/general.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mongodb/mongod.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/redis/redis-server.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>
  <localfile>
    <log_format>command</log_format>
    <command>docker events --filter type=container --format "{{.Status}} {{.Actor.Attributes.name}}" 2>/dev/null || true</command>
    <alias>docker-events</alias>
    <frequency>60</frequency>
  </localfile>
  <!-- k3s / k8s API audit log -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/k3s/audit.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kubernetes/audit/audit.log</location>
  </localfile>
  <!-- Web / app generic -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>'

    # Insert before closing </ossec_config>
    if ! grep -q "BlueTeam Challenge" "$conf"; then
        sed -i "s|</ossec_config>|${LOGFILES}\n</ossec_config>|" "$conf"
        success "ossec.conf patched with log sources."
    else
        warn "ossec.conf already patched — skipping."
    fi

    # Enable syscheck for sensitive dirs
    python3 - <<'PYEOF'
import re, sys
conf_path = "/var/ossec/etc/ossec.conf"
with open(conf_path, "r") as f:
    data = f.read()

extra_dirs = """
    <!-- BlueTeam extra directories -->
    <directories realtime="yes" check_all="yes">/etc/mysql</directories>
    <directories realtime="yes" check_all="yes">/etc/mongod.conf</directories>
    <directories realtime="yes" check_all="yes">/etc/redis</directories>
    <directories realtime="yes" check_all="yes">/etc/docker</directories>
    <directories realtime="yes" check_all="yes">/home</directories>
    <directories realtime="yes" check_all="yes">/root</directories>
    <directories realtime="yes" check_all="yes">/tmp</directories>"""

if "BlueTeam extra directories" not in data:
    data = data.replace("</syscheck>", extra_dirs + "\n  </syscheck>")
    with open(conf_path, "w") as f:
        f.write(data)
    print("[OK]    syscheck extra dirs added.")
else:
    print("[WARN]  syscheck already patched.")
PYEOF
}

# ─── STEP 5 — Enable Active Response ──────────────────────────────────────────
configure_active_response() {
    info "Step 5/6 — Configuring Active Response..."
    local conf="/var/ossec/etc/ossec.conf"
    local AR_BLOCK='
  <!-- ===== Active Response – BlueTeam Challenge ===== -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100200,100210,100220,100310,100410,100510,100610,100710,100810,100910</rules_id>
    <timeout>3600</timeout>
  </active-response>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>7200</timeout>
  </active-response>'

    if ! grep -q "Active Response – BlueTeam" "$conf"; then
        sed -i "s|</ossec_config>|${AR_BLOCK}\n</ossec_config>|" "$conf"
        success "Active Response configured."
    else
        warn "Active Response already configured."
    fi
}

# ─── STEP 6 — Restart & Validate ──────────────────────────────────────────────
restart_wazuh() {
    info "Step 6/6 — Restarting Wazuh services..."
    systemctl restart wazuh-manager 2>/dev/null || /var/ossec/bin/wazuh-control restart
    sleep 5
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        success "Wazuh Manager is RUNNING."
    else
        /var/ossec/bin/wazuh-control status | tee -a "$LOG"
        warn "Check logs: /var/ossec/logs/ossec.log"
    fi
    info "Dashboard URL: https://$(hostname -I | awk '{print $1}')"
    info "Credentials:   $SCRIPT_DIR/wazuh-passwords.txt"
}

# ─── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo "" | tee "$LOG"
    echo "======================================================" | tee -a "$LOG"
    echo "  Wazuh BlueTeam Auto-Deploy — $(date)"                 | tee -a "$LOG"
    echo "======================================================" | tee -a "$LOG"

    check_root
    system_update
    install_wazuh
    deploy_rules
    configure_ossec
    configure_active_response
    restart_wazuh

    echo ""
    success "=== DEPLOYMENT COMPLETE ==="
    echo -e "${GREEN}Rules deployed:${NC}"
    ls "$WAZUH_RULES_PATH"/100_*.xml 2>/dev/null | xargs -I{} basename {} || true
    echo ""
    echo -e "${YELLOW}Full log: $LOG${NC}"
}

main "$@"
