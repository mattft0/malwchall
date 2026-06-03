#!/usr/bin/env bash
# =============================================================================
# SCRIPT 2/2 — À EXÉCUTER SUR LA MACHINE SERVICES (agent Wazuh)
# Installe et enrôle l'agent Wazuh vers le Manager
# Configure le monitoring des logs locaux
# Lance le durcissement des services
# =============================================================================
set -euo pipefail

MANAGER_IP="${1:-}"
[[ -z "$MANAGER_IP" ]] && {
    echo "Usage: sudo bash deploy_agent.sh <IP_DU_WAZUH_SERVER>"
    echo "Ex:    sudo bash deploy_agent.sh 192.168.1.10"
    exit 1
}
[[ $EUID -eq 0 ]] || { echo "Lancer en root: sudo bash $0 $MANAGER_IP"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/deploy_agent.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*" | tee -a "$LOG"; }
success() { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG"; exit 1; }

# ─── STEP 1 — Installer l'agent Wazuh ────────────────────────────────────────
install_agent() {
    info "Step 1/4 — Ajout du dépôt Wazuh..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --yes --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -y >> "$LOG" 2>&1

    # Détection dynamique de la version cible (soit celle du manager local, soit la dernière 4.10.x)
    local target_ver=""
    if dpkg -l | grep -q wazuh-manager; then
        target_ver=$(dpkg-query --showformat='${Version}' --show wazuh-manager 2>/dev/null || echo "")
    fi
    if [[ -z "$target_ver" ]]; then
        # Sinon, on prend la dernière 4.10.x disponible dans le dépôt
        target_ver=$(apt-cache madison wazuh-agent 2>/dev/null | grep -oE "4\.10\.[0-9]+-[0-9]+" | head -n 1 || echo "4.10.4-1")
    fi

    info "Installation/Downgrade de l'agent en version $target_ver (pointé vers $MANAGER_IP)..."
    if dpkg -l | grep -q wazuh-agent; then
        apt-get remove -y wazuh-agent >> "$LOG" 2>&1 || true
    fi
    DEBIAN_FRONTEND=noninteractive WAZUH_MANAGER="$MANAGER_IP" apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        --allow-downgrades wazuh-agent="$target_ver" >> "$LOG" 2>&1
    success "Agent installé et configuré pour: $MANAGER_IP"
}

# ─── STEP 2 — Configurer les logs locaux dans ossec.conf de l'agent ──────────
# Note: Le Manager pousse aussi une config via agent.conf (shared).
# On configure ici en local pour être sûr même si la synchro tarde.
configure_agent_logs() {
    info "Step 2/4 — Configuration des logs locaux (ossec.conf agent)..."
    local conf="/var/ossec/etc/ossec.conf"
    [[ -f "$conf" ]] || error "ossec.conf agent non trouvé"

    cp "$conf" "${conf}.bak.$(date +%s)"

    # On injecte les localfile AVANT </ossec_config>
    export LOGFILES='
  <!-- ===== BlueTeam Challenge — Logs services à monitorer ===== -->

  <!-- Système & Auth -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- MariaDB 11 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/error.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/general.log</location>
  </localfile>

  <!-- MongoDB 7 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mongodb/mongod.log</location>
  </localfile>

  <!-- Redis 7 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/redis/redis-server.log</location>
  </localfile>

  <!-- Nginx / Apache (reverse proxy pour apps Python) -->
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
  </localfile>

  <!-- Docker events (polling toutes les 60s) -->
  <localfile>
    <log_format>command</log_format>
    <command>docker events --since 60s --until 0s --format "{{.Type}} {{.Action}} name={{.Actor.Attributes.name}} image={{.Actor.Attributes.image}}" 2>/dev/null || true</command>
    <alias>docker-events</alias>
    <frequency>60</frequency>
  </localfile>

  <!-- Docker container logs via journald -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/lib/docker/containers/*/*-json.log</location>
  </localfile>

  <!-- k3s audit log -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/k3s/audit.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/k3s/k3s.log</location>
  </localfile>

  <!-- Kubernetes vanilla -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kubernetes/audit/audit.log</location>
  </localfile>

  <!-- Apps Python (adapter les chemins si besoin) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/app/*.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/gunicorn/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/gunicorn/error.log</location>
  </localfile>

  <!-- Commandes système suspectes via auditd -->
  <localfile>
    <log_format>command</log_format>
    <command>last -20 2>/dev/null | head -20</command>
    <alias>last-logins</alias>
    <frequency>300</frequency>
  </localfile>'

    python3 - <<'PYEOF'
import os
conf_path = "/var/ossec/etc/ossec.conf"
with open(conf_path, "r") as f:
    data = f.read()

logfiles = os.environ.get('LOGFILES', '')

if "BlueTeam Challenge" not in data:
    # Replace the last occurrence of </ossec_config> to append configuration
    if "</ossec_config>" in data:
        parts = data.rsplit("</ossec_config>", 1)
        data = parts[0] + logfiles + "\n</ossec_config>" + parts[1]
        with open(conf_path, "w") as f:
            f.write(data)
        print("[OK]    ossec.conf agent patché avec les sources de logs.")
    else:
        print("[ERROR] Balise </ossec_config> non trouvée.")
else:
    print("[WARN]  ossec.conf déjà patché.")
PYEOF

    # S'assurer que l'adresse du Manager est correctement configurée
    sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|g" "$conf"
    sed -i "s|<address>127.0.0.1</address>|<address>$MANAGER_IP</address>|g" "$conf"

    # Corriger le conflit de nom avec le Manager (nom "debian" déjà pris)
    python3 - <<'PYEOF'
conf_path = "/var/ossec/etc/ossec.conf"
with open(conf_path, "r") as f:
    data = f.read()

if "<agent_name>" not in data:
    if "<enrollment>" in data:
        data = data.replace("<enrollment>", "<enrollment>\n      <agent_name>blueteam-agent</agent_name>")
        with open(conf_path, "w") as f:
            f.write(data)
        print("[OK]    Nom d'agent unique configuré dans la section enrollment existante.")
    elif "<client>" in data:
        # Si <enrollment> n'existe pas, on l'injecte dans le block <client> avant </client>
        enrollment_block = "    <enrollment>\n      <enabled>yes</enabled>\n      <agent_name>blueteam-agent</agent_name>\n    </enrollment>\n  </client>"
        data = data.replace("</client>", enrollment_block, 1)
        with open(conf_path, "w") as f:
            f.write(data)
        print("[OK]    Block enrollment et nom d'agent unique créés.")
    else:
        print("[WARN]  Section client non trouvée, impossible d'ajouter le nom unique.")
else:
    print("[WARN]  Nom d'agent déjà personnalisé.")
PYEOF

    # Syscheck local sur les répertoires critiques
    python3 - <<'PYEOF'
conf_path = "/var/ossec/etc/ossec.conf"
with open(conf_path, "r") as f:
    data = f.read()

extra = """
    <!-- BlueTeam: répertoires critiques à surveiller -->
    <directories realtime="yes" check_all="yes">/etc/mysql</directories>
    <directories realtime="yes" check_all="yes">/etc/redis</directories>
    <directories realtime="yes" check_all="yes">/etc/docker</directories>
    <directories realtime="yes" check_all="yes">/etc/k3s</directories>
    <directories realtime="yes" check_all="yes">/root/.ssh</directories>
    <directories realtime="yes" check_all="yes">/home</directories>
    <directories realtime="yes" check_all="yes">/tmp</directories>
    <directories realtime="yes" check_all="yes">/var/spool/cron</directories>
    <directories realtime="yes" check_all="yes">/etc/sudoers.d</directories>"""

if "BlueTeam: répertoires" not in data:
    data = data.replace("</syscheck>", extra + "\n  </syscheck>")
    with open(conf_path, "w") as f:
        f.write(data)
    print("[OK]    Syscheck patché.")
else:
    print("[WARN]  Syscheck déjà patché.")
PYEOF
}

# ─── STEP 3 — Activer auditd pour les appels système suspects ────────────────
configure_auditd() {
    info "Step 3/4 — Configuration auditd..."

    if ! command -v auditctl >/dev/null 2>&1; then
        apt-get install -y auditd audispd-plugins >> "$LOG" 2>&1
        success "auditd installé."
    fi

    # Règles auditd pour détecter les actions suspectes
    cat > /etc/audit/rules.d/blueteam.rules <<'AUDITRULES'
# BlueTeam Challenge — Audit Rules
# Exécution de commandes suspectes
-a always,exit -F arch=b64 -S execve -F path=/bin/bash -k bash_exec
-a always,exit -F arch=b64 -S execve -F path=/bin/sh -k sh_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python3 -k python_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k curl_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k wget_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -k netcat_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ncat -k ncat_exec

# Fichiers sensibles
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d -p wa -k sudoers_change
-w /root/.ssh -p wa -k ssh_key_change
-w /var/spool/cron -p wa -k cron_change
-w /etc/cron.d -p wa -k cron_change

# SUID/SGID
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&04000 -k suid_set
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&02000 -k sgid_set

# /tmp exec
-w /tmp -p wx -k tmp_exec

# Docker socket
-w /var/run/docker.sock -p rwa -k docker_socket
AUDITRULES

    augenrules --load >> "$LOG" 2>&1 || warn "augenrules --load a échoué ou non disponible"
    (systemctl restart auditd >> "$LOG" 2>&1 || service auditd restart >> "$LOG" 2>&1) && success "auditd configuré et redémarré." || warn "auditd: redémarrage échoué"
}

# ─── STEP 4 — Démarrer l'agent ────────────────────────────────────────────────
start_agent() {
    info "Step 4/4 — Démarrage de l'agent Wazuh..."
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl restart wazuh-agent

    sleep 5
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        success "Wazuh Agent ACTIF → envoi des logs vers $MANAGER_IP"
    else
        warn "Vérifier: /var/ossec/logs/ossec.log"
    fi

    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║  AGENT WAZUH DÉPLOYÉ                         ║"
    echo "╠══════════════════════════════════════════════╣"
    echo "║  Manager : $MANAGER_IP"
    echo "║  Statut  : $(systemctl is-active wazuh-agent 2>/dev/null)"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "→ Sur le Manager, vérifier l'enrôlement:"
    echo "  /var/ossec/bin/agent_control -l"
    echo ""
    echo "→ Sur le Manager, voir les alertes en temps réel:"
    echo "  tail -f /var/ossec/logs/alerts/alerts.log"
}

# ─── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo "" > "$LOG"
    echo "======================================================" | tee -a "$LOG"
    echo "  WAZUH AGENT — Deploy — $(date)" | tee -a "$LOG"
    echo "  Manager: $MANAGER_IP" | tee -a "$LOG"
    echo "======================================================" | tee -a "$LOG"


    install_agent
    configure_agent_logs
    configure_auditd
    start_agent

    success "=== AGENT DÉPLOYÉ ET CONNECTÉ ==="
}

main "$@"
