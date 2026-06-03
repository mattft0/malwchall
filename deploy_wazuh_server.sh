#!/usr/bin/env bash
# =============================================================================
# SCRIPT 1/2 — À EXÉCUTER SUR LA MACHINE WAZUH SERVER
# Installe Wazuh All-in-One (Manager + Indexer + Dashboard)
# Déploie les règles de détection personnalisées
# Pousse la config de monitoring vers les agents via agent.conf
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/wazuh_rules"
LOG="$SCRIPT_DIR/deploy_wazuh_server.log"
WAZUH_RULES_PATH="/var/ossec/etc/rules"
WAZUH_SHARED_PATH="/var/ossec/etc/shared/default"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*" | tee -a "$LOG"; }
success() { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || error "Lancer en root: sudo bash $0"
}

# ─── STEP 1 — Mise à jour système + dépendances ─────────────────────────────
system_update() {
    info "Step 1/5 — Mise à jour système + installation des dépendances..."
    apt-get update -y >> "$LOG" 2>&1
    apt-get upgrade -y >> "$LOG" 2>&1

    # Dépendances requises par le script wazuh-install.sh
    info "Installation des dépendances (software-properties-common, curl, gnupg)..."
    apt-get install -y \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        debconf-utils \
        procps \
        grep \
        sed \
        tar >> "$LOG" 2>&1
    success "Système à jour + dépendances installées."
}

# ─── STEP 2 — Installation Wazuh All-in-One ──────────────────────────────────
install_wazuh_server() {
    info "Step 2/5 — Installation Wazuh all-in-one (~15-20 min)..."
    info "Téléchargement du script d'installation..."
    curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh
    chmod +x wazuh-install.sh

    # -a  : all-in-one (manager + indexer + dashboard)
    # -o  : overwrite/erase existing installation
    # --ignore-check : ignore OS compatibility warnings
    info "Lancement de wazuh-install.sh -a -o --ignore-check..."
    bash ./wazuh-install.sh -a -o --ignore-check 2>&1 | tee -a "$LOG"
    success "Wazuh installé."

    info "Extraction des credentials..."
    if [[ -f wazuh-install-files.tar ]]; then
        tar -xvf wazuh-install-files.tar >> "$LOG" 2>&1
        if [[ -f wazuh-install-files/wazuh-passwords.txt ]]; then
            cp wazuh-install-files/wazuh-passwords.txt "$SCRIPT_DIR/wazuh-passwords.txt"
            success "Credentials sauvegardés dans: $SCRIPT_DIR/wazuh-passwords.txt"
            echo ""
            echo "======= CREDENTIALS WAZUH ======="
            cat "$SCRIPT_DIR/wazuh-passwords.txt"
            echo "================================="
        fi
    fi
}

# ─── STEP 3 — Déploiement des règles de détection ────────────────────────────
deploy_custom_rules() {
    info "Step 3/5 — Déploiement des règles personnalisées sur le Manager..."
    mkdir -p "$WAZUH_RULES_PATH"

    for f in "$RULES_DIR"/*.xml; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f")
        cp "$f" "$WAZUH_RULES_PATH/$name"
        success "Règle déployée: $name"
    done
}

# ─── STEP 4 — agent.conf (config poussée vers tous les agents) ───────────────
# En Wazuh, le Manager peut pousser de la configuration vers les agents
# via /var/ossec/etc/shared/default/agent.conf
# Cela évite de devoir modifier manuellement ossec.conf sur chaque agent
deploy_agent_conf() {
    info "Step 4/5 — Création de agent.conf (config poussée aux agents)..."
    mkdir -p "$WAZUH_SHARED_PATH"

    cat > "$WAZUH_SHARED_PATH/agent.conf" <<'AGENTCONF'
<!--
  agent.conf — Configuration poussée par le Manager vers tous les agents
  Les agents lisent ce fichier et monitorent les fichiers listés ici.
  Source: /var/ossec/etc/shared/default/agent.conf (sur le MANAGER)
-->
<agent_config>

  <!-- ══════════════════════════════════════════════════════════
       SYSCHECK — Surveillance d'intégrité fichiers (FIM)
       ══════════════════════════════════════════════════════════ -->
  <syscheck>
    <frequency>300</frequency>
    <!-- Configs critiques des services -->
    <directories realtime="yes" check_all="yes">/etc/mysql</directories>
    <directories realtime="yes" check_all="yes">/etc/mysql/mariadb.conf.d</directories>
    <directories realtime="yes" check_all="yes">/etc/mongod.conf</directories>
    <directories realtime="yes" check_all="yes">/etc/redis</directories>
    <directories realtime="yes" check_all="yes">/etc/docker</directories>
    <directories realtime="yes" check_all="yes">/etc/k3s</directories>
    <!-- Comptes et SSH -->
    <directories realtime="yes" check_all="yes">/etc/passwd</directories>
    <directories realtime="yes" check_all="yes">/etc/shadow</directories>
    <directories realtime="yes" check_all="yes">/etc/sudoers</directories>
    <directories realtime="yes" check_all="yes">/etc/sudoers.d</directories>
    <directories realtime="yes" check_all="yes">/root/.ssh</directories>
    <directories realtime="yes" check_all="yes">/home</directories>
    <!-- Crontabs -->
    <directories realtime="yes" check_all="yes">/etc/cron.d</directories>
    <directories realtime="yes" check_all="yes">/etc/cron.daily</directories>
    <directories realtime="yes" check_all="yes">/var/spool/cron</directories>
    <!-- Binaires système critiques -->
    <directories realtime="yes" check_all="yes">/usr/bin</directories>
    <directories realtime="yes" check_all="yes">/usr/sbin</directories>
    <directories realtime="yes" check_all="yes">/bin</directories>
    <!-- /tmp (staging malware) -->
    <directories realtime="yes" check_all="yes">/tmp</directories>
  </syscheck>

  <!-- ══════════════════════════════════════════════════════════
       LOG MONITORING — Fichiers de logs à surveiller sur l'agent
       ══════════════════════════════════════════════════════════ -->

  <!-- Système -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
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
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/mysql-slow.log</location>
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

  <!-- Nginx (frontend / reverse proxy Python apps) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <!-- Apache2 (si présent) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <!-- Docker events (commande périodique) -->
  <localfile>
    <log_format>command</log_format>
    <command>docker events --since 60s --until 0s --format "{{.Type}} {{.Action}} {{.Actor.Attributes.name}} {{.Actor.Attributes.image}}" 2>/dev/null || true</command>
    <alias>docker-events</alias>
    <frequency>60</frequency>
  </localfile>

  <!-- Docker container logs (adapter le nom du container si besoin) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/lib/docker/containers/*/*-json.log</location>
  </localfile>

  <!-- k3s audit log -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/k3s/audit.log</location>
  </localfile>

  <!-- k3s service log -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/k3s/k3s.log</location>
  </localfile>

  <!-- Kubernetes standard audit (si k8s vanille) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/kubernetes/audit/audit.log</location>
  </localfile>

  <!-- Python apps — adapter les chemins à ton app -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/app/app.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/gunicorn/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/gunicorn/error.log</location>
  </localfile>

  <!-- ══════════════════════════════════════════════════════════
       ACTIVE RESPONSE — Commandes disponibles sur l'agent
       ══════════════════════════════════════════════════════════ -->
  <!-- Le blocage IP est déclenché par le Manager (voir ossec.conf serveur) -->
  <!-- Les scripts sont sur l'agent dans /var/ossec/active-response/bin/ -->

</agent_config>
AGENTCONF

    success "agent.conf créé → sera poussé automatiquement à tous les agents."
}

# ─── STEP 5 — Restart Wazuh ──────────────────────────────────────────────────
# Mode DETECTION ONLY — aucun blocage automatique d'IP
# Les alertes sont visibles dans le dashboard et dans alerts.log
configure_server() {
    info "Step 5/5 — Restart Wazuh (mode détection uniquement)..."
    local conf="/var/ossec/etc/ossec.conf"
    [[ -f "$conf" ]] || error "ossec.conf non trouvé"

    cp "$conf" "${conf}.bak.$(date +%s)"

    # Restart
    systemctl restart wazuh-manager 2>/dev/null || /var/ossec/bin/wazuh-control restart
    sleep 5

    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        success "Wazuh Manager opérationnel !"
    else
        warn "Vérifier: /var/ossec/logs/ossec.log"
    fi

    local IP
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║  WAZUH SERVER PRÊT — DETECTION ONLY          ║"
    echo "╠══════════════════════════════════════════════╣"
    echo "║  Dashboard : https://$IP"
    echo "║  Credentials: $SCRIPT_DIR/wazuh-passwords.txt"
    echo "║  IP Manager (pour l'agent) : $IP"
    echo "╚══════════════════════════════════════════════╝"
    echo ""
    echo "→ Sur la machine SERVICES, lancer:"
    echo "  sudo bash deploy_agent.sh $IP"
}

# ─── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo "" > "$LOG"
    echo "======================================================" | tee -a "$LOG"
    echo "  WAZUH SERVER — Deploy — $(date)" | tee -a "$LOG"
    echo "======================================================" | tee -a "$LOG"

    check_root
    system_update
    install_wazuh_server
    deploy_custom_rules
    deploy_agent_conf
    configure_server

    success "=== SERVEUR WAZUH DÉPLOYÉ ==="
}

main "$@"
