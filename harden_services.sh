#!/usr/bin/env bash
# =============================================================================
# Hardening Script — BlueTeam Challenge
# Run BEFORE the challenge starts to harden each service
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

# ─── MariaDB Hardening ────────────────────────────────────────────────────────
harden_mariadb() {
    echo -e "\n${YELLOW}=== MariaDB Hardening ===${NC}"

    # Enable general log to file so Wazuh can read it
    mysql -u root -e "
        SET GLOBAL general_log = 'ON';
        SET GLOBAL general_log_file = '/var/log/mysql/general.log';
        SET GLOBAL log_warnings = 2;
        DELETE FROM mysql.user WHERE User='';
        DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
        DROP DATABASE IF EXISTS test;
        DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
        FLUSH PRIVILEGES;
    " 2>/dev/null && ok "MariaDB: anonymous users removed, test DB dropped, logging enabled" || warn "MariaDB: could not connect as root without password"

    # Bind to localhost only
    local cnf="/etc/mysql/mariadb.conf.d/50-server.cnf"
    if [[ -f "$cnf" ]]; then
        sed -i 's/^#\?bind-address\s*=.*/bind-address = 127.0.0.1/' "$cnf"
        ok "MariaDB: bound to 127.0.0.1"
    fi

    # Create log dir
    mkdir -p /var/log/mysql
    chown mysql:mysql /var/log/mysql 2>/dev/null || true
}

# ─── MongoDB Hardening ─────────────────────────────────────────────────────────
harden_mongodb() {
    echo -e "\n${YELLOW}=== MongoDB Hardening ===${NC}"
    local conf="/etc/mongod.conf"
    [[ -f "$conf" ]] || { warn "MongoDB: mongod.conf not found — skipping"; return; }

    # Enable auth
    if ! grep -q "^security:" "$conf"; then
        cat >> "$conf" <<'EOF'

security:
  authorization: enabled

operationProfiling:
  slowOpThresholdMs: 100
  mode: all
EOF
        ok "MongoDB: authorization enabled, profiling enabled"
    else
        warn "MongoDB: security section already exists in mongod.conf"
    fi

    # Bind to localhost
    sed -i 's/bindIp: .*/bindIp: 127.0.0.1/' "$conf"
    ok "MongoDB: bound to 127.0.0.1"

    # Enable log appending
    sed -i '/^systemLog:/,/^[a-z]/ s/destination: .*/destination: file/' "$conf"

    # Restart
    systemctl restart mongod 2>/dev/null && ok "MongoDB: restarted" || warn "MongoDB: could not restart"
}

# ─── Redis Hardening ──────────────────────────────────────────────────────────
harden_redis() {
    echo -e "\n${YELLOW}=== Redis Hardening ===${NC}"
    local conf
    conf="$(find /etc/redis* -name "*.conf" 2>/dev/null | head -1)"
    [[ -f "$conf" ]] || { warn "Redis: config not found — skipping"; return; }

    # Generate random password
    local REDIS_PASS
    REDIS_PASS=$(openssl rand -hex 32)

    # Require password
    sed -i "s/^#\s*requirepass.*/requirepass $REDIS_PASS/" "$conf"
    if ! grep -q "^requirepass" "$conf"; then
        echo "requirepass $REDIS_PASS" >> "$conf"
    fi

    # Bind to localhost
    sed -i 's/^bind .*/bind 127.0.0.1/' "$conf"

    # Disable dangerous commands
    cat >> "$conf" <<EOF

# BlueTeam hardening — disable dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG "REDIS_CONFIG_$(openssl rand -hex 8)"
rename-command DEBUG ""
rename-command SLAVEOF ""
rename-command REPLICAOF ""
rename-command MODULE ""
EOF

    echo "Redis password: $REDIS_PASS" > /root/redis_credentials.txt
    chmod 600 /root/redis_credentials.txt
    ok "Redis: password set, dangerous commands disabled, credentials in /root/redis_credentials.txt"

    systemctl restart redis-server 2>/dev/null || systemctl restart redis 2>/dev/null && ok "Redis: restarted" || warn "Redis: could not restart"
}

# ─── Docker Hardening ─────────────────────────────────────────────────────────
harden_docker() {
    echo -e "\n${YELLOW}=== Docker Hardening ===${NC}"

    # Create/update daemon.json
    local daemon_json="/etc/docker/daemon.json"
    mkdir -p /etc/docker
    cat > "$daemon_json" <<'EOF'
{
    "no-new-privileges": true,
    "userns-remap": "default",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "icc": false,
    "live-restore": true
}
EOF
    ok "Docker: daemon.json hardened (no-new-privileges, userns-remap, icc disabled)"
    systemctl restart docker 2>/dev/null && ok "Docker: restarted" || warn "Docker: could not restart"
}

# ─── k3s / k8s Hardening ──────────────────────────────────────────────────────
harden_k3s() {
    echo -e "\n${YELLOW}=== k3s/k8s Hardening ===${NC}"

    # Enable audit logging for k3s
    local audit_policy="/etc/k3s/audit-policy.yaml"
    mkdir -p /etc/k3s
    if [[ ! -f "$audit_policy" ]]; then
        cat > "$audit_policy" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log auth-related resources at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets", "configmaps", "serviceaccounts"]
    - group: "rbac.authorization.k8s.io"
      resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  # Log pod exec/attach at RequestResponse
  - level: RequestResponse
    verbs: ["create"]
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]
  # Log everything else at Metadata level
  - level: Metadata
    omitStages:
    - RequestReceived
EOF
        ok "k3s: audit policy created at $audit_policy"
    fi

    # Add audit flags to k3s service if not already there
    local k3s_service="/etc/systemd/system/k3s.service"
    if [[ -f "$k3s_service" ]] && ! grep -q "audit-log-path" "$k3s_service"; then
        sed -i "/ExecStart=.*k3s server/ s|$| --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log --kube-apiserver-arg=audit-policy-file=/etc/k3s/audit-policy.yaml --kube-apiserver-arg=audit-log-maxage=7 --kube-apiserver-arg=audit-log-maxbackup=3|" "$k3s_service"
        mkdir -p /var/log/k3s
        systemctl daemon-reload
        systemctl restart k3s 2>/dev/null && ok "k3s: restarted with audit logging" || warn "k3s: could not restart"
    else
        warn "k3s: service file not found or audit already configured"
    fi
}

# ─── Firewall (ufw) ───────────────────────────────────────────────────────────
harden_firewall() {
    echo -e "\n${YELLOW}=== Firewall (ufw) ===${NC}"
    if command -v ufw >/dev/null 2>&1; then
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow 443/tcp    # Wazuh dashboard
        ufw allow 1514/tcp   # Wazuh agent comms
        ufw allow 1515/tcp   # Wazuh agent enrollment
        ufw --force enable
        ok "UFW: firewall rules applied"
    else
        warn "ufw not installed — skipping"
    fi
}

# ─── System Hardening ─────────────────────────────────────────────────────────
harden_system() {
    echo -e "\n${YELLOW}=== System Hardening ===${NC}"

    # Restrict /tmp execution
    if ! grep -q "noexec" /etc/fstab 2>/dev/null | grep tmp; then
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null && ok "System: /tmp mounted noexec" || warn "System: could not remount /tmp"
    fi

    # Kernel hardening via sysctl
    cat > /etc/sysctl.d/99-blueteam.conf <<'EOF'
# BlueTeam hardening
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2
fs.suid_dumpable = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.ip_forward = 0
EOF
    sysctl -p /etc/sysctl.d/99-blueteam.conf > /dev/null 2>&1 && ok "System: kernel hardening applied" || warn "System: some sysctl values could not be set"

    # Disable core dumps
    echo "* hard core 0" >> /etc/security/limits.conf
    ok "System: core dumps disabled"
}

# ─── MAIN ──────────────────────────────────────────────────────────────────────
echo "======================================================"
echo "  BlueTeam Hardening Script — $(date)"
echo "======================================================"

harden_mariadb
harden_mongodb
harden_redis
harden_docker
harden_k3s
harden_firewall
harden_system

echo ""
echo "======================================================"
ok "All hardening steps completed!"
echo "======================================================"
