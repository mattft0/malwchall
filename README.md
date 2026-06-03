# ╔══════════════════════════════════════════════════════════════════╗
# ║  BlueTeam Challenge — Architecture 2 machines                   ║
# ╚══════════════════════════════════════════════════════════════════╝

# Architecture déployée

```
┌─────────────────────────────┐        ┌──────────────────────────────────┐
│   MACHINE A — Wazuh Server  │        │   MACHINE B — Services           │
│                             │        │                                  │
│  ┌─────────────────────┐    │◄──────►│  ┌────────────────────────────┐  │
│  │  Wazuh Manager      │    │  1514  │  │  Wazuh Agent               │  │
│  │  Wazuh Indexer      │    │  1515  │  │                            │  │
│  │  Wazuh Dashboard    │    │        │  │  Monitore:                 │  │
│  │                     │    │        │  │  - MariaDB 11              │  │
│  │  Règles XML custom  │    │        │  │  - MongoDB 7               │  │
│  │  Active Response    │    │        │  │  - Redis 7                 │  │
│  └─────────────────────┘    │        │  │  - Docker                  │  │
│                             │        │  │  - k3s/k8s                 │  │
│  Dashboard: https://<IP_A>  │        │  │  - Apps Python             │  │
└─────────────────────────────┘        │  └────────────────────────────┘  │
                                       │  auditd (syscalls)               │
                                       └──────────────────────────────────┘
```

---

## 📁 Fichiers du projet

```
MalwChall/
├── deploy_wazuh_server.sh       ← 🖥️  Machine A : installe Wazuh + règles
├── deploy_agent.sh              ← 🖥️  Machine B : installe agent + log monitoring
├── harden_services.sh           ← 🖥️  Machine B : durcit les services
├── wazuh_rules/                 ← Règles de détection (copiées sur Machine A)
│   ├── 100_mariadb_rules.xml        (IDs 100100-108)
│   ├── 100_mongodb_rules.xml        (IDs 100200-208)
│   ├── 100_redis_rules.xml          (IDs 100300-307)
│   ├── 100_python_webapp_rules.xml  (IDs 100400-448)
│   ├── 100_docker_rules.xml         (IDs 100500-508)
│   ├── 100_kubernetes_rules.xml     (IDs 100600-611)
│   └── 100_system_rest_rules.xml    (IDs 100700-731)
└── README.md
```

---

## 🚀 Ordre d'exécution (1h chrono)

### ⏱️ T+0 — Machine B : Durcir les services (5 min)
```bash
# Sur la machine avec les services
sudo bash harden_services.sh
```

### ⏱️ T+5 — Machine A : Installer Wazuh Server (~20 min)
```bash
# Sur la machine dédiée à Wazuh
# (copier les fichiers avec scp ou git clone d'abord)
scp -r MalwChall/ user@<IP_MACHINE_A>:~/
ssh user@<IP_MACHINE_A>
sudo bash MalwChall/deploy_wazuh_server.sh
```
> À la fin, note l'IP de Machine A et les credentials.

### ⏱️ T+25 — Machine B : Installer l'agent (3 min)
```bash
# Sur la machine avec les services
sudo bash deploy_agent.sh <IP_MACHINE_A>
```

### ⏱️ T+28 — Vérifications
```bash
# Sur Machine A — Voir les agents connectés
/var/ossec/bin/agent_control -l

# Sur Machine A — Alertes en temps réel
tail -f /var/ossec/logs/alerts/alerts.log

# Sur Machine A — Tester une règle manuellement
echo "GET /{{7*7}} HTTP/1.1" | /var/ossec/bin/wazuh-logtest

# Dashboard Web
https://<IP_MACHINE_A>
```

---

## 🛡️ Règles par service

| Service | Attaques couvertes | Niveau | IDs |
|---|---|---|---|
| **MariaDB 11** | Brute force, SQLi, `LOAD DATA INFILE`, UDF RCE, `GRANT ALL` | 8–14 | 100100–108 |
| **MongoDB 7** | Brute force, NoSQL injection (`$where`, `$gt`), mapReduce RCE, dump | 8–14 | 100200–208 |
| **Redis 7** | NOAUTH, `CONFIG SET` RCE, `FLUSHALL`, Lua `EVAL`, `MODULE LOAD` | 8–15 | 100300–307 |
| **Jinja2** | SSTI (`{{7*7}}`, `__class__`, `__import__`, `os.system`) | 14–15 | 100401–402 |
| **Pickle** | Désérialisation (magic bytes, `__reduce__`, upload POST) | 10–14 | 100410–411 |
| **JWT** | `alg:none` bypass, RS256→HS256 confusion, `kid` path traversal | 13–14 | 100420–422 |
| **libxml2/XXE** | `ENTITY SYSTEM`, LFI via `file://`, SSRF via XML | 14–15 | 100430–431 |
| **httpx/requests** | SSRF (loopback, RFC1918, cloud metadata `169.254.169.254`) | 13–14 | 100440–441 |
| **REST/JSON** | Mass assignment, prototype pollution `__proto__`, verb tampering | 10–11 | 100700–703 |
| **Docker** | Container privilégié, `docker.sock` monté, exec shell, `--pid=host` | 10–15 | 100500–508 |
| **k3s/k8s** | Anonymous API, ClusterRoleBinding, `pod/exec`, secrets read, wildcard RBAC | 10–15 | 100600–611 |
| **Système** | Reverse shell, crontab persistence, SSH backdoor, `/tmp` exec, `LD_PRELOAD` | 11–15 | 100710–731 |

---

## ⚡ Active Response (automatique)

Les IPs déclenchant des règles critiques sont **automatiquement bloquées** par `iptables` sur **Machine B** :

| Déclencheur | Blocage |
|---|---|
| SQLi, SSTI, NoSQLi, container escape, reverse shell | 1h |
| Brute force, scanners | 30 min |

---

## 🔧 Commandes utiles pendant le challenge

```bash
# ── Sur Machine A (Manager) ──────────────────────────────────────────────────

# Alertes en temps réel avec niveaux
tail -f /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line)
        lvl = a.get('rule',{}).get('level',0)
        if lvl >= 8:
            print(f'[LVL{lvl}] {a[\"rule\"][\"description\"]} — {a.get(\"agent\",{}).get(\"name\",\"?\")}')
    except: pass
"

# Voir les agents connectés
/var/ossec/bin/agent_control -l

# Débloquer une IP manuellement sur Machine B
# (depuis Machine A via active-response delete)
/var/ossec/bin/agent_control -b <IP_A_DEBLOQUER> -f firewall-drop0 -u <AGENT_ID>

# Tester une ligne de log manuellement
/var/ossec/bin/wazuh-logtest

# Valider les règles XML (syntaxe)
/var/ossec/bin/ossec-analysisd -t

# ── Sur Machine B (Agent) ────────────────────────────────────────────────────

# Statut agent
systemctl status wazuh-agent

# IPs bloquées par Active Response
iptables -L INPUT -n | grep DROP

# Débloquer une IP manuellement
iptables -D INPUT -s <IP> -j DROP

# Logs de l'agent
tail -f /var/ossec/logs/ossec.log
```

---

## ⚠️ Points d'attention

> **MariaDB** : Le `general_log` doit être **ON** pour détecter les SQLi.
> `harden_services.sh` l'active automatiquement.

> **MongoDB** : Les logs JSON de MongoDB 7 peuvent nécessiter un decoder custom.
> Vérifier que le log est bien en texte dans `/var/log/mongodb/mongod.log`.

> **k3s audit** : N'est actif qu'après restart de k3s avec les flags `--audit-log-path`.
> `harden_services.sh` injecte ces flags automatiquement.

> **Docker events** : La commande est pollée toutes les 60s. Si Docker n'est pas installé,
> la commande échoue silencieusement (`|| true`).

> **Port 1514/1515** : Ces ports doivent être **ouverts** entre Machine B → Machine A.
> Vérifier avec: `nc -zv <IP_MACHINE_A> 1514`
