#!/usr/bin/env bash
# Sentinel-Watchdog v1.0
# Created by: NayanKumar-ops

set -euo pipefail

# ---  Set Path for Cron ---
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# --- PRO FIX 2: Configuration ---
CONFIG_FILE="./config.conf"
LOCK_FILE="/tmp/sentinel-watchdog.lock"

# ---------- Logging ----------
log() {
    local level="$1"
    local msg="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $msg" | tee -a "$LOG_FILE"
}

# ---------- Root Check ----------
if [[ $EUID -ne 0 ]]; then
   echo "❌ Error: This script must be run as root (sudo)." >&2
   exit 1
fi

# ---------- Config Loader ----------
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Config file not found: $CONFIG_FILE"
        exit 1
    fi

    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#|^\[|^$ ]] && continue
        value="${value//\"/}"
        export "$key=$value"
    done < "$CONFIG_FILE"
}

# ---------- Lock Mechanism ----------
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "WARN" "Another instance is running (PID $pid)"
            exit 1
        else
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

# ---------- Snapshot Logic ----------
take_snapshot() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    {
        echo "=== SENTINEL SNAPSHOT ==="
        echo "Time: $(date)"
        echo "-------------------------"
        echo "UPTIME:"; uptime
        echo "-------------------------"
        echo "MEMORY:"; free -h
        echo "-------------------------"
        echo "DISK:"; df -h
        echo "-------------------------"
        echo "TOP PROCESSES:"; ps aux --sort=-%cpu | head -10
        echo "-------------------------"
        echo "CONNECTIONS:"; ss -tulpn
    } > "$SNAPSHOT_DIR/snapshot-$ts.txt"
    log "INFO" "Snapshot saved: $SNAPSHOT_DIR/snapshot-$ts.txt"
}

# ---------- Checks ----------
check_services() {
    for svc in $SERVICES; do
        if ! systemctl is-active --quiet "$svc"; then
            log "ERROR" "Service $svc is not running"
            systemctl restart "$svc" && log "INFO" "Restarted $svc"
            take_snapshot
        fi
    done
}

check_disk() {
    df -h | awk 'NR>1 {print $5 " " $6}' | while read -r usage mount; do
        usage=${usage%\%}
        if (( usage > DISK_THRESHOLD )); then
            log "WARN" "High disk usage on $mount: ${usage}%"
            take_snapshot
        fi
    done
}

check_memory() {
    local mem
    mem=$(free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}')
    if (( mem > MEMORY_THRESHOLD )); then
        log "WARN" "High memory usage: ${mem}%"
        take_snapshot
    fi
}

check_swap() {
    local swap
    swap=$(free | awk '/Swap:/ {if ($2>0) printf "%.0f", $3/$2 * 100; else print 0}')
    if (( swap > SWAP_THRESHOLD )); then
        log "WARN" "High swap usage: ${swap}%"
        take_snapshot
    fi
}

check_ssh_failures() {
    # Only run if journalctl is available
    if command -v journalctl &> /dev/null; then
        local count
        count=$(journalctl -u sshd --since "5 min ago" 2>/dev/null | grep -c "Failed password" || true)
        if (( count > FAILED_LOGIN_ATTEMPTS )); then
            log "WARN" "Security Alert: $count failed SSH logins in 5 mins"
            take_snapshot
        fi
    fi
}

# ---------- Main Execution ----------
main() {
    load_config
    
    # Auto-create directories if missing
    mkdir -p "$LOG_DIR" "$SNAPSHOT_DIR"
    
    LOG_FILE="$LOG_DIR/watchdog-$(date +%Y%m%d).log"

    acquire_lock
    log "INFO" "Sentinel-Watchdog started..."

    check_services
    check_disk
    check_memory
    check_swap
    check_ssh_failures

    log "INFO" "Sentinel-Watchdog checks complete."
}

main
