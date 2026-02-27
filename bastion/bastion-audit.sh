#!/usr/bin/env bash
# =============================================================================
#  BASTION-AUDIT ENGINE v1.0
#  CIS Benchmark-Aligned Security Posture Auditor for Rocky Linux
#
#  Usage : sudo ./bastion-audit.sh [--report-dir /path/to/output]
#  Output: TXT + CSV report saved to /var/log/bastion-audit/ by default
# =============================================================================

set -euo pipefail

# ─── CLI FLAGS ────────────────────────────────────────────────────────────────
REPORT_DIR="/var/log/bastion-audit"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir) REPORT_DIR="$2"; shift 2 ;;
    *) echo "[ERROR] Unknown flag: $1"; exit 1 ;;
  esac
done

# ─── GUARD: Must run as root ──────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Run this script as root: sudo ./bastion-audit.sh" >&2
  exit 1
fi

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── SCORING ─────────────────────────────────────────────────────────────────
# Weighted: CRITICAL=3  HIGH=2  MEDIUM=1  INFO=0
TOTAL_CHECKS=0; PASSED_CHECKS=0; SCORE_MAX=0; SCORE_EARNED=0
declare -A WEIGHTS=( [CRITICAL]=3 [HIGH]=2 [MEDIUM]=1 [INFO]=0 )

# ─── REPORT SETUP ────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
REPORT_TXT="$REPORT_DIR/bastion_report_${TIMESTAMP}.txt"
REPORT_CSV="$REPORT_DIR/bastion_report_${TIMESTAMP}.csv"
echo "Check_ID,Category,Severity,Status,Detail,CIS_Reference" > "$REPORT_CSV"

# ─── HELPERS ─────────────────────────────────────────────────────────────────

log_check() {
  local id="$1" category="$2" severity="$3" status="$4" detail="$5" cis_ref="${6:-N/A}"
  TOTAL_CHECKS=$(( TOTAL_CHECKS + 1 ))
  local weight=${WEIGHTS[$severity]:-0}
  SCORE_MAX=$(( SCORE_MAX + weight ))

  local color="$RESET" icon="?"
  if [[ "$status" == "PASS" ]]; then
    PASSED_CHECKS=$(( PASSED_CHECKS + 1 ))
    SCORE_EARNED=$(( SCORE_EARNED + weight ))
    color="$GREEN"; icon="✔"
  elif [[ "$status" == "FAIL" ]]; then
    [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]] && color="$RED" || color="$YELLOW"
    icon="✘"
  elif [[ "$status" == "WARN" ]]; then
    color="$YELLOW"; icon="⚠"
  elif [[ "$status" == "INFO" ]]; then
    color="$CYAN"; icon="ℹ"
  fi

  printf "${color}  [%s] [%-8s] [%-6s] %s${RESET}\n" "$icon" "$severity" "$status" "$detail"
  printf "         ${CYAN}↳ %s | %s${RESET}\n" "$cis_ref" "$id"

  printf "  [%s] [%-8s] [%-6s] %s\n" "$icon" "$severity" "$status" "$detail" >> "$REPORT_TXT"
  printf "         ↳ %s | %s\n" "$cis_ref" "$id" >> "$REPORT_TXT"

  local safe_detail; safe_detail=$(echo "$detail" | sed 's/,/;/g')
  echo "${id},${category},${severity},${status},\"${safe_detail}\",${cis_ref}" >> "$REPORT_CSV"
}

section_header() {
  local title="$1"
  printf "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
  printf "  ▶  %s\n" "$title"
  printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
  printf "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" >> "$REPORT_TXT"
  printf "  ▶  %s\n" "$title" >> "$REPORT_TXT"
  printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" >> "$REPORT_TXT"
}

get_ssh_value() {
  grep -i "^[[:space:]]*${1}[[:space:]]" /etc/ssh/sshd_config \
    2>/dev/null | tail -1 | awk '{print $2}' | tr -d '"'
}

# ─── BANNER ──────────────────────────────────────────────────────────────────

BANNER="
╔══════════════════════════════════════════════════════╗
║         BASTION-AUDIT ENGINE  v1.0                  ║
║         CIS Benchmark Security Posture Report        ║
╚══════════════════════════════════════════════════════╝
  Host     : ${HOSTNAME_VAL}
  OS       : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  Kernel   : $(uname -r)
  Run Time : $(date)
"
echo -e "${BOLD}${CYAN}${BANNER}${RESET}"
echo "$BANNER" >> "$REPORT_TXT"

# =============================================================================
#  MODULE 1 — SSH HARDENING
# =============================================================================
section_header "MODULE 1 — SSH Hardening"

val=$(get_ssh_value "PermitRootLogin")
[[ "${val,,}" == "no" ]] \
  && log_check "SSH-01" "SSH" "CRITICAL" "PASS" "PermitRootLogin is disabled" "CIS 5.2.8" \
  || log_check "SSH-01" "SSH" "CRITICAL" "FAIL" "PermitRootLogin is '${val:-not set}' — root SSH access allowed!" "CIS 5.2.8"

val=$(get_ssh_value "PasswordAuthentication")
[[ "${val,,}" == "no" ]] \
  && log_check "SSH-02" "SSH" "CRITICAL" "PASS" "PasswordAuthentication disabled (key-only)" "CIS 5.2.11" \
  || log_check "SSH-02" "SSH" "CRITICAL" "FAIL" "PasswordAuthentication is '${val:-not set}' — brute-force risk!" "CIS 5.2.11"

val=$(get_ssh_value "Protocol")
[[ "$val" == "2" || -z "$val" ]] \
  && log_check "SSH-03" "SSH" "HIGH" "PASS" "SSH Protocol v2 enforced" "CIS 5.2.2" \
  || log_check "SSH-03" "SSH" "HIGH" "FAIL" "SSH Protocol '${val}' — SSHv1 is insecure!" "CIS 5.2.2"

val=$(get_ssh_value "X11Forwarding")
[[ "${val,,}" == "no" || -z "$val" ]] \
  && log_check "SSH-04" "SSH" "MEDIUM" "PASS" "X11Forwarding is disabled" "CIS 5.2.6" \
  || log_check "SSH-04" "SSH" "MEDIUM" "FAIL" "X11Forwarding is enabled — unnecessary attack surface" "CIS 5.2.6"

val=$(get_ssh_value "MaxAuthTries")
[[ -n "$val" && "$val" -le 4 ]] \
  && log_check "SSH-05" "SSH" "MEDIUM" "PASS" "MaxAuthTries = ${val} (≤4)" "CIS 5.2.7" \
  || log_check "SSH-05" "SSH" "MEDIUM" "FAIL" "MaxAuthTries '${val:-not set}' — recommend ≤4" "CIS 5.2.7"

val=$(get_ssh_value "ClientAliveInterval")
[[ -n "$val" && "$val" -gt 0 && "$val" -le 300 ]] \
  && log_check "SSH-06" "SSH" "MEDIUM" "PASS" "ClientAliveInterval = ${val}s (idle timeout active)" "CIS 5.2.16" \
  || log_check "SSH-06" "SSH" "MEDIUM" "FAIL" "ClientAliveInterval '${val:-not set}' — sessions never time out" "CIS 5.2.16"

val=$(get_ssh_value "Banner")
[[ -n "$val" && "$val" != "none" ]] \
  && log_check "SSH-07" "SSH" "INFO" "PASS" "SSH login banner configured: ${val}" "CIS 5.2.15" \
  || log_check "SSH-07" "SSH" "INFO" "FAIL" "No SSH login banner set — legal notice missing" "CIS 5.2.15"

grep -qE "^[[:space:]]*(AllowUsers|AllowGroups)" /etc/ssh/sshd_config 2>/dev/null \
  && log_check "SSH-08" "SSH" "HIGH" "PASS" "SSH access restricted via AllowUsers/AllowGroups" "CIS 5.2.17" \
  || log_check "SSH-08" "SSH" "HIGH" "FAIL" "No AllowUsers/AllowGroups — any user can attempt SSH" "CIS 5.2.17"

# =============================================================================
#  MODULE 2 — IDENTITY & ACCESS MANAGEMENT
# =============================================================================
section_header "MODULE 2 — Identity & Access Management"

empty_pass=$(awk -F: '($2=="" || $2=="!!") && $1!="root" {print $1}' /etc/shadow 2>/dev/null || true)
[[ -z "$empty_pass" ]] \
  && log_check "IAM-01" "IAM" "CRITICAL" "PASS" "No accounts with empty/unset passwords" "CIS 6.3.1" \
  || log_check "IAM-01" "IAM" "CRITICAL" "FAIL" "Empty/locked password accounts: $(echo $empty_pass | tr '\n' ' ')" "CIS 6.3.1"

uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -v '^root$' || true)
[[ -z "$uid0" ]] \
  && log_check "IAM-02" "IAM" "CRITICAL" "PASS" "Only root has UID 0" "CIS 6.2.5" \
  || log_check "IAM-02" "IAM" "CRITICAL" "FAIL" "Non-root accounts with UID 0: $(echo $uid0 | tr '\n' ' ')" "CIS 6.2.5"

INACTIVE_DAYS=90
stale_users=""
while IFS=: read -r username _ _ _ _ _ last_change; do
  uid_val=$(id -u "$username" 2>/dev/null || echo 0)
  [[ "$uid_val" -lt 1000 ]] && continue
  if [[ -n "$last_change" && "$last_change" =~ ^[0-9]+$ ]]; then
    days_since=$(( ( $(date +%s) - last_change * 86400 ) / 86400 ))
    [[ "$days_since" -gt "$INACTIVE_DAYS" ]] && stale_users+="${username}(${days_since}d) "
  fi
done < /etc/shadow
[[ -z "$stale_users" ]] \
  && log_check "IAM-03" "IAM" "MEDIUM" "PASS" "No accounts inactive >${INACTIVE_DAYS} days" "CIS 5.4.1.4" \
  || log_check "IAM-03" "IAM" "MEDIUM" "WARN" "Stale accounts: ${stale_users}" "CIS 5.4.1.4"

max_age=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
[[ -n "$max_age" && "$max_age" -le 90 ]] \
  && log_check "IAM-04" "IAM" "MEDIUM" "PASS" "PASS_MAX_DAYS = ${max_age} (≤90)" "CIS 5.4.1.1" \
  || log_check "IAM-04" "IAM" "MEDIUM" "FAIL" "PASS_MAX_DAYS '${max_age:-not set}' — passwords may never expire" "CIS 5.4.1.1"

pam_len=$(grep -rh "minlen=" /etc/pam.d/system-auth /etc/pam.d/password-auth \
  2>/dev/null | grep -oP 'minlen=\K[0-9]+' | tail -1 || true)
min_len="${pam_len:-$(grep "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}')}"
[[ -n "$min_len" && "$min_len" -ge 14 ]] \
  && log_check "IAM-05" "IAM" "HIGH" "PASS" "Minimum password length = ${min_len} (≥14)" "CIS 5.4.1" \
  || log_check "IAM-05" "IAM" "HIGH" "FAIL" "Min password length '${min_len:-not set}' — recommend ≥14" "CIS 5.4.1"

root_path=$(sudo -i env 2>/dev/null | grep '^PATH=' | cut -d= -f2)
echo ":${root_path}:" | grep -qE '(^|:)\.(:|$)' \
  && log_check "IAM-06" "IAM" "HIGH" "FAIL" "Dot '.' found in root PATH — path hijack risk!" "CIS 6.2.6" \
  || log_check "IAM-06" "IAM" "HIGH" "PASS" "Root PATH does not contain '.' — safe" "CIS 6.2.6"

# =============================================================================
#  MODULE 3 — FIREWALL & PORT GOVERNANCE
# =============================================================================
section_header "MODULE 3 — Firewall & Port Governance"

systemctl is-active --quiet firewalld 2>/dev/null \
  && log_check "FW-01" "FIREWALL" "CRITICAL" "PASS" "firewalld is active and running" "CIS 3.5.1.1" \
  || log_check "FW-01" "FIREWALL" "CRITICAL" "FAIL" "firewalld is NOT running — host is unprotected!" "CIS 3.5.1.1"

( systemctl is-active --quiet nftables 2>/dev/null || \
  systemctl is-active --quiet iptables 2>/dev/null ) \
  && log_check "FW-02" "FIREWALL" "HIGH" "PASS" "Kernel-level firewall (nftables/iptables) active" "CIS 3.5.2" \
  || log_check "FW-02" "FIREWALL" "HIGH" "WARN" "nftables/iptables not detected (firewalld may handle this)" "CIS 3.5.2"

ALLOWED_PORTS=(22 80 443)
if command -v ss &>/dev/null; then PORT_CMD="ss -tulnp"
elif command -v netstat &>/dev/null; then PORT_CMD="netstat -tulnp"
else PORT_CMD=""; fi

if [[ -n "$PORT_CMD" ]]; then
  while IFS= read -r line; do
    port=$(echo "$line" | grep -oP '(?<=:)\d+(?=\s)' | head -1)
    [[ -z "$port" ]] && continue
    process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
    is_allowed=false
    for a in "${ALLOWED_PORTS[@]}"; do [[ "$port" == "$a" ]] && is_allowed=true && break; done
    $is_allowed \
      && log_check "FW-PORT-${port}" "FIREWALL" "INFO" "PASS" "Port ${port} (${process}) — whitelisted" "CIS 3.5" \
      || log_check "FW-PORT-${port}" "FIREWALL" "HIGH" "WARN" "Port ${port} (${process}) — review if needed" "CIS 3.5"
  done < <($PORT_CMD 2>/dev/null | tail -n +2 | grep -v "^$")
fi

# =============================================================================
#  MODULE 4 — SYSTEM HARDENING
# =============================================================================
section_header "MODULE 4 — System Hardening"

selinux_status=$(getenforce 2>/dev/null || echo "Unknown")
if   [[ "$selinux_status" == "Enforcing"  ]]; then
  log_check "SYS-01" "SYSTEM" "CRITICAL" "PASS" "SELinux is Enforcing" "CIS 1.6.1.2"
elif [[ "$selinux_status" == "Permissive" ]]; then
  log_check "SYS-01" "SYSTEM" "CRITICAL" "FAIL" "SELinux is Permissive — policies not enforced!" "CIS 1.6.1.2"
else
  log_check "SYS-01" "SYSTEM" "CRITICAL" "FAIL" "SELinux is Disabled — major security gap!" "CIS 1.6.1.2"
fi

[[ "$(ulimit -c 2>/dev/null)" == "0" ]] \
  && log_check "SYS-02" "SYSTEM" "MEDIUM" "PASS" "Core dumps disabled" "CIS 1.5.1" \
  || log_check "SYS-02" "SYSTEM" "MEDIUM" "FAIL" "Core dumps enabled — may expose sensitive memory" "CIS 1.5.1"

aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
if   [[ "$aslr" == "2" ]]; then log_check "SYS-03" "SYSTEM" "HIGH" "PASS" "ASLR fully enabled (randomize_va_space=2)" "CIS 1.5.3"
elif [[ "$aslr" == "1" ]]; then log_check "SYS-03" "SYSTEM" "HIGH" "WARN" "ASLR partial (value=1) — recommend 2" "CIS 1.5.3"
else                            log_check "SYS-03" "SYSTEM" "HIGH" "FAIL" "ASLR disabled — exploit risk elevated!" "CIS 1.5.3"
fi

( systemctl is-active --quiet dnf-automatic 2>/dev/null || \
  systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null ) \
  && log_check "SYS-04" "SYSTEM" "MEDIUM" "PASS" "Automatic security updates (dnf-automatic) enabled" "CIS 1.9" \
  || log_check "SYS-04" "SYSTEM" "MEDIUM" "WARN" "dnf-automatic not active — consider enabling auto patches" "CIS 1.9"

mount | grep -q "on /tmp type" \
  && log_check "SYS-05" "SYSTEM" "MEDIUM" "PASS" "/tmp is on a separate filesystem" "CIS 1.1.2" \
  || log_check "SYS-05" "SYSTEM" "MEDIUM" "FAIL" "/tmp not on dedicated mount — noexec/nosuid cannot be enforced" "CIS 1.1.2"

ww_count=$(find /usr /bin /sbin /etc -xdev -type f -perm -002 2>/dev/null | wc -l)
[[ "$ww_count" -eq 0 ]] \
  && log_check "SYS-06" "SYSTEM" "HIGH" "PASS" "No world-writable files in system paths" "CIS 6.1.10" \
  || log_check "SYS-06" "SYSTEM" "HIGH" "FAIL" "${ww_count} world-writable file(s) in system paths — audit required!" "CIS 6.1.10"

systemctl is-active --quiet auditd 2>/dev/null \
  && log_check "SYS-07" "SYSTEM" "HIGH" "PASS" "auditd is running" "CIS 4.1.1" \
  || log_check "SYS-07" "SYSTEM" "HIGH" "FAIL" "auditd NOT running — system activity not being logged!" "CIS 4.1.1"

# =============================================================================
#  FINAL SCORE
# =============================================================================
section_header "SECURITY POSTURE SCORE"

PERCENT=0
[[ "$SCORE_MAX" -gt 0 ]] && PERCENT=$(( (SCORE_EARNED * 100) / SCORE_MAX ))

if   [[ "$PERCENT" -ge 90 ]]; then GRADE="A — Hardened"    ; GRADE_COLOR="$GREEN"
elif [[ "$PERCENT" -ge 75 ]]; then GRADE="B — Acceptable"  ; GRADE_COLOR="$CYAN"
elif [[ "$PERCENT" -ge 60 ]]; then GRADE="C — Needs Work"  ; GRADE_COLOR="$YELLOW"
else                                GRADE="D — At Risk"     ; GRADE_COLOR="$RED"
fi

SUMMARY="
  ┌─────────────────────────────────────────────────┐
  │  Checks Run      : ${TOTAL_CHECKS}
  │  Checks Passed   : ${PASSED_CHECKS}
  │  Weighted Score  : ${SCORE_EARNED} / ${SCORE_MAX} pts
  │  Security Score  : ${PERCENT}%
  │  Grade           : ${GRADE}
  │
  │  Reports saved to: ${REPORT_DIR}
  │    ├── bastion_report_${TIMESTAMP}.txt
  │    └── bastion_report_${TIMESTAMP}.csv
  └─────────────────────────────────────────────────┘"

echo -e "${GRADE_COLOR}${SUMMARY}${RESET}"
echo "$SUMMARY" >> "$REPORT_TXT"
echo "" >> "$REPORT_CSV"
echo "SUMMARY,,,,\"Checks: ${TOTAL_CHECKS} | Passed: ${PASSED_CHECKS} | Score: ${PERCENT}% | Grade: ${GRADE}\"," >> "$REPORT_CSV"

printf "\n${BOLD}${GREEN}  ✔  Audit complete.${RESET}\n\n"

