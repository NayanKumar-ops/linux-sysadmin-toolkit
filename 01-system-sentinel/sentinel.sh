#!/bin/bash

# THE LINUX SENTINEL 🛡️
# A Bash script to monitor system health and security automatically.

# 1. DEFINE COLORS (To make it look professional)
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

clear
echo -e "${CYAN}=====================================================${RESET}"
echo -e "${CYAN}   🛡️  THE LINUX SENTINEL - SYSTEM DASHBOARD  🛡️   ${RESET}"
echo -e "${CYAN}=====================================================${RESET}"
echo -e "Date: $(date)"
echo -e "Hostname: $(hostname)"
echo -e "-----------------------------------------------------"

# 2. CHECK DISK SPACE (Alert if usage > 80%)
DISK_USAGE=$(df -h / | grep / | awk '{ print $5 }' | sed 's/%//g')

if [ $DISK_USAGE -ge 80 ]; then
    echo -e "💾 DISK STATUS: ${RED}CRITICAL ($DISK_USAGE% used)${RESET}"
else
    echo -e "💾 DISK STATUS: ${GREEN}HEALTHY ($DISK_USAGE% used)${RESET}"
fi

# 3. CHECK RAM USAGE
FREE_RAM=$(free -m | grep Mem | awk '{print $4}')
echo -e "🧠 FREE RAM:    ${YELLOW}${FREE_RAM}MB${RESET}"

# 4. CPU LOAD CHECK
LOAD=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
echo -e "⚙️  CPU LOAD:    ${GREEN}${LOAD}%${RESET}"

echo -e "-----------------------------------------------------"

# 5. SECURITY CHECK: Count Failed Login Attempts (Last 10 entries)
# Note: This checks the secure log for 'Failed password'
echo -e "${YELLOW}🔒 SECURITY ALERT (Failed Logins):${RESET}"

if [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure | tail -n 5
    echo -e "${CYAN}Scan Complete.${RESET}"
else
    echo -e "${RED}Cannot read /var/log/secure (Run as Root!)${RESET}"
fi

echo -e "${CYAN}=====================================================${RESET}"
