# 01 – System Sentinel

System Sentinel is a Linux monitoring project designed to practice
how system administrators **observe, log, and respond** to common
system issues.

The focus is operational thinking — not just commands.

---

## Goals
- Monitor system health signals
- Log incidents safely
- Apply controlled recovery actions
- Capture system snapshots for analysis

---

## 🧩 Subproject: Sentinel-Watchdog

Sentinel-Watchdog is a Bash-based watchdog script that runs manually
or via cron to inspect system and security conditions.

---

##  Structure

sentinel-watchdog/
├── sentinel-watchdog.sh
├── config.conf
├── logs/
├── snapshots/
└── docs/




# ⚙️ Implemented Features

✔ Config-driven behavior  
✔ Lock file to prevent duplicate runs  
✔ Centralized logging  
✔ Service health checks  
✔ Disk usage monitoring  
✔ Memory & swap monitoring  
✔ SSH failed-login detection  
✔ System snapshot capture  

---

## Planned / Design-Only Ideas

- Advanced alerting (email / Slack)
- Predictive disk usage analysis
- SQLite-based incident storage
- Cloud metadata tagging

These are documented **as design concepts only**.

---

## How to Run

```bash
cd sentinel-watchdog
bash sentinel-watchdog.sh
