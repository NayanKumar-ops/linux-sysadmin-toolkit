# linux-sysadmin-toolkit

Shell-based tools for Linux system monitoring, security auditing, and hardening.
Built and tested on Rocky Linux (minimal install, no GUI) — real environment, not a simulator.

---

## Tools

### 01-system-sentinel
A production-style Linux monitoring tool that observes, logs, and responds to common system issues the way an actual sysadmin would. Focuses on building real visibility into system health and behavior.

### bastion/
Security auditing and hardening scripts for Rocky Linux bastion hosts.

| Script | Description |
|---|---|
| `bastion-audit.sh` | Runs structured CIS Benchmark-aligned security checks against a live system. Weighted scoring with dual TXT/CSV output. |

---

## Environment

| Detail | Value |
|---|---|
| OS | Rocky Linux (minimal, no GUI) |
| Shell | Bash |
| Target | Headless, terminal-only environments |

---

## Usage

**System Sentinel**
```bash
cd 01-system-sentinel
bash sentinel.sh
```

**Bastion Audit**
```bash
cd bastion
bash bastion-audit.sh
```



## Why I Built This

I'm self-teaching Linux sysadmin work toward the RHCSA. I built these tools because reading documentation only gets you so far — I wanted to actually practice what production sysadmin work looks like. Every script here runs on a real Rocky Linux minimal environment.

More tools in progress. Watch this space.

---

## Author

**NayanKumar-ops** build in public daily 
grind

