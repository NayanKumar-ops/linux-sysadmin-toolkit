# Linux-SysAdmin-Toolkit

A collection of shell-based tools for Linux system monitoring, security auditing, and hardening — built and tested on Rocky Linux (minimal, no GUI).



## Tools

## 01-system-sentinel
A Linux monitoring tool designed to observe, log, and respond to common system issues the way a real sysadmin would. Focuses on building practical visibility into system health and behavior.

### bastion
Security auditing and hardening scripts for Rocky Linux bastion hosts. Includes `bastion-audit.sh` for running structured security checks against a live system.

---

## Environment

- OS: Rocky Linux (minimal install, no GUI)
- Shell: Bash
- All tools are designed for headless, terminal-only environments

---

## Usage

**Run system-sentinel:**
```bash
cd 01-system-sentinel
bash sentinel.sh
```

**Run bastion audit:**
```bash
cd bastion
bash bastion-audit.sh
```

---

## Why I Built This

I am a self-taught Linux sysadmin working toward RHCSA. I built these tools to go beyond reading documentation — to actually practice what production sysadmin work looks like. Everything here runs on a real Rocky Linux minimal environment, not a simulator.

--

## Author

**NayanKumar-ops**  
