# Sentinel-Watchdog – Design Notes

This document captures future improvement ideas and architectural reasoning.
Features listed here are **not implemented in v1.0** and are planned for later iterations.

## Planned Enhancements (Future Scope)
- **Alerting Integration:** Add optional Slack or Email alerts (mailx) for critical events.
- 
- **Persistent Storage:** Explore storing logs in SQLite for long-term trend analysis.
- 
- **Predictive Monitoring:** Prototype Python-based scripts to analyze disk growth patterns.
- 
- **Active Defense (Optional):** Investigate auto-blocking IPs via firewalld after repeated SSH failures.

## Architectural Decisions
- **Why Bash?** Selected for portability and zero external dependencies on minimal Linux systems.
- 
- **Why Lockfiles?** Used to prevent concurrent executions when triggered by Cron.
- 
- **Why Config Files?** Enables safe tuning without modifying core logic.

These notes exist to document design thinking and guide potential v2.0 development.
