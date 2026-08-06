# Sentinel Guard — Super-Healer Watchdog

Independent system-level watchdog for Hermes Agent VPS. Runs WITHOUT LLM — pure shell + system cron.

## Version: v3.2 (2026-08-06)

- **Independent** — system crontab (not Hermes cron). Survives gateway death.
- **Self-heal** — script corrupt → auto-restore from backup.
- **Config watch** — config/.env/SOUL.md auto-restore if deleted/corrupted (anti-revoke).
- **Secret vault** — AES-256 encrypted backups, auto every 2min.
- **Core vault** — RSA-4096 asymmetric backup. Sentinel encrypts with public key; decrypt requires owner access code (private key sealed, plaintext removed from system).
- **Life-loop** — Yerin ↔ Merlin heartbeat recovery. One dies → other revives.
- **Keep-alive** — watchdog of watchdogs: restarts crond, re-registers crontab/Hermes-cron.
- **Anti-kill** — kill crond → keep-alive revives. Kill gateway secondary → restart-hermes-2 revives.

## Files

| File | Function |
|---|---|
| `sentinel.sh` | Main sentinel script (all pillars L-Q + R) |
| `core-vault.sh` | Core vault: RSA-4096 asymmetric backup (owner-gated) |
| `keep-alive.sh` | Watchdog ulung — keeps all layers alive |
| `restart-hermes-2.sh` | Revives secondary (Merlin) gateway |
| `sentinel-secondary-wrapper.sh` | Wrapper for secondary sentinel cron |
| `config.env.example` | Config template (secrets redacted) |

## Install

```bash
cp sentinel.sh /usr/local/bin/sentinel-guard.sh
cp core-vault.sh /root/.hermes/scripts/core-vault.sh
chmod +x /usr/local/bin/sentinel-guard.sh /root/.hermes/scripts/core-vault.sh
# System cron (independent layer)
crontab -e
# Add: * * * * * /usr/local/bin/sentinel-guard.sh
```

## Security

- All secrets redacted from repo (verified: 0 token/private-key matches in files AND git history).
- Config example ships with `[REDACTED]` placeholders.
- Core vault private key NEVER in repo — encrypted with owner access code, plaintext removed from system.
