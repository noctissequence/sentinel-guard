# Sentinel Guard — Self-Healing Security Watchdog + Intrusion Detection

System-level security watchdog for Linux VPS/containers. Runs WITHOUT an LLM — pure Bash + system cron. Detects intrusions, blocks attacks, auto-heals services, and restores itself if tampered.

> ⚠️ **Scope note:** despite the compact name, this is a full intrusion-detection & hardening system (~1450 lines, 22 security modules), not a minimal 4-script watchdog. See [Modules](#modules) below.

## Highlights

- **Independent** — system crontab, not app cron. Survives agent/gateway death.
- **Self-heal** — script corrupt/tampered → auto-restore from backup (SHA-256 verified).
- **Intrusion detection** — port, SSH key, process (miner/reverse-shell), cron, file tripwire, auth brute-force, secret-permission, HTTP service, repo deface, cron-failure, anomaly (hunter) scans.
- **OSSEC/Fail2ban-style hardening** — file integrity monitoring (baseline hash+perm+owner on critical files), per-IP auth brute-force ban with auto-unban, rootkit-style rootcheck (setuid drift, hidden processes, promiscuous interfaces).
- **Auto-remediation (healer)** — quarantines defaced files, restores corrupted state, kills malicious processes, blocks rogue ports, purges unknown SSH keys, reverts attacker crons, restarts down services.
- **Secret vault** — AES-256 encrypted credential backups, auto every run.
- **Core vault** — RSA-4096 asymmetric backup. Encrypts with public key; decrypt requires owner access code (private key sealed, plaintext removed from system).
- **Life-loop** — Primary agent ↔ Secondary agent heartbeat recovery. One dies → other revives.
- **Keep-alive** — watchdog of watchdogs: restarts crond, re-registers crontab + app cron.
- **Anti-kill** — kill crond → keep-alive revives. Kill secondary gateway → restart-secondary revives.

## Architecture — 5 protection layers

```
L1  System cron (root)      →  runs sentinel every minute, survives everything
L2  Sentinel guard          →  scans + heals (this repo)
L3  Keep-alive              →  restarts crond, re-registers cron lines
L4  Restart scripts         →  revives secondary gateway + services
L5  Life-loop heartbeat     →  agent↔agent recovery
```

## Modules

| Module | What it does | Config |
|---|---|---|
| **Self-integrity (L)** | SHA-256 tamper check on own script → restore from backup | — |
| **Config watch (M)** | config/.env/soul file deleted/corrupted → auto-restore (anti-revoke) | — |
| **Secret vault (N)** | AES-256 encrypted credential backups | — |
| **Life-loop (O)** | heartbeat files, stale > threshold → alert + recovery | `LIFE_LOOP`, `LIFE_LOOP_PARTNER`, `LIFE_LOOP_MAX_AGE` |
| **Cron self-register (P)** | sentinel missing from app cron → re-register | — |
| **Core vault (R)** | RSA-4096 asymmetric backup, owner-gated restore | `core-vault.sh` |
| **GitHub monitor (S)** | polls configured repos (Atom feed) → author ≠ owner → alert (anti-deface) | `GITHUB_WATCH`, `GITHUB_REPOS` |
| **Cron failure watch** | reads app-cron execution DB → failed jobs in window → alert | — |
| **Hunter (T)** | anomaly scan: deface content, corrupt state/JSON, suspicious processes, dead tokens, rogue ports | `HUNTER_WATCH`, `WEB_ROOT_SCAN`, `HUNTER_PROC_PATTERNS` |
| **Healer (U)** | remediates hunter findings: quarantine deface, restore/backup corrupt, kill process, alert token/port | `HEALER_WATCH` |
| **FIM watch (V)** | file integrity monitoring: baseline sha256+perm+owner on critical files; change → tamper alert (OSSEC syscheck-style), optional auto-restore | `FIM_WATCH`, `FIM_FILES`, `FIM_UPDATE_BASELINE`, `FIM_AUTO_RESTORE` |
| **Auth ban watch (W)** | per-IP failed-login count in window → ban over threshold, auto-unban after ban time, IP whitelist (Fail2ban-style) | `AUTH_BAN_WATCH`, `BAN_MAXRETRY`, `BAN_FINDTIME`, `BAN_TIME`, `BAN_IP_WHITELIST` |
| **Rootcheck watch (X)** | setuid/setgid drift, persistent hidden processes, promiscuous interfaces (OSSEC rootcheck-style) | `ROOTCHECK_WATCH`, `ROOTCHECK_SETUID_WHITELIST`, `ROOTCHECK_PROMISC_WHITELIST` |
| **Port watch** | listener outside whitelist → auto-block + alert | `PORT_WATCH`, `PORT_WHITELIST`, `AUTO_BLOCK_PORTS` |
| **SSH key watch** | authorized_keys changed / unknown key → backup + purge | `SSH_WATCH`, `AUTO_PURGE_KEYS` |
| **Process watch** | miner / reverse-shell / suspicious procs → kill | `PROC_WATCH`, `AUTO_KILL_SUSPICIOUS` |
| **Cron watch** | cron modified/added by attacker → revert to baseline | `CRON_WATCH` |
| **File watch** | tripwire on .bashrc/.profile/authorized_keys | `FILE_WATCH`, `TRIPWIRE_FILES` |
| **Immutable watch** | chattr +i on critical files | `IMMUTABLE_WATCH`, `IMMUTABLE_FILES` |
| **Auth watch** | brute-force SSH attempts → auto-ban IP | `AUTH_WATCH`, `FAILED_THRESHOLD`, `AUTO_BAN_IP` |
| **Secret watch** | .env/config perms → enforce 0600 | `SECRET_WATCH`, `ENFORCE_600` |
| **HTTP watch** | container-aware: service down → restart via command | `HTTP_WATCH`, `HTTP_SERVICES`, `<NAME>_RESTART_CMD` |

## Files

| File | Function |
|---|---|
| `sentinel.sh` | Main sentinel — all pillars (L–X) + security modules (~1450 lines) |
| `core-vault.sh` | Core vault: RSA-4096 asymmetric backup (owner-gated) |
| `keep-alive.sh` | Watchdog of watchdogs — keeps crond + cron lines alive |
| `restart-router.sh` | Revives router service if down |
| `restart-secondary.sh` | Revives secondary agent gateway |
| `sentinel-secondary-wrapper.sh` | Wrapper for secondary sentinel cron |
| `config.env.example` | Config template (secrets redacted) |

## Install

```bash
cp sentinel.sh /usr/local/bin/sentinel-guard.sh
cp config.env.example /etc/sentinel-guard/config.env
# edit config.env — set TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, whitelists
chmod +x /usr/local/bin/sentinel-guard.sh

# System cron (independent layer — survives app restarts)
crontab -e
# Add: * * * * * /usr/local/bin/sentinel-guard.sh

# Optional secondary sentinel (runs with separate config)
# Add: */2 * * * * SENTINEL_CONFIG=/etc/sentinel-guard-secondary/config.env /usr/local/bin/sentinel-guard.sh
```

Manual run (debug):

```bash
bash /usr/local/bin/sentinel-guard.sh        # one full scan cycle
bash -x /usr/local/bin/sentinel-guard.sh     # trace mode
tail -f /var/log/sentinel-guard.log          # watch activity
```

Emergency restore:

```bash
# Owner-gated restore from RSA-encrypted core vault
./core-vault.sh status
./core-vault.sh restore <name> <access-code>
```

## Requirements

- Linux (tested on Debian/Ubuntu containers)
- `cron`, `curl`, `sha256sum`, `md5sum` (standard)
- `python3` (for JSON validation in hunter scans) — must be on PATH for cron jobs
- Telegram bot token + chat ID for alerts (optional but recommended)

## Configuration

Copy `config.env.example` → `/etc/sentinel-guard/config.env`. Every module can be toggled on/off. Values:

- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` — alert destination
- `PORT_WHITELIST` — space-separated allowed ports (22 80 443 …)
- `HTTP_SERVICES` — `"name|url|expected_code"` list, `<NAME>_RESTART_CMD` per service
- `GITHUB_REPOS` — `owner/repo` list to monitor for deface
- `LIFE_LOOP_PARTNER` / `SENTINEL_IDENTITY` — heartbeat identities
- `FIM_FILES` — space-separated critical files for integrity baseline
- `BAN_MAXRETRY` / `BAN_FINDTIME` / `BAN_TIME` — per-IP auth-ban policy (Fail2ban-style)
- `BAN_IP_WHITELIST` — IPs never auto-banned (Fail2ban `ignoreip`)
- `FIM_AUTO_RESTORE` — `on` → restore tampered FIM file from backup (OSSEC-style)
- `ROOTCHECK_PROMISC_WHITELIST` — interfaces exempt from promiscuous check

> 💡 **Alert-only first:** `AUTO_LOCKDOWN`, `AUTO_BLOCK_PORTS`, `AUTO_PURGE_KEYS`, `AUTO_KILL_SUSPICIOUS`, `AUTO_BAN_IP` are active by default. If you want to observe before acting, set them `off` and keep the watch on.

## Security

- All secrets redacted from repo (verified: 0 token/private-key matches in files AND git history).
- Config example ships with `[REDACTED]` placeholders.
- Core vault private key NEVER in repo — encrypted with owner access code, plaintext removed from system.
- Logs are rotated; no secrets are written to logs.
- State dir + lock file hardened against `/tmp` symlink races (mode 700, anti-symlink).

## Testing

```bash
bash tests/run_tests.sh
```

Automated suite (no LLM, pure shell) covering: syntax (`bash -n` on every script), secret scrub (0 personal language / token / internal codename / port), anti-injection pattern (`$()` blocked in restart hooks), FIM baseline + tamper detection + restore, auth-ban per-IP counting + whitelist, rootcheck setuid drift, and `/tmp` race hardening. All tests use an isolated temp state dir — safe to run on a live host.

## Status

v3.5 (2026-08-08) — production-tested on container VPS. Modules: L,M,N,O,P,R,S,T,U + FIM (V), AuthBan (W), Rootcheck (X) + v2.0–v2.6 security modules. Design patterns borrowed from OSSEC / Wazuh / Fail2ban (all GPL — concepts reimplemented from scratch, no copied code). Hardened: anti-command-injection on restart hooks, `/tmp` symlink-race protection, journald auth-log fallback, IP whitelist + firewall-missing alert on auth-ban, FIM auto-restore, promiscuous-interface whitelist. 17/17 automated tests pass.
