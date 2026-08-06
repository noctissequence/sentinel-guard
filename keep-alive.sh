#!/bin/bash
# ============================================================
# keep-alive.sh — WATCHDOG ULUNG (Pilar Q)
# Memastikan SEMUA layer tetap hidup:
#   1. crond daemon jalan (fondasi independensi)
#   2. sentinel di system crontab masih ada (self-register)
#   3. sentinel di Hermes cron masih ada (redundansi)
#   4. gateway secondary jalan
# Semua tanpa LLM — murni sistem.
# ============================================================
set -u
LOG="/var/log/sentinel-guard.log"
NOW=$(date +%s)
log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG" 2>/dev/null; }

# --- 1. Crond daemon ---
CROND_ALIVE=""
for pid in /proc/[0-9]*; do
    cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 60)
    case "$cmd" in
        *cron*|*crond*) CROND_ALIVE="yes" ;;
    esac
done
if [ -z "$CROND_ALIVE" ]; then
    /usr/sbin/cron 2>/dev/null
    log "keep-alive: crond daemon restarted"
fi

# --- 2. System crontab masih ada? ---
if ! crontab -l 2>/dev/null | grep -q "sentinel-guard.sh"; then
    ( crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/sentinel-guard.sh >/dev/null 2>&1" ) | crontab -
    log "keep-alive: system crontab sentinel re-registered"
fi
if ! crontab -l 2>/dev/null | grep -q "sentinel-guard-secondary"; then
    ( crontab -l 2>/dev/null; echo "*/2 * * * * SENTINEL_CONFIG=/etc/sentinel-guard-secondary/config.env /usr/local/bin/sentinel-guard.sh >/dev/null 2>&1" ) | crontab -
    log "keep-alive: system crontab secondary re-registered"
fi
if ! crontab -l 2>/dev/null | grep -q "keep-alive.sh"; then
    ( crontab -l 2>/dev/null; echo "*/5 * * * * /root/.hermes/scripts/keep-alive.sh >/dev/null 2>&1" ) | crontab -
    log "keep-alive: self re-registered"
fi

# --- 3. Hermes cron sentinel masih ada? ---
JOBS_FILE="/root/.hermes/cron/jobs.json"
if [ -f "$JOBS_FILE" ] && ! grep -q "sentinel-guard" "$JOBS_FILE" 2>/dev/null; then
    HERMES_HOME=/root/.hermes /usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main cron create \
        --name "sentinel-guard" --schedule "*/2 * * * *" --script sentinel-guard.sh --no-agent >/dev/null 2>&1 || true
    log "keep-alive: hermes cron sentinel re-registered"
fi

# --- 4. Gateway secondary ---
if [ -x /root/.hermes/scripts/restart-hermes-2.sh ]; then
    /root/.hermes/scripts/restart-hermes-2.sh >/dev/null 2>&1
fi

# --- 5. 9Router ---
if [ -x /root/.hermes/scripts/restart-router9.sh ]; then
    /root/.hermes/scripts/restart-router9.sh >/dev/null 2>&1
fi
if ! crontab -l 2>/dev/null | grep -q "restart-router9"; then
    ( crontab -l 2>/dev/null; echo "*/3 * * * * /root/.hermes/scripts/restart-router9.sh >/dev/null 2>&1" ) | crontab -
    log "keep-alive: system crontab router9-watch re-registered"
fi

exit 0
