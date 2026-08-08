#!/bin/bash
# ============================================================
# restart-router.sh — Recovery: pastikan router service
# Dipanggil sentinel kalau router down / mati.
# ============================================================
export PATH="$HOME/.bun/bin:$PATH"
LOGF="/var/log/sentinel-guard.log"
log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOGF" 2>/dev/null; }

# Cek port router
if curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:${ROUTER_PORT}/ 2>/dev/null | grep -qE "200|307|302"; then
    log "restart-router: sudah jalan (HTTP OK)"
    exit 0
fi

# Cek proses router
RUNNING=$(for pid in /proc/[0-9]*; do cmd=$(cat $pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 60); case "$cmd" in *router*) echo yes;; esac; done 2>/dev/null | head -1)
if [ "$RUNNING" = "yes" ]; then
    log "restart-router: proses ada tapi port mati — restart"
    pkill -f "router" 2>/dev/null
    sleep 2
fi

# Start ulang
nohup /root/.bun/bin/bun run /root/.bun/bin/router --port ${ROUTER_PORT} --host 0.0.0.0 --tray > /var/log/router.log 2>&1 &
sleep 5
if curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:${ROUTER_PORT}/ 2>/dev/null | grep -qE "200|307|302"; then
    log "restart-router: STARTED OK"
    echo "router restarted"
else
    log "restart-router: START FAILED"
    echo "router START FAILED"
    exit 1
fi
