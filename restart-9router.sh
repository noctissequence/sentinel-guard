#!/bin/bash
# ============================================================
# restart-router9.sh — Recovery: pastikan 9Router jalan di 20128
# Dipanggil sentinel kalau 9Router down / mati.
# ============================================================
export PATH="$HOME/.bun/bin:$PATH"
LOGF="/var/log/sentinel-guard.log"
log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOGF" 2>/dev/null; }

# Cek port 20128
if curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:20128/ 2>/dev/null | grep -qE "200|307|302"; then
    log "restart-router9: sudah jalan (HTTP OK)"
    exit 0
fi

# Cek proses router9
RUNNING=$(for pid in /proc/[0-9]*; do cmd=$(cat $pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 60); case "$cmd" in *router9*) echo yes;; esac; done 2>/dev/null | head -1)
if [ "$RUNNING" = "yes" ]; then
    log "restart-router9: proses ada tapi port mati — restart"
    pkill -f "router9" 2>/dev/null
    sleep 2
fi

# Start ulang
nohup /root/.bun/bin/bun run /root/.bun/bin/router9 --port 20128 --host 0.0.0.0 --tray > /root/router9.log 2>&1 &
sleep 5
if curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:20128/ 2>/dev/null | grep -qE "200|307|302"; then
    log "restart-router9: STARTED OK"
    echo "router9 restarted"
else
    log "restart-router9: START FAILED"
    echo "router9 START FAILED"
    exit 1
fi
