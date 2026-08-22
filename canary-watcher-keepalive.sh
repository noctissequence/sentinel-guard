#!/bin/bash
# =============================================================================
# canary-watcher-keepalive.sh — Self-heal daemon canary inotify watcher.
# Start-if-not-running, pakai setsid (bukan background hermes) biar survive
# session exit. Cron tiap 2 menit. 100% shell, no LLM.
# =============================================================================
set -u
WATCH_SCRIPT=/etc/sentinel-guard/canary-token-watcher.sh
PIDFILE=/tmp/canary-watcher.pid
LOG=/var/log/sentinel-guard.log

is_alive() {
  [ -f "$PIDFILE" ] || return 1
  local pid; pid="$(cat "$PIDFILE" 2>/dev/null)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# sudah jalan? keluar
if is_alive; then
  exit 0
fi

# kill sisa kalau ada
if [ -f "$PIDFILE" ]; then
  OLD="$(cat "$PIDFILE" 2>/dev/null)"
  [ -n "$OLD" ] && kill "$OLD" 2>/dev/null
fi

# daemonize via setsid (survive session exit)
setsid "$WATCH_SCRIPT" --watch >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

sleep 2
if is_alive; then
  echo "[$(date -u '+%Y-%m-%d %H:%M:%S')] canary-watcher: started (pid $!)" >>"$LOG"
else
  echo "[$(date -u '+%Y-%m-%d %H:%M:%S')] canary-watcher: FAILED to start" >>"$LOG"
fi
exit 0
