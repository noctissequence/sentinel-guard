#!/bin/bash
# =============================================================================
# canary-token-watcher.sh — Deteksi akses BACA ke file umpan (honeytoken).
#
# Tujuan :
#   Menangkap attacker yang MEMBACA file umpan (canary) di lokasi menarik.
#   Sentinel-guard udah bisa deteksi file BERUBAH (hash mtime), TAPI gak bisa
#   deteksi file yang DI-BACA. Ini ngenain gap itu lewat inotify (kernel).
#
# Prinsip :
#   * 100% shell + inotifywait. ZERO LLM / AI decision. Deterministic.
#   * File canary di /etc/sentinel-guard/canary/ (BUKAN path production) demi
#     hindari boomerang: watchdog/cron legit gak bakal sentuh folder ini.
#   * akses READ -> log + buka state flag biar sentinel hunter baca & lapor.
#
# Cara pakai (cron):
#   * * * * * /etc/sentinel-guard/canary-token-watcher.sh --check
#   (daemon: bash canary-token-watcher.sh --watch  # jalan mulus via setsid)
#
# Create: 2026-08-22  sentinel-guard maintainers
# =============================================================================
set -u

CANARY_DIR="${CANARY_DIR:-/etc/sentinel-guard/canary}"
STATE_DIR="${SENTINEL_STATE:-/tmp/hermes-sentinel}"
FLAG="$STATE_DIR/canary_state/canary_alert.txt"
LOG="${CANARY_LOG:-/var/log/sentinel-guard.log}"
HUNTER_STATE="$STATE_DIR/hunter_state"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] canary: $*" >> "$LOG" 2>/dev/null; }

# --- buat file canary (sekali init) -----------------------------------------
canary_init() {
  mkdir -p "$CANARY_DIR" 2>/dev/null
  # Umpan 1: kredensial palsu keliatan valid
  if [ ! -f "$CANARY_DIR/canary_credentials.json" ]; then
    cat > "$CANARY_DIR/canary_credentials.json" <<'EOF'
{
  "host": "localhost",
  "user": "postgres",
  "password": "honey_do_not_use_8f3a91",
  "warning": "THIS IS A HONEYPOT. ANY USE = INTRUSION DETECTED."
}
EOF
    chmod 600 "$CANARY_DIR/canary_credentials.json"
  fi
  # Umpan 2: backup konfigurasi palsu
  if [ ! -f "$CANARY_DIR/config_old.yaml" ]; then
    printf '# legacy config snapshot\napi_key: sk-honey_do_not_use_e7c21b\n' > "$CANARY_DIR/config_old.yaml"
    chmod 600 "$CANARY_DIR/config_old.yaml"
  fi
  # Umpan 3: env backup palsu
  if [ ! -f "$CANARY_DIR/.env.backup" ]; then
    printf 'SECRET_HONEY=do_not_use_4b9d0c\n' > "$CANARY_DIR/.env.backup"
    chmod 600 "$CANARY_DIR/.env.backup"
  fi
  log "canary init: buat umpan di $CANARY_DIR"
}

# --- triggered flag (dipakai mode --check / sentinel hunter) -----------------
flag_read() {
  mkdir -p "$(dirname "$FLAG")" "$HUNTER_STATE" 2>/dev/null
  local src="$1"
  {
    echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "file=$src"
    echo "proc=canary-inotify"
    ss -tnp 2>/dev/null | grep -iE 'ESTAB|SYN' | head -5
    echo "--"
  } > "$FLAG"
  # tampar juga ke hunter findings biar dashboard K2 / sentinel lapor
  echo "CANARY|medium|canary file read: $src $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$HUNTER_STATE/findings.txt" 2>/dev/null
  log "ALERT triggered dari BACA $src"
}

# --- daemon watch (mode utama) ----------------------------------------------
canary_watch() {
  canary_init
  if ! command -v inotifywait >/dev/null 2>&1; then
    log "ERROR: inotify-tools tidak terpasang (apt-get install inotify-tools)"
    exit 1
  fi
  log "watch aktif: $CANARY_DIR (inotifywait -e access)"
  # loop mulus: inotifywait sekali-sekali (bukan -m) biar gak makan CPU
  while true; do
    inotifywait -q -e access -e open --format '%w%f|%e' "$CANARY_DIR" 2>/dev/null
    try_read="$(ls "$CANARY_DIR" 2>/dev/null | head -1)"
    if [ -n "$try_read" ]; then
      flag_read "$CANARY_DIR"
    fi
    sleep 1
  done
}

# --- mode check (cron) : lapor flag yang ada ---------------------------------
canary_check() {
  if [ -f "$FLAG" ]; then
    log "PENDING canary alert (flag terdeteksi)"
    cat "$FLAG"
    return 0
  fi
  return 0
}

# --- main ---------------------------------------------------------------------
case "${1:-}" in
  --watch) canary_watch ;;
  --check) canary_check ;;
  --init)  canary_init ;;
  *)
    echo "Usage: $0 {--watch|--check|--init}"
    exit 1
    ;;
esac
exit 0
