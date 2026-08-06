#!/bin/bash
# ============================================================
# restart-hermes-2.sh — Recovery: pastikan gateway secondary jalan
# Dipanggil oleh sentinel Yerin kalau hermes-2.heartbeat stale,
# dan oleh system cron tiap 3 menit (layer independen).
#
# v2: deteksi gateway secondary via process scan + HERMES_HOME check,
#     jangan start duplikat kalau sudah jalan.
# ============================================================
LOG="/var/log/sentinel-guard.log"

# Cek proses gateway secondary (python -m hermes_cli.main gateway run
# dengan HERMES_HOME=/root/.hermes-secondary atau cwd hermes-secondary)
BUDAK_ALIVE=""
for pid in /proc/[0-9]*; do
    cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200)
    case "$cmd" in
        *hermes_cli.main*gateway*|*hermes*gateway*run*)
            # bedakan dari PID 1 (gateway utama) — cek environ HERMES_HOME
            envs=$(cat "$pid/environ" 2>/dev/null | tr '\0' ' ')
            if echo "$envs" | grep -q "hermes-secondary"; then
                BUDAK_ALIVE="yes"
                break
            fi
            ;;
    esac
done

if [ -z "$BUDAK_ALIVE" ]; then
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') restart-hermes-2: gateway secondary TIDAK jalan — starting..." >> "$LOG"
    # Bersihkan stale lock biar gateway bisa start
    rm -f /root/.hermes-secondary/gateway.lock /root/.hermes-secondary/gateway.pid 2>/dev/null
    # Start gateway secondary di background
    setsid /root/.hermes-secondary/start-secondary.sh > /root/.hermes-secondary/logs/gateway.log 2>&1 &
    disown || true
    sleep 3
    # Verifikasi
    VERIFY=""
    for pid in /proc/[0-9]*; do
        cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200)
        envs=$(cat "$pid/environ" 2>/dev/null | tr '\0' ' ')
        case "$cmd" in
            *hermes_cli.main*gateway*|*hermes*gateway*run*)
                if echo "$envs" | grep -q "hermes-secondary"; then
                    VERIFY="yes"
                fi
                ;;
        esac
    done
    if [ -n "$VERIFY" ]; then
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') restart-hermes-2: gateway secondary STARTED OK" >> "$LOG"
    else
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') restart-hermes-2: gateway secondary FAILED to start — see gateway.log" >> "$LOG"
    fi
else
    # Update heartbeat langsung (biar gak false-stale)
    date -u +%s > /root/hermes-shared/heartbeat/hermes-2.heartbeat 2>/dev/null
fi
