#!/bin/bash
# ============================================================
# sentinel.sh — SECOND-LINE DEFENSE v2.0 (HARDENED)
# PERSONAL PRODUCTION (PRODUCTION VPS, post-incident 2026-08-06)
#
# Guards:
#   1. systemd units (restart if dead, crash-loop detect)
#   2. JSON state file validation (corrupt -> backup + reset)
#   3. NEW: PORT EXPOSURE — service baru listen 0.0.0.0 tanpa auth
#      (root cause insiden 8765/postdraft) -> alert + auto-block
#   4. NEW: SSH KEY WATCH — authorized_keys berubah / key baru
#      di /root/.ssh -> alert + backup + hapus
#   5. NEW: PROCESS WATCH — reverse shell / miner / suspicious
#      (nc, ncat, socat, xmrig, minerd, /dev/tcp)
#   6. NEW: CRON/USER WATCH — cron baru, user baru, sudoers berubah
#   7. NEW: FILE INTEGRITY — tripwire hash file kritis
#   8. NEW: AUTO-LOCKDOWN — kalau terdeteksi intrusi, langsung
#      blokir semua port masuk kecuali whitelist + kill proses
#
# Mode: silent saat sehat. ALERT + LOCKDOWN saat ada anomali.
# Config: /etc/sentinel-guard/config.env
# ============================================================

set -u

CONFIG="${SENTINEL_CONFIG:-/etc/sentinel-guard/config.env}"
if [ ! -f "$CONFIG" ]; then
    echo "sentinel: config not found at $CONFIG" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$CONFIG"

# --- locking ---
LOCK_FILE="${SENTINEL_LOCK_FILE:-/tmp/sentinel-guard.lock}"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    exit 0
fi

# --- defaults ---
CRASH_THRESHOLD="${CRASH_THRESHOLD:-3}"
CRASH_WINDOW_SEC="${CRASH_WINDOW_SEC:-600}"
CASCADE_THRESHOLD="${CASCADE_THRESHOLD:-3}"
STATE_DIR="${SENTINEL_STATE_DIR:-/tmp/hermes-sentinel}"
mkdir -p "$STATE_DIR"
LOG_FILE="${SENTINEL_LOG_FILE:-/var/log/sentinel-guard.log}"

for _var in CRASH_THRESHOLD CRASH_WINDOW_SEC CASCADE_THRESHOLD; do
    _val="${!_var:-}"
    if ! [[ "$_val" =~ ^[0-9]+$ ]]; then
        echo "sentinel: config error — $_var harus angka, dapat: '$_val'" >&2
        exit 1
    fi
done

NOW=$(date +%s)

# --- bot token ---
if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ "$TELEGRAM_BOT_TOKEN" = "YOUR_BOT_TOKEN" ]; then
    TELEGRAM_BOT_TOKEN=$(grep -E "^TELEGRAM_BOT_TOKEN=" /root/.hermes/.env 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'")
fi
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "sentinel: TELEGRAM_BOT_TOKEN not configured" >&2
    exit 1
fi

send_alert() {
    if ! curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$1" \
        --max-time 10 > /dev/null 2>&1; then
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') sentinel: ALERT SEND FAILED: $1" >> "$LOG_FILE" 2>/dev/null
    fi
}

PROBLEMS=""

# ============================================================
# MODULE A: CASCADE + systemd units (existing, guard if systemctl exists)
# ============================================================
if command -v systemctl > /dev/null 2>&1; then
    read -r -a WATCH_UNITS_ARR <<< "$WATCH_UNITS"
    DOWN_COUNT=0
    for u in "${WATCH_UNITS_ARR[@]}"; do
        if [ "$(systemctl is-active "$u" 2>/dev/null)" != "active" ]; then
            DOWN_COUNT=$((DOWN_COUNT + 1))
        fi
    done

    if [ "$DOWN_COUNT" -ge "$CASCADE_THRESHOLD" ]; then
        PROBLEMS="${PROBLEMS}💥 CASCADE DETECTED (${DOWN_COUNT} unit down) — recovery orchestrator triggered\\n"
        ORCH_LOCK="/tmp/recovery-orchestrator.lock"
        if mkdir "$ORCH_LOCK" 2>/dev/null; then
            nohup /root/.hermes/scripts/recovery-orchestrator.sh >> /var/log/recovery-orchestrator.log 2>&1 &
            ( sleep 300; rmdir "$ORCH_LOCK" 2>/dev/null ) &
        fi
        MSG="🛰️ SENTINEL ALERT
$(echo -e "$PROBLEMS")"
        send_alert "$MSG"
        exit 0
    fi

    for u in "${WATCH_UNITS_ARR[@]}"; do
        ACTIVE=$(systemctl is-active "$u" 2>/dev/null)
        if [ "$ACTIVE" != "active" ]; then
            COUNT_FILE="$STATE_DIR/restart_count_${u}.txt"
            LAST_FILE="$STATE_DIR/restart_last_${u}.txt"
            COUNT=$(cat "$COUNT_FILE" 2>/dev/null || echo 0)
            LAST=$(cat "$LAST_FILE" 2>/dev/null || echo 0)
            if [ $((NOW - LAST)) -gt "$CRASH_WINDOW_SEC" ]; then
                COUNT=0
            fi
            COUNT=$((COUNT + 1))
            echo "$COUNT" > "$COUNT_FILE"
            echo "$NOW" > "$LAST_FILE"
            if [ "$COUNT" -ge "$CRASH_THRESHOLD" ]; then
                PROBLEMS="${PROBLEMS}🔴 ${u} crash-loop (${COUNT}x/${CRASH_WINDOW_SEC}s) — manual check\\n"
                continue
            fi
            systemctl restart "$u" 2>/dev/null
            sleep 2
            if [ "$(systemctl is-active "$u" 2>/dev/null)" = "active" ]; then
                PROBLEMS="${PROBLEMS}🟡 ${u} was down → restarted OK\\n"
            else
                PROBLEMS="${PROBLEMS}🔴 ${u} down & RESTART FAILED\\n"
            fi
        fi
    done
fi

# ============================================================
# MODULE B: JSON state file validation (existing)
# ============================================================
for f in $STATE_FILES; do
    if [ -f "$f" ]; then
        if ! python3 -c "import json; json.load(open('$f'))" 2>/dev/null; then
            cp "$f" "${f}.corrupt.$(date +%s)" 2>/dev/null
            BASENAME=$(basename "$f")
            case "$BASENAME" in
                *blacklist*|*signals*|*positions*|*wallets*) echo "[]" > "$f" ;;
                *) echo "{}" > "$f" ;;
            esac
            PROBLEMS="${PROBLEMS}♻️ state corrupt → backed up + reset: ${f}\\n"
        fi
    fi
done

# ============================================================
# MODULE C: PORT EXPOSURE WATCH (NEW — root cause fix)
# Service baru listen di 0.0.0.0/:: tanpa whitelist = bahaya
# (insiden: postdraft 8765 serve seluruh home dir tanpa auth)
# ============================================================
PORT_LOCKDOWN=false
if [ "${PORT_WATCH:-on}" = "on" ]; then
    # Whitelist: port yang memang sengaja dibuka (SSH, HTTP(S), dll)
    PORT_WHITELIST="${PORT_WHITELIST:-22 80 443}"
    # Snapshot port sekarang — pakai ss kalau ada, fallback /proc/net/tcp
    if command -v ss > /dev/null 2>&1; then
        CURRENT_PORTS=$(ss -tln 2>/dev/null | awk 'NR>1 {print $4}' | sed 's/.*://' | sort -u | tr '\n' ' ')
    else
        # /proc/net/tcp fallback — bash murni, tanpa strtonum (mawk gak dukung)
        CURRENT_PORTS=""
        for HEXPORT in $(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk 'NR>1 && $4=="0A" {split($2,a,":"); print a[2]}' | sort -u); do
            DECPORT=$((16#$HEXPORT))
            CURRENT_PORTS="$CURRENT_PORTS$DECPORT "
        done
    fi
    PREV_FILE="$STATE_DIR/known_ports.txt"
    PREV_PORTS=$(cat "$PREV_FILE" 2>/dev/null || echo "")
    if [ -n "$PREV_PORTS" ] && [ "$CURRENT_PORTS" != "$PREV_PORTS" ]; then
        for p in $CURRENT_PORTS; do
            if ! echo "$PREV_PORTS" | grep -qw "$p" && ! echo "$PORT_WHITELIST" | grep -qw "$p"; then
                # Check: ini port baru yang listen di semua interface?
                NEW_BIND=""
                if command -v ss > /dev/null 2>&1; then
                    NEW_BIND=$(ss -tln 2>/dev/null | grep -E ":$p\b" | grep -E "0.0.0.0|\*|::" | head -1)
                else
                    # /proc fallback: cek local addr != 127.0.0.1 (0100007F) dan != ::1
                    HEXP=$(printf '%04X' "$p")
                    NEW_BIND=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v hp="$HEXP" 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]==hp && index(a[1],"0100007F")!=1 && index(a[1],"00000000000000000000000001000000")!=1) print $2}')
                fi
                if [ -n "$NEW_BIND" ]; then
                    PROBLEMS="${PROBLEMS}🚨 NEW PORT ${p} exposed on ALL interfaces!\\n"
                    PORT_LOCKDOWN=true
                    if [ "${AUTO_BLOCK_PORTS:-on}" = "on" ] && command -v ufw > /dev/null 2>&1; then
                        ufw deny "$p"/tcp > /dev/null 2>&1 && PROBLEMS="${PROBLEMS}🛡️ Port ${p} AUTO-BLOCKED via UFW\\n"
                    fi
                fi
            fi
        done
    fi
    echo "$CURRENT_PORTS" > "$PREV_FILE"
fi

# ============================================================
# MODULE D: SSH KEY WATCH (NEW — key bocor tidak cukup, key baru = bahaya)
# ============================================================
if [ "${SSH_WATCH:-on}" = "on" ]; then
    # authorized_keys hash
    AK="/root/.ssh/authorized_keys"
    if [ -f "$AK" ]; then
        AK_HASH=$(md5sum "$AK" 2>/dev/null | awk '{print $1}')
        AK_PREV=$(cat "$STATE_DIR/authorized_keys.hash" 2>/dev/null || echo "")
        if [ -n "$AK_PREV" ] && [ "$AK_HASH" != "$AK_PREV" ]; then
            # Backup dulu, lalu kosongkan (kunci baru tidak dikenal = potensi intrusi)
            cp "$AK" "$STATE_DIR/authorized_keys.$(date +%s).bak" 2>/dev/null
            PROBLEMS="${PROBLEMS}🚨 authorized_keys BERUBAH! Backup → ${STATE_DIR}/...\\n"
            if [ "${AUTO_PURGE_KEYS:-on}" = "on" ]; then
                : > "$AK"  # kosongkan — tidak ada key yang diizinkan otomatis
                chmod 600 "$AK"
                PROBLEMS="${PROBLEMS}🛡️ authorized_keys di-kosongkan (AUTO-PURGE)\\n"
            fi
            PORT_LOCKDOWN=true
        fi
        echo "$AK_HASH" > "$STATE_DIR/authorized_keys.hash"
    fi

    # Key baru di /root/.ssh (file *.pub / id_* baru)
    SSH_KEY_COUNT=$(find /root/.ssh -maxdepth 1 -type f \( -name "*.pub" -o -name "id_*" \) 2>/dev/null | wc -l)
    KEY_PREV=$(cat "$STATE_DIR/ssh_key_count.txt" 2>/dev/null || echo "")
    if [ -n "$KEY_PREV" ] && [ "$SSH_KEY_COUNT" != "$KEY_PREV" ]; then
        PROBLEMS="${PROBLEMS}🚨 Jumlah SSH key di /root/.ssh berubah: ${KEY_PREV} → ${SSH_KEY_COUNT}\\n"
        PORT_LOCKDOWN=true
    fi
    echo "$SSH_KEY_COUNT" > "$STATE_DIR/ssh_key_count.txt"
fi

# ============================================================
# MODULE E: PROCESS WATCH (NEW — reverse shell / miner)
# ============================================================
if [ "${PROC_WATCH:-on}" = "on" ]; then
    SUSPICIOUS=$(for pid in /proc/[0-9]*; do
        cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200)
        case "$cmd" in
            *nc\ *|*ncat*|*socat*|*xmrig*|*minerd*|*cpuminer*|*kdevtmpfsi*|*kinsing*|*/dev/tcp*|*bash*-i*|*pty.spawn*|*sh*-i*)
                echo "PID $(basename "$pid"): $cmd" ;;
        esac
    done)
    if [ -n "$SUSPICIOUS" ]; then
        PROBLEMS="${PROBLEMS}🚨 PROSES MEN CURIGAKAN:\\n$SUSPICIOUS\\n"
        if [ "${AUTO_KILL_SUSPICIOUS:-on}" = "on" ]; then
            for pid in /proc/[0-9]*; do
                cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200)
                case "$cmd" in
                    *xmrig*|*minerd*|*cpuminer*|*kdevtmpfsi*|*kinsing*)
                        kill -9 "$(basename "$pid")" 2>/dev/null
                        PROBLEMS="${PROBLEMS}🛡️ Killed miner PID $(basename "$pid")\\n"
                        ;;
                esac
            done
            PORT_LOCKDOWN=true
        fi
    fi
fi

# ============================================================
# MODULE F: CRON / USER / SUDOERS WATCH (NEW)
# ============================================================
if [ "${CRON_WATCH:-on}" = "on" ]; then
    CRON_SNAP=$( (crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null | grep -v '^#' | grep -v '^$'; ls /etc/cron.d/ 2>/dev/null) | md5sum | awk '{print $1}' )
    CRON_PREV=$(cat "$STATE_DIR/cron.hash" 2>/dev/null || echo "")
    if [ -n "$CRON_PREV" ] && [ "$CRON_SNAP" != "$CRON_PREV" ]; then
        PROBLEMS="${PROBLEMS}🚨 CRON berubah! (crontab / etc/cron.d)\\n"
        PORT_LOCKDOWN=true
    fi
    echo "$CRON_SNAP" > "$STATE_DIR/cron.hash"

    USER_SNAP=$(awk -F: '$3>=1000 || $3==0 {print $1":"$3}' /etc/passwd 2>/dev/null | md5sum | awk '{print $1}')
    USER_PREV=$(cat "$STATE_DIR/users.hash" 2>/dev/null || echo "")
    if [ -n "$USER_PREV" ] && [ "$USER_SNAP" != "$USER_PREV" ]; then
        PROBLEMS="${PROBLEMS}🚨 USER ACCOUNTS berubah! (/etc/passwd)\\n"
        PORT_LOCKDOWN=true
    fi
    echo "$USER_SNAP" > "$STATE_DIR/users.hash"

    if [ -f /etc/sudoers ]; then
        SUDO_HASH=$(md5sum /etc/sudoers 2>/dev/null | awk '{print $1}')
        SUDO_PREV=$(cat "$STATE_DIR/sudoers.hash" 2>/dev/null || echo "")
        if [ -n "$SUDO_PREV" ] && [ "$SUDO_HASH" != "$SUDO_PREV" ]; then
            PROBLEMS="${PROBLEMS}🚨 /etc/sudoers BERUBAH!\\n"
            PORT_LOCKDOWN=true
        fi
        echo "$SUDO_HASH" > "$STATE_DIR/sudoers.hash"
    fi
fi

# ============================================================
# MODULE G: FILE INTEGRITY (NEW — tripwire)
# ============================================================
if [ "${FILE_WATCH:-on}" = "on" ]; then
    TRIPWIRE_FILES="${TRIPWIRE_FILES:-/root/.bashrc /root/.profile /root/.ssh/authorized_keys /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config}"
    for f in $TRIPWIRE_FILES; do
        [ -f "$f" ] || continue
        HASH=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        STATE_FILE="$STATE_DIR/tripwire_$(echo "$f" | tr '/' '_').hash"
        PREV=$(cat "$STATE_FILE" 2>/dev/null || echo "")
        if [ -n "$PREV" ] && [ "$HASH" != "$PREV" ]; then
            PROBLEMS="${PROBLEMS}🚨 FILE BERUBAH: ${f}\\n"
            PORT_LOCKDOWN=true
        fi
        echo "$HASH" > "$STATE_FILE"
    done
fi

# ============================================================
# MODULE H: AUTO-LOCKDOWN (NEW — response terakhir)
# Kalau terdeteksi intrusi: blokir SEMUA port masuk kecuali whitelist.
# Walaupun attacker pegang SSH key, kalau port 22 juga diblock dia
# tetap nggak bisa masuk — ini "nggak bisa akses apa pun".
# ============================================================
if [ "$PORT_LOCKDOWN" = "true" ] && [ "${AUTO_LOCKDOWN:-on}" = "on" ]; then
    if command -v ufw > /dev/null 2>&1; then
        # Simpan state sebelum lockdown biar bisa dipulihkan manual
        ufw status numbered > "$STATE_DIR/ufw_before_lockdown.txt" 2>/dev/null
        # Default deny semua incoming
        ufw default deny incoming 2>/dev/null
        # Hanya izinkan whitelist
        for p in ${PORT_WHITELIST:-22 80 443}; do
            ufw allow "$p"/tcp 2>/dev/null
        done
        PROBLEMS="${PROBLEMS}🔒 AUTO-LOCKDOWN ACTIVE: semua port diblokir kecuali whitelist\\n"
    fi
    # Lockdown marker — sentinel tidak restart service di mode ini
    touch "$STATE_DIR/LOCKDOWN_ACTIVE"
else
    rm -f "$STATE_DIR/LOCKDOWN_ACTIVE" 2>/dev/null
fi

# ============================================================
# MODULE I: FILE IMMUTABILITY (NEW — key yang bocor pun tidak cukup)
# File kritis di-chattr +i (immutable): tidak bisa diubah/dihapus
# bahkan oleh root. Attacker yang dapat SSH key tetap tidak bisa
# mengubah .env, auth.json, config.yaml, SOUL.md, sentinel.sh.
# Module ini: (1) apply immutable flags, (2) verify flag tetap ada.
# NOTE: chattr +i butuh CAP_LINUX_IMMUTABLE — TIDAK ada di Docker
# container default. Di container: probe dulu, kalau tidak didukung
# skip module (tanpa alert). Di VPS host: aktif penuh.
# ============================================================
if [ "${IMMUTABLE_WATCH:-on}" = "on" ]; then
    # Probe: apakah environment mendukung chattr +i?
    _PROBE="/tmp/.sentinel_immutable_probe"
    echo "probe" > "$_PROBE" 2>/dev/null
    chattr +i "$_PROBE" 2>/dev/null
    if lsattr "$_PROBE" 2>/dev/null | grep -q '^[-A-Za-z]*i'; then
        # Environment SUPPORT chattr — apply ke semua file kritis
        IMMUTABLE_FILES="${IMMUTABLE_FILES:-/root/.hermes/.env /root/.hermes/auth.json /root/.hermes/config.yaml /root/.hermes/SOUL.md /root/.hermes/scripts/sentinel.sh /etc/sentinel-guard/config.env}"
        for f in $IMMUTABLE_FILES; do
            [ -f "$f" ] || continue
            # Apply immutable flag (idempotent)
            chattr +i "$f" 2>/dev/null || true
            # Verify flag masih ada
            if lsattr "$f" 2>/dev/null | grep -q '^[-A-Za-z]*i'; then
                # Immutable OK — no action
                :
            else
                # Flag hilang = ada yang coba hapus immutable
                PROBLEMS="${PROBLEMS}🚨 IMMUTABLE FLAG HILANG: ${f} (ada yang coba ubah!)\\n"
                PORT_LOCKDOWN=true
                # Re-apply
                chattr +i "$f" 2>/dev/null && PROBLEMS="${PROBLEMS}🛡️ Immutable re-applied: ${f}\\n"
            fi
        done
    else
        # Container tanpa CAP_LINUX_IMMUTABLE — chattr tidak didukung.
        # JANGAN alert (bukan serangan, tapi limit environment).
        # Tercatat di log sekali (state file) biar operator tahu.
        if [ ! -f "$STATE_DIR/immutable_unsupported.marker" ]; then
            echo "Immutable module SKIP — environment tidak support chattr +i (Docker container)" >> "$LOG_FILE" 2>/dev/null
            touch "$STATE_DIR/immutable_unsupported.marker"
        fi
    fi
    chattr -i "$_PROBE" 2>/dev/null
    rm -f "$_PROBE" 2>/dev/null
fi

# ============================================================
# MODULE J: AUTH LOG WATCH (NEW — brute force / login mencurigakan)
# Pantau failed login & login baru. Kalau ada banyak failed login
# = serangan brute force → auto-ban IP + lockdown.
# ============================================================
if [ "${AUTH_WATCH:-on}" = "on" ]; then
    AUTH_LOG="/var/log/auth.log"
    if [ -f "$AUTH_LOG" ]; then
        # Failed login count dalam window terakhir (15 menit)
        FAILED_COUNT=$(awk -v since="$(date -u -d '15 minutes ago' '+%b %e %H:%M' 2>/dev/null)" \
            'BEGIN{IGNORECASE=1} /Failed password|Invalid user|authentication failure/ && $0 >= since {count++} END{print count+0}' "$AUTH_LOG" 2>/dev/null)
        FAILED_THRESHOLD="${FAILED_THRESHOLD:-10}"
        if [ "${FAILED_COUNT:-0}" -ge "$FAILED_THRESHOLD" ]; then
            PROBLEMS="${PROBLEMS}🚨 BRUTE FORCE DETECTED: ${FAILED_COUNT} failed logins in 15m!\\n"
            # Ambil IP penyerang (top attacker)
            TOP_IP=$(grep -E "Failed password|Invalid user" "$AUTH_LOG" 2>/dev/null | tail -200 | \
                grep -oE "from [0-9.]+" | awk '{print $2}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
            if [ -n "$TOP_IP" ] && [ "${AUTO_BAN_IP:-on}" = "on" ]; then
                if command -v ufw > /dev/null 2>&1; then
                    ufw deny from "$TOP_IP" 2>/dev/null && PROBLEMS="${PROBLEMS}🛡️ IP ${TOP_IP} AUTO-BANNED\\n"
                fi
                # Juga ban via iptables fallback
                if command -v iptables > /dev/null 2>&1; then
                    iptables -A INPUT -s "$TOP_IP" -j DROP 2>/dev/null
                fi
            fi
            PORT_LOCKDOWN=true
        fi
    fi
fi

# ============================================================
# MODULE K: SECRET INTEGRITY (NEW — key yang bocor = deteksi & lockdown)
# Hash secret files secara berkala. Kalau ada perubahan mendadak
# (misal attacker nambahin key mereka ke auth.json/.env) →
# alert + lockdown. Juga cek: apakah file yang seharusnya 600
# jadi kebuka (permission downgrade = tanda manipulasi).
# ============================================================
if [ "${SECRET_WATCH:-on}" = "on" ]; then
    SECRET_FILES="${SECRET_FILES:-/root/.hermes/.env /root/.hermes/auth.json /root/.hermes/config.yaml}"
    for f in $SECRET_FILES; do
        [ -f "$f" ] || continue
        # Hash + permission check
        HASH=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        PERM=$(stat -c '%a' "$f" 2>/dev/null)
        STATE_FILE="$STATE_DIR/secret_$(echo "$f" | tr '/' '_').state"
        PREV=$(cat "$STATE_FILE" 2>/dev/null || echo "")
        CURRENT_STATE="${HASH}|${PERM}"
        if [ -n "$PREV" ] && [ "$CURRENT_STATE" != "$PREV" ]; then
            PROBLEMS="${PROBLEMS}🚨 SECRET FILE BERUBAH: ${f} (hash/perm: ${PERM})\\n"
            PORT_LOCKDOWN=true
        fi
        echo "$CURRENT_STATE" > "$STATE_FILE"
        # Permission hardening: pastikan 600
        if [ "$PERM" != "600" ] && [ "${ENFORCE_600:-on}" = "on" ]; then
            chmod 600 "$f" 2>/dev/null
            PROBLEMS="${PROBLEMS}🛡️ ${f} permission di-hardening ke 600 (dari ${PERM})\\n"
        fi
    done
fi

# ============================================================
# MODULE K: HTTP SERVICE WATCH (container-aware — no systemd)
# ============================================================
# Di container tidak ada systemctl, jadi WATCH_UNITS tidak efektif.
# Modul ini cek service via HTTP health endpoint. Config:
#   HTTP_WATCH=on
#   HTTP_SERVICES="name|url|expect_code" (space-separated)
# ============================================================
if [ "${HTTP_WATCH:-off}" = "on" ]; then
    for svc in ${HTTP_SERVICES:-}; do
        svc_name="${svc%%|*}"
        rest="${svc#*|}"
        svc_url="${rest%%|*}"
        svc_expect="${rest#*|}"
        svc_expect="${svc_expect:-200}"
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$svc_url" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" != "$svc_expect" ]; then
            COUNT_FILE="$STATE_DIR/http_restart_${svc_name}.txt"
            LAST_FILE="$STATE_DIR/http_restart_last_${svc_name}.txt"
            COUNT=$(cat "$COUNT_FILE" 2>/dev/null || echo 0)
            LAST=$(cat "$LAST_FILE" 2>/dev/null || echo 0)
            if [ $((NOW - LAST)) -gt "${CRASH_WINDOW_SEC:-600}" ]; then
                COUNT=0
            fi
            COUNT=$((COUNT + 1))
            echo "$COUNT" > "$COUNT_FILE"
            echo "$NOW" > "$LAST_FILE"
            if [ "$COUNT" -ge "${CRASH_THRESHOLD:-3}" ]; then
                PROBLEMS="${PROBLEMS}🔴 ${svc_name} HTTP ${HTTP_CODE} (expect ${svc_expect}) — crash-loop ${COUNT}x — manual check\n"
                continue
            fi
            # restart via restart hook jika tersedia
            RESTART_HOOK=""
            case "$svc_name" in
                webapp1)  RESTART_HOOK="${FLUXSCOUT_RESTART_CMD:-}" ;;
                sequenceverse) RESTART_HOOK="${SEQUENCEVERSE_RESTART_CMD:-}" ;;
                webapp2)      RESTART_HOOK="${WALL3_RESTART_CMD:-}" ;;
            esac
            if [ -n "$RESTART_HOOK" ]; then
                eval "$RESTART_HOOK" > /dev/null 2>&1
                sleep 3
                HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$svc_url" 2>/dev/null || echo "000")
                if [ "$HTTP_CODE2" = "$svc_expect" ]; then
                    PROBLEMS="${PROBLEMS}🟡 ${svc_name} was down (HTTP ${HTTP_CODE}) → restarted OK (HTTP ${HTTP_CODE2})\n"
                else
                    PROBLEMS="${PROBLEMS}🔴 ${svc_name} down & RESTART FAILED (HTTP ${HTTP_CODE2})\n"
                fi
            else
                PROBLEMS="${PROBLEMS}🟡 ${svc_name} HTTP ${HTTP_CODE} (expect ${svc_expect}) — no restart hook\n"
            fi
        fi
    done
fi

# ============================================================
# Alert (with dedup — Fable pattern: "Gak Semua Dikirim Notif")
# Track alert hash; jangan kirim ulang alert yang sama dalam
# DEDUP_WINDOW (default 1 jam) kecuali severity naik.
# ============================================================
if [ -n "$PROBLEMS" ]; then
    DEDUP_WINDOW="${DEDUP_WINDOW:-3600}"
    ALERT_HASH=$(echo "$PROBLEMS" | md5sum | awk '{print $1}')
    LAST_FILE="$STATE_DIR/last_alert.hash"
    LAST_HASH=$(cat "$LAST_FILE" 2>/dev/null || echo "")
    LAST_TS_FILE="$STATE_DIR/last_alert.ts"
    LAST_TS=$(cat "$LAST_TS_FILE" 2>/dev/null || echo 0)

    SHOULD_SEND=true
    if [ "$ALERT_HASH" = "$LAST_HASH" ] && [ $((NOW - LAST_TS)) -lt "$DEDUP_WINDOW" ]; then
        # Alert sama dalam window → silent (sudah dilaporkan)
        SHOULD_SEND=false
    fi

    if [ "$SHOULD_SEND" = "true" ]; then
        MSG="🛰️ SENTINEL ALERT (v2.0 HARDENED)
$(echo -e "$PROBLEMS")"
        send_alert "$MSG"
        echo "$ALERT_HASH" > "$LAST_FILE"
        echo "$NOW" > "$LAST_TS_FILE"
    fi
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $PROBLEMS" >> "$LOG_FILE" 2>/dev/null
fi

exit 0
