#!/bin/bash
# CRON PATH minimal (/usr/bin:/bin) -> python3 di /usr/local/bin gak ketemu
# -> semua python-check false-fail di cron. WAJIB export PATH penuh.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# ============================================================
# sentinel.sh — SENTINEL GUARD v3.0 PHOENIX (SUPER-HEALER)
# PRODUCTION VPS, post-incident 2026-08-06
#
# Guards:
#   1. systemd units (restart if dead, crash-loop detect)
#   2. JSON state file validation (corrupt -> backup + reset)
#   3. NEW: PORT EXPOSURE — service baru listen 0.0.0.0 tanpa auth
#      (root cause: exposed service tanpa auth) -> alert + auto-block
#   4. NEW: SSH KEY WATCH — authorized_keys berubah / key baru
#      di /root/.ssh -> alert + backup + hapus
#   5. NEW: PROCESS WATCH — reverse shell / miner / suspicious
#      (nc, ncat, socat, xmrig, minerd, /dev/tcp)
#   6. NEW: CRON/USER WATCH — cron baru, user baru, sudoers berubah
#   7. NEW: FILE INTEGRITY — tripwire hash file kritis
#   8. NEW: AUTO-LOCKDOWN — kalau terdeteksi intrusi, langsung
#      blokir semua port masuk kecuali whitelist + kill proses
#   v3.0 PHOENIX (SUPER-HEALER):
#   L. SELF-INTEGRITY  — script sendiri di-hash; diubah/dihapus -> restore
#   M. CONFIG WATCH    — config.yaml/.env/SOUL.md; hilang/korup -> restore,
#                        hash mismatch -> alert + backup .changed
#   N. SECRET VAULT    — backup credential di-encrypt AES-256 (openssl)
#   O. LIFE-LOOP       — heartbeat Primary <-> Secondary; mutual wake
#   P. CRON SELF-REGISTER — cron hilang -> daftar ulang sendiri
#
# Mode: silent saat sehat. ALERT + LOCKDOWN + HEAL saat ada anomali.
# Config: /etc/sentinel-guard/config.env
# ============================================================

set -u

CONFIG="${SENTINEL_CONFIG:-/etc/sentinel-guard/config.env}"
# exit kalau dijalanin langsung; return kalau di-source (SENTINEL_FUNC_TEST=1)
# biar test runner gak kebunuh oleh exit di top-level.
sg_exit() {
    if [ "${SENTINEL_FUNC_TEST:-0}" != "1" ]; then exit "$1"; fi
    return "$1"
}
if [ ! -f "$CONFIG" ]; then
    echo "sentinel: config not found at $CONFIG" >&2
    sg_exit 1
fi
# shellcheck disable=SC1090
. "$CONFIG"

# --- locking ---
LOCK_FILE="${SENTINEL_LOCK_FILE:-/tmp/sentinel-guard.lock}"
# Anti-symlink: cegah /tmp race pada lock file
if [ -L "$LOCK_FILE" ]; then rm -f "$LOCK_FILE" 2>/dev/null; fi
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    sg_exit 0
fi

# --- defaults ---
CRASH_THRESHOLD="${CRASH_THRESHOLD:-3}"
CRASH_WINDOW_SEC="${CRASH_WINDOW_SEC:-600}"
CASCADE_THRESHOLD="${CASCADE_THRESHOLD:-3}"
STATE_DIR="${SENTINEL_STATE_DIR:-/tmp/hermes-sentinel}"
# Anti-symlink: STATE_DIR harus real dir (bukan symlink attacker), mode 700
if [ -L "$STATE_DIR" ] || [ ! -d "$STATE_DIR" ]; then rm -f "$STATE_DIR" 2>/dev/null; fi
mkdir -p "$STATE_DIR" 2>/dev/null
chmod 700 "$STATE_DIR" 2>/dev/null
LOG_FILE="${SENTINEL_LOG_FILE:-/var/log/sentinel-guard.log}"

# --- v3.0 PHOENIX dirs ---
SENTINEL_DIR="/etc/sentinel-guard"
BACKUP_DIR="$SENTINEL_DIR/backups"
HASH_DIR="$SENTINEL_DIR/hashes"
VAULT_DIR="$SENTINEL_DIR/vault"
mkdir -p "$BACKUP_DIR" "$HASH_DIR" "$VAULT_DIR" 2>/dev/null
chmod 700 "$SENTINEL_DIR" "$BACKUP_DIR" "$HASH_DIR" "$VAULT_DIR" 2>/dev/null

for _var in CRASH_THRESHOLD CRASH_WINDOW_SEC CASCADE_THRESHOLD; do
    _val="${!_var:-}"
    if ! [[ "$_val" =~ ^[0-9]+$ ]]; then
        echo "sentinel: config error — $_var harus angka, dapat: '$_val'" >&2
        sg_exit 1
    fi
done

NOW=$(date +%s)

# --- bot token ---
if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ "$TELEGRAM_BOT_TOKEN" = "YOUR_BOT_TOKEN" ]; then
    TELEGRAM_BOT_TOKEN=$(grep -E "^TELEGRAM_BOT_TOKEN=" ${HERMES_HOME:-$HOME/.hermes}/.env 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'")
fi
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "sentinel: TELEGRAM_BOT_TOKEN not configured" >&2
    sg_exit 1
fi

send_alert() {
    if ! curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" \
        -d text="$1" \
        --max-time 10 > /dev/null 2>&1; then
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') sentinel: ALERT SEND FAILED: $1" >> "$LOG_FILE" 2>/dev/null
    fi
}

log() { echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $*" >> "$LOG_FILE" 2>/dev/null; }

# ============================================================
# PILAR L — SELF-INTEGRITY: sentinel script sendiri anti-tamper
# Script di-hash baseline; diubah/dihapus -> restore dari backup.
# ============================================================
self_integrity() {
    local script="/usr/local/bin/sentinel-guard.sh"
    local hash_file="$HASH_DIR/sentinel.sha256"
    [ -f "$script" ] || {
        send_alert "🛡️ CRITICAL: sentinel-guard.sh HILANG! Restoring...";
        chattr -i "$script" 2>/dev/null;
        cp -f "$BACKUP_DIR/sentinel-guard.sh.bak" "$script" 2>/dev/null;
        chmod +x "$script" 2>/dev/null;
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') sentinel restored (was missing)" >> "$LOG_FILE" 2>/dev/null;
        return;
    }
    [ -f "$hash_file" ] || {
        sha256sum "$script" | awk '{print $1}' > "$hash_file";
        return;
    }
    local current expected
    current=$(sha256sum "$script" | awk '{print $1}')
    expected=$(awk '{print $1}' "$hash_file" 2>/dev/null)
    if [ -n "$expected" ] && [ "$current" != "$expected" ]; then
        send_alert "🛡️ WARNING: sentinel-guard.sh DIUBAH! Hash mismatch. Restoring from backup..."
        chattr -i "$script" 2>/dev/null;
        cp -f "$BACKUP_DIR/sentinel-guard.sh.bak" "$script" 2>/dev/null
        chmod +x "$script" 2>/dev/null
        sha256sum "$script" | awk '{print $1}' > "$hash_file"
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') sentinel self-heal (hash mismatch)" >> "$LOG_FILE" 2>/dev/null
    fi
}

# ============================================================
# PILAR M — CONFIG WATCH: hermes config/.env/SOUL.md anti-tamper
# Mode cerdas: file HILANG/KOSONG/INVALID -> restore paksa (pasti masalah).
# Hash mismatch wajar (owner sengaja ganti) -> alert saja + backup .changed.
# ============================================================
check_config_file() {
    local file="$1" hash_file="$2" backup="$3" label="$4" min_size="${5:-100}"
    [ -f "$file" ] || {
        send_alert "🛡️ CRITICAL: $label HILANG! Restoring from backup..."
        chattr -i "$file" 2>/dev/null   # remove immutable sebelum write
        cp -f "$backup" "$file" 2>/dev/null
        chmod 600 "$file" 2>/dev/null
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $label restored (missing)" >> "$LOG_FILE" 2>/dev/null
        return
    }
    local size
    size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
    if [ "$size" -lt "$min_size" ]; then
        send_alert "🛡️ CRITICAL: $label KORUP (${size}B < ${min_size}B)! Restoring backup..."
        chattr -i "$file" 2>/dev/null   # remove immutable sebelum write
        cp -f "$backup" "$file" 2>/dev/null
        chmod 600 "$file" 2>/dev/null
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $label restored (corrupt ${size}B)" >> "$LOG_FILE" 2>/dev/null
        return
    fi
    if [ "$label" = "hermes .env" ]; then
        if ! grep -qE '(DEEPSEEK_API_KEY|OPENROUTER_API_KEY|TELEGRAM_BOT_TOKEN)=' "$file" 2>/dev/null; then
            send_alert "🛡️ CRITICAL: .env KEHILANGAN SEMUA TOKEN! Restoring backup (anti-revoke recovery)..."
            chattr -i "$file" 2>/dev/null   # remove immutable sebelum write
            cp -f "$backup" "$file" 2>/dev/null
            chmod 600 "$file" 2>/dev/null
            echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') .env restored (no valid tokens)" >> "$LOG_FILE" 2>/dev/null
            return
        fi
    fi
    [ -f "$hash_file" ] || {
        sha256sum "$file" | awk '{print $1}' > "$hash_file"
        return
    }
    local current expected
    current=$(sha256sum "$file" | awk '{print $1}')
    expected=$(awk '{print $1}' "$hash_file" 2>/dev/null)
    if [ -n "$expected" ] && [ "$current" != "$expected" ]; then
        cp -f "$file" "$BACKUP_DIR/$(basename "$file").changed.$(date +%s)" 2>/dev/null
        send_alert "🛡️ WARNING: $label DIUBAH (hash mismatch). Versi baru di-backup sebagai .changed. Not auto-restored — jika perubahan disengaja, update baseline: sha256sum $file"
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $label changed (hash mismatch)" >> "$LOG_FILE" 2>/dev/null
    fi
}

config_watch() {
    check_config_file "${HERMES_HOME:-$HOME/.hermes}/config.yaml" "$HASH_DIR/hermes-config.sha256" "$BACKUP_DIR/hermes-config.yaml.bak" "hermes config.yaml" 200
    check_config_file "${HERMES_HOME:-$HOME/.hermes}/.env" "$HASH_DIR/hermes-env.sha256" "$BACKUP_DIR/hermes-env.bak" "hermes .env" 500
    check_config_file "${HERMES_HOME:-$HOME/.hermes}/SOUL.md" "$HASH_DIR/soul.sha256" "$BACKUP_DIR/soul.md.bak" "SOUL.md" 100
}

# ============================================================
# PILAR N — SECRET VAULT: backup credential di-encrypt AES-256
# Defense-in-depth: walau attacker dapet backup/ dir, isi tetap
# tidak terbaca tanpa master key (di vault/, mode 600).
# ============================================================
MASTER_KEY_FILE="$VAULT_DIR/master.key"

vault_encrypt() {
    local src="$1" name="$2"
    [ -f "$MASTER_KEY_FILE" ] || return 1
    [ -f "$src" ] || return 1
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 \
        -in "$src" -out "$VAULT_DIR/$name.enc" \
        -pass file:"$MASTER_KEY_FILE" 2>/dev/null
    chmod 600 "$VAULT_DIR/$name.enc" 2>/dev/null
}

vault_decrypt() {
    local name="$1" dst="$2"
    [ -f "$MASTER_KEY_FILE" ] || return 1
    [ -f "$VAULT_DIR/$name.enc" ] || return 1
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 \
        -in "$VAULT_DIR/$name.enc" -out "$dst" \
        -pass file:"$MASTER_KEY_FILE" 2>/dev/null
}

secret_vault() {
    if [ ! -f "$MASTER_KEY_FILE" ]; then
        openssl rand -hex 32 > "$MASTER_KEY_FILE" 2>/dev/null
        chmod 600 "$MASTER_KEY_FILE" 2>/dev/null
    fi
    vault_encrypt "$BACKUP_DIR/hermes-env.bak" "env"
    vault_encrypt "$BACKUP_DIR/hermes-config.yaml.bak" "config"
    vault_encrypt "$BACKUP_DIR/soul.md.bak" "soul"
    vault_encrypt "/etc/sentinel-guard/config.env" "sentinel-config"
    if [ -f "$VAULT_DIR/env.enc" ]; then
        local tmp
        tmp=$(mktemp)
        if vault_decrypt "env" "$tmp" && [ -s "$tmp" ]; then
            : # OK
        else
            send_alert "🛡️ CRITICAL: Secret vault decrypt GAGAL! Master key corrupted?"
        fi
        rm -f "$tmp"
    fi
}

# ============================================================
# PILAR O — LIFE-LOOP: heartbeat Primary <-> Secondary
# Saling monitor: salah satu mati, yang lain bangunin.
# ============================================================
life_loop() {
    local hb_dir="/root/hermes-shared/heartbeat"
    mkdir -p "$hb_dir" 2>/dev/null
    if [ "${SENTINEL_IDENTITY:-hermes-1}" = "hermes-1" ]; then
        date -u +%s > "$hb_dir/hermes-1.heartbeat" 2>/dev/null
        chmod 644 "$hb_dir/hermes-1.heartbeat" 2>/dev/null
    else
        date -u +%s > "$hb_dir/hermes-2.heartbeat" 2>/dev/null
        chmod 644 "$hb_dir/hermes-2.heartbeat" 2>/dev/null
    fi

    if [ "${LIFE_LOOP:-on}" = "on" ]; then
        local partner="${LIFE_LOOP_PARTNER:-hermes-2}"
        local hb_file="$hb_dir/$partner.heartbeat"
        local max_age="${LIFE_LOOP_MAX_AGE:-300}"
        local alert_file="$STATE_DIR/life-loop.$partner"
        if [ -f "$hb_file" ]; then
            local hb_ts age last_alert=0
            hb_ts=$(cat "$hb_file" 2>/dev/null || echo 0)
            age=$((NOW - hb_ts))
            if [ "$age" -gt "$max_age" ]; then
                [ -f "$alert_file" ] && last_alert=$(cat "$alert_file" 2>/dev/null || echo 0)
                if [ $((NOW - last_alert)) -gt 900 ]; then
                    echo "$NOW" > "$alert_file"
                    send_alert "🛡️ LIFE-LOOP: $partner HEARTBEAT STALE (${age}s). Recovery attempted."
                    # Recovery: restart partner gateway
                    if [ "$partner" = "hermes-2" ] && [ -x ${HERMES_HOME:-$HOME/.hermes}/scripts/restart-secondary.sh ]; then
                        ${HERMES_HOME:-$HOME/.hermes}/scripts/restart-secondary.sh >/dev/null 2>&1 &
                    elif [ -x ${HERMES_HOME:-$HOME/.hermes}/scripts/secondary_worker.sh ]; then
                        ${HERMES_HOME:-$HOME/.hermes}/scripts/secondary_worker.sh >/dev/null 2>&1 &
                    fi
                    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') life-loop: $partner stale ${age}s, recovery attempted" >> "$LOG_FILE" 2>/dev/null
                fi
            fi
        fi
    fi
}

# ============================================================
# PILAR P — CRON SELF-REGISTER: cron sentinel hilang -> daftar ulang
# ============================================================
cron_self_register() {
    local jobs_file="${HERMES_HOME:-/root/.hermes}/cron/jobs.json"
    [ -f "$jobs_file" ] || return 0
    if ! grep -q "sentinel-guard" "$jobs_file" 2>/dev/null; then
        send_alert "🛡️ WARNING: sentinel-guard cron HILANG dari jobs! Re-registering..."
        HERMES_HOME="${HERMES_HOME:-/root/.hermes}" \
        /usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main cron create \
            --name "sentinel-guard" \
            --schedule "*/2 * * * *" \
            --script sentinel-guard.sh \
            --no-agent >/dev/null 2>&1 || true
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') sentinel cron re-registered" >> "$LOG_FILE" 2>/dev/null
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
        # NOTE: TIDAK exit di sini — sentinel harus lanjut jalan (self-heal penuh).
        # Alert tetap terkirim via alert block di akhir (dengan dedup).
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
# (insiden: exposed service serve seluruh home dir tanpa auth)
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
    # authorized_keys hash — purge INCREMENTAL: key di baseline (pemilik) dipertahankan,
    # key BARU (asing) dihapus. Mencegah lockout owner saat ganti key legit.
    AK="/root/.ssh/authorized_keys"
    AK_BASELINE="$STATE_DIR/authorized_keys.baseline"
    if [ -f "$AK" ]; then
        # Baseline pertama (key pemilik yang dikenal)
        if [ ! -f "$AK_BASELINE" ]; then
            cp "$AK" "$AK_BASELINE" 2>/dev/null
            chmod 600 "$AK_BASELINE" 2>/dev/null
        fi
        # Baseline KOSONG tapi AK ada isi = setup awal legit (belum pernah baseline).
        # Update baseline, JANGAN purge — kalau purge, semua key dianggap asing
        # dan owner ke-lockout (boomerang).
        if [ ! -s "$AK_BASELINE" ] && [ -s "$AK" ]; then
            cp "$AK" "$AK_BASELINE" 2>/dev/null
            chmod 600 "$AK_BASELINE" 2>/dev/null
        fi
        AK_HASH=$(md5sum "$AK" 2>/dev/null | awk '{print $1}')
        AK_PREV=$(cat "$STATE_DIR/authorized_keys.hash" 2>/dev/null || echo "")
        if [ -n "$AK_PREV" ] && [ "$AK_HASH" != "$AK_PREV" ]; then
            cp "$AK" "$STATE_DIR/authorized_keys.$(date +%s).bak" 2>/dev/null
            # Hitung key asing: baris yang TIDAK ada di baseline
            FOREIGN=$(mktemp)
            : > "$FOREIGN"
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                case "$line" in \#*) continue ;; esac
                if ! grep -Fxq "$line" "$AK_BASELINE" 2>/dev/null; then
                    echo "$line" >> "$FOREIGN"
                fi
            done < "$AK"
            if [ -s "$FOREIGN" ]; then
                PROBLEMS="${PROBLEMS}🚨 authorized_keys BERUBAH — key ASING terdeteksi! Backup → ${STATE_DIR}/...\\n"
                if [ "${AUTO_PURGE_KEYS:-on}" = "on" ]; then
                    # Tulis ulang: hanya key yang ada di baseline (key pemilik)
                    grep -Fx -f "$AK_BASELINE" "$AK" > "$AK.tmp" 2>/dev/null || : > "$AK.tmp"
                    mv "$AK.tmp" "$AK"
                    chmod 600 "$AK"
                    PROBLEMS="${PROBLEMS}🛡️ Key asing DIHAPUS (${FOREIGN} baris), key pemilik dipertahankan\\n"
                    PORT_LOCKDOWN=true
                fi
            else
                # Perubahan tapi semua key dikenal — kemungkinan edit legit owner
                cp "$AK" "$AK_BASELINE" 2>/dev/null  # update baseline
                PROBLEMS="${PROBLEMS}🟡 authorized_keys berubah (key dikenal) — baseline di-update\\n"
            fi
            rm -f "$FOREIGN"
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
            *nc\ -l*|*ncat*|*socat*|*xmrig*|*minerd*|*cpuminer*|*kdevtmpfsi*|*kinsing*|*/dev/tcp*|*bash\ -i*|*pty.spawn*|*sh\ -i*)
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
        # CRON berubah — bedakan: legit owner vs asing (smart revert per-bar).
        # JANGAN revert seluruh crontab ke baseline (boomerang: cron legit
        # owner kayak obsidian/webapp ikut hilang).
        if [ "${AUTO_REVERT_CRON:-on}" = "on" ] && [ -f "$STATE_DIR/cron.baseline" ]; then
            # Baseline kosong? Ambil sekarang (setup awal)
            if [ ! -s "$STATE_DIR/cron.baseline" ]; then
                crontab -l 2>/dev/null > "$STATE_DIR/cron.baseline"
            fi
            # Baris BARU = yang ada di crontab sekarang tapi TIDAK di baseline
            NEW_LINES=$(comm -13 <(sort "$STATE_DIR/cron.baseline" 2>/dev/null) <(crontab -l 2>/dev/null | sort) 2>/dev/null)
            if [ -n "$NEW_LINES" ]; then
                # Pattern mencurigakan (attacker): tmp/shm, curl|bash, wget|sh, miner, reverse
                SUS_CRON=$(echo "$NEW_LINES" | grep -E "/tmp/|/dev/shm/|curl .*\|.*(ba)?sh|wget .*\|.*(ba)?sh|minerd|xmrig|kdevtmpfsi|kinsing|\.onion|nc -e|ncat -e" 2>/dev/null)
                if [ -n "$SUS_CRON" ]; then
                    PROBLEMS="${PROBLEMS}🚨 CRON MEN CURIGAKAN terdeteksi — dihapus:\\\\n$SUS_CRON\\\\n"
                    # Hapus cuma baris mencurigakan dari crontab
                    crontab -l 2>/dev/null | grep -vF -e "$SUS_CRON" > /tmp/cron.clean 2>/dev/null
                    # grep -vF -e per baris — handle multi-line
                    while IFS= read -r sus_line; do
                        [ -z "$sus_line" ] && continue
                        crontab -l 2>/dev/null | grep -vF "$sus_line" > /tmp/cron.clean2 2>/dev/null
                        mv /tmp/cron.clean2 /tmp/cron.clean
                    done <<< "$SUS_CRON"
                    cat /tmp/cron.clean | crontab - 2>/dev/null
                    PROBLEMS="${PROBLEMS}🛡️ cron mencurigakan DIHAPUS (smart revert)\\\\n"
                    PORT_LOCKDOWN=true
                else
                    # Cron baru wajar (owner nambah legit) — update baseline, jangan hapus
                    crontab -l 2>/dev/null > "$STATE_DIR/cron.baseline"
                    PROBLEMS="${PROBLEMS}🟡 CRON berubah (entry wajar ditambahkan) — baseline di-update\\\\n"
                fi
            else
                # Perubahan lain (file di /etc/cron.d dll) — update baseline
                crontab -l 2>/dev/null > "$STATE_DIR/cron.baseline"
            fi
        else
            PROBLEMS="${PROBLEMS}🚨 CRON berubah! (crontab / etc/cron.d)\\\\\\\\n"
            PORT_LOCKDOWN=true
        fi
    fi
    echo "$CRON_SNAP" > "$STATE_DIR/cron.hash"
    # Simpan baseline pertama (hanya kalau belum ada)
    if [ ! -f "$STATE_DIR/cron.baseline" ]; then
        crontab -l 2>/dev/null > "$STATE_DIR/cron.baseline"
        echo "cron baseline saved: $(wc -l < "$STATE_DIR/cron.baseline") lines"
    fi

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
        IMMUTABLE_FILES="${IMMUTABLE_FILES:-${HERMES_HOME:-$HOME/.hermes}/.env /root/.hermes/auth.json ${HERMES_HOME:-$HOME/.hermes}/config.yaml ${HERMES_HOME:-$HOME/.hermes}/SOUL.md /root/.hermes/scripts/sentinel.sh /etc/sentinel-guard/config.env}"
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
            if [ "${AUTH_BAN_WATCH:-on}" = "off" ]; then
            PROBLEMS="${PROBLEMS}🚨 BRUTE FORCE DETECTED: ${FAILED_COUNT} failed logins in 15m!\\n"
            fi
            # Ambil IP penyerang (top attacker)
            TOP_IP=$(grep -E "Failed password|Invalid user" "$AUTH_LOG" 2>/dev/null | tail -200 | \
                grep -oE "from [0-9.]+" | awk '{print $2}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
            if [ -n "$TOP_IP" ] && [ "${AUTO_BAN_IP:-on}" = "on" ] && [ "${AUTH_BAN_WATCH:-on}" = "off" ]; then
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
    SECRET_FILES="${SECRET_FILES:-${HERMES_HOME:-$HOME/.hermes}/.env /root/.hermes/auth.json ${HERMES_HOME:-$HOME/.hermes}/config.yaml}"
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
if [ "${HTTP_WATCH:-on}" = "on" ]; then
    for svc in ${HTTP_SERVICES:-}; do
        svc_name="${svc%%|*}"
        rest="${svc#*|}"
        svc_url="${rest%%|*}"
        svc_expect="${rest#*|}"
        svc_expect="${svc_expect:-200}"
        HTTP_CODE=$(curl -s -L -o /dev/null -w "%{http_code}" --max-time 5 "$svc_url" 2>/dev/null || echo "000")
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
            # RESTART hook via indirect expansion: <SERVICE_UPPER>_RESTART_CMD.
            # Nama service bebas (dari HTTP_SERVICES) — gak ada daftar hardcode.
            RESTART_HOOK=""
            hook_var="$(echo "$svc_name" | tr '[:lower:]-' '[:upper:]_')_RESTART_CMD"
            RESTART_HOOK="${!hook_var:-}"
            if [ -z "$RESTART_HOOK" ] && [ -x "${HERMES_HOME:-$HOME/.hermes}/scripts/restart-${svc_name}.sh" ]; then
                RESTART_HOOK="${HERMES_HOME:-$HOME/.hermes}/scripts/restart-${svc_name}.sh"
            fi
            if [ -n "$RESTART_HOOK" ]; then
                # Anti-injection: tolak hook yang mengandung shell metacharacters
                case "$RESTART_HOOK" in
                    *";"*|*"&"*|*"|"*|*"\$("*|*"\`"*)
                        PROBLEMS="${PROBLEMS}🔴 ${svc_name} RESTART_HOOK mencurigakan — di-skip (config ke-tamper?)
"
                        ;;
                    *)
                        bash -c "$RESTART_HOOK" > /dev/null 2>&1
                        ;;
                esac
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
# PILAR R — CORE VAULT: auto-backup ke core tiap run
# (Pilar N upgraded: selain vault/, tiap tick backup kritis
#  di-encrypt ke core vault — write path tanpa kode owner.
#  Restore/decrypt core butuh access code owner.)
# ============================================================
core_vault_backup() {
    local cv="/root/.hermes/scripts/core-vault.sh"
    [ -x "$cv" ] || return 0
    "$cv" backup ${HERMES_HOME:-$HOME/.hermes}/.env env >/dev/null 2>&1
    "$cv" backup ${HERMES_HOME:-$HOME/.hermes}/config.yaml config >/dev/null 2>&1
    "$cv" backup ${HERMES_HOME:-$HOME/.hermes}/SOUL.md soul >/dev/null 2>&1
    "$cv" backup /etc/sentinel-guard/config.env sentinel-config >/dev/null 2>&1
    "$cv" backup /usr/local/bin/sentinel-guard.sh sentinel-script >/dev/null 2>&1
}

# ============================================================
# AUTO-SYNC BACKUP LAPIS 1 (Pilar M upgrade)
# Kalau config/.env berubah (disengaja), update backup lokal
# biar self-heal selalu restore versi TERBARU, bukan versi setup.
#
# AMAN: hanya config.yaml + SOUL.md yang di-auto-sync (perubahan
# wajar: model/personality). .env TIDAK di-auto-sync — backup
# .env tetap versi token valid yang diketahui, biar attacker
# yang ganti .env (tapi masih ada token) gak bisa nge-commit
# versi token MEREKA sebagai backup resmi.
# ============================================================
auto_sync_backups() {
    local latest_cfg latest_soul
    latest_cfg=$(ls -t "$BACKUP_DIR"/config.yaml.changed.* 2>/dev/null | head -1)
    latest_soul=$(ls -t "$BACKUP_DIR"/SOUL.md.changed.* 2>/dev/null | head -1)
    if [ -n "$latest_cfg" ]; then
        cp -f "$latest_cfg" "$BACKUP_DIR/hermes-config.yaml.bak" 2>/dev/null
        sha256sum ${HERMES_HOME:-$HOME/.hermes}/config.yaml | awk '{print $1}' > "$HASH_DIR/hermes-config.sha256"
        log "auto-sync: hermes-config.yaml.bak updated ke versi terbaru"
    fi
    if [ -n "$latest_soul" ]; then
        cp -f "$latest_soul" "$BACKUP_DIR/soul.md.bak" 2>/dev/null
        sha256sum ${HERMES_HOME:-$HOME/.hermes}/SOUL.md | awk '{print $1}' > "$HASH_DIR/soul.sha256"
        log "auto-sync: soul.md.bak updated ke versi terbaru"
    fi
}

# ============================================================
# U2: GATEWAY PRIMARY WATCH — pastikan gateway utama (primary agent) hidup.
# Sentinel di-system cron tetap jalan walau gateway mati -> detect + restart.
# ============================================================
gateway_watch() {
    local gw_pat="${GATEWAY_PROC_PATTERN:-hermes.*gateway.*run|hermes_cli\.main.*gateway}"
    local gw_alive gw_restart
    gw_alive=$(for pid in /proc/[0-9]*; do
        cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 120)
        echo "$cmd" | grep -qE "$gw_pat" && echo "$pid"
    done 2>/dev/null | head -1)
    if [ -z "$gw_alive" ]; then
        gw_restart="${GATEWAY_RESTART_SCRIPT:-/root/.hermes/scripts/restart-primary.sh}"
        PROBLEMS="${PROBLEMS}🟡 GATEWAY PRIMARY DOWN — restart via ${gw_restart}\n"
        if [ -x "$gw_restart" ]; then
            "$gw_restart" >/dev/null 2>&1 &
        fi
    fi
}

# ============================================================
# U3b: GATEWAY HEALTH CHECK (functional, 2026-08-07) — reviewer 2.1
# gateway_watch cuma cek proses nongol di /proc — gateway hang (event loop
# macet, network stuck) gak ke-detect. Hermes cron jobs jalan DI DALAM
# gateway process: kalau gateway hang, executions.db gak update.
# MAX(finished_at) lebih tua dari threshold + masih ada job aktif = HANG.
# ============================================================
gateway_health_check() {
    local db="/root/.hermes/cron/executions.db"
    local max_age="${GATEWAY_MAX_IDLE_MIN:-6}"
    [ -f "$db" ] || return 0
    # Skip kalau gak ada Hermes cron job aktif (MAX bakal stale -> false positive)
    local njob
    njob=$(python3 -c "
import json, os
p='/root/.hermes/cron/jobs.json'
try:
    d=json.load(open(p))
    n=len(d) if isinstance(d,(list,dict)) else 0
    print(n)
except Exception:
    print(0)
" 2>/dev/null)
    [ "${njob:-0}" -gt 0 ] || return 0
    local last
    last=$(python3 -c "
import sqlite3
try:
    db=sqlite3.connect('$db', timeout=3)
    r=db.execute('SELECT MAX(finished_at) FROM executions').fetchone()[0]
    print(r or '')
except Exception:
    pass
" 2>/dev/null)
    [ -n "$last" ] || return 0
    local last_ts now_ts age
    last_ts=$(date -u -d "$last" +%s 2>/dev/null)
    [ -n "$last_ts" ] || return 0
    now_ts=$(date -u +%s)
    age=$(( now_ts - last_ts ))
    if [ "$age" -gt $((max_age * 60)) ]; then
        PROBLEMS="${PROBLEMS}🟡 GATEWAY HANG — no cron exec in ${age}s (functional check)\n"
    fi
}

# ============================================================
# U4: LOG ROTATION — log gak boleh membengkak tanpa batas
# ============================================================
rotate_log() {
    [ -f "$LOG_FILE" ] || return 0
    local size
    size=$(stat -c '%s' "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$size" -gt 5242880 ]; then  # 5MB
        mv "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null
        for i in 3 2 1; do
            [ -f "$LOG_FILE.$i" ] && mv "$LOG_FILE.$i" "$LOG_FILE.$((i+1))" 2>/dev/null
        done
        touch "$LOG_FILE" 2>/dev/null
        log "log rotated (was ${size}B)"
    fi
}

# ============================================================
# PILAR S — GITHUB REPO MONITOR (anti-deface)
# Public repo: atom feed tanpa auth. Private repo: API + token.
# Kalau author bukan owner / ada konten mencurigakan -> ALERT.
# ============================================================
github_repo_monitor() {
    [ "${GITHUB_WATCH:-on}" != "on" ] && return 0
    local repos="${GITHUB_REPOS:-}"
    local state="$STATE_DIR/github_state"
    mkdir -p "$state" 2>/dev/null
    # Throttle private API: max 1x per 10 menit (rate limit 60/hr unauthenticated;
    # dengan throttle: 4 repo x 6x/hr = 24/hr — aman)
    local priv_throttle=600
    local priv_last="$state/private_last_check"
    local priv_ts=0
    [ -f "$priv_last" ] && priv_ts=$(cat "$priv_last" 2>/dev/null || echo 0)
    # Token untuk private repo — baca dari env atau git-credentials (mode 600)
    local ghtoken="${GITHUB_TOKEN:-}"
    if [ -z "$ghtoken" ] && [ -f /root/.git-credentials ]; then
        ghtoken=$(grep -o 'https://[^:]*:[^@]*@github.com' /root/.git-credentials 2>/dev/null | sed 's|https://||;s|:.*||' | head -1)
        ghtoken=$(grep 'github.com' /root/.git-credentials 2>/dev/null | sed 's|https://||;s|@github.com||' | cut -d: -f2)
    fi
    local auth=""
    [ -n "$ghtoken" ] && auth="Authorization: token $ghtoken"
    for repo in $repos; do
        local info sha author msg
        # Coba atom feed (public). Kalau kosong/404 → API (private).
        info=$(curl -sL --max-time 10 -H "User-Agent: sentinel-guard" ${auth:+-H "$auth"} "https://github.com/$repo/commits/main.atom" 2>/dev/null | head -c 4000)
        if ! echo "$info" | grep -q 'Grit::Commit/'; then
            # Private/API path — THROTTLED (10 menit) biar gak kena rate limit 60/hr
            if [ $((NOW - priv_ts)) -lt "$priv_throttle" ]; then
                log "github-monitor: private check throttled ($repo)"
                continue
            fi
            echo "$NOW" > "$priv_last"
            info=$(curl -sL --max-time 10 -H "User-Agent: sentinel-guard" ${auth:+-H "$auth"} "https://api.github.com/repos/$repo/commits?per_page=1" 2>/dev/null | head -c 3000)
            sha=$(echo "$info" | grep -m1 '"sha"' | sed 's/.*"sha": *"\([a-f0-9]\{40\}\)".*/\1/' 2>/dev/null)
            author=$(echo "$info" | grep -m1 '"login"' | sed 's/.*"login": *"\([^"]*\)".*/\1/' 2>/dev/null)
            msg=$(echo "$info" | grep -m1 '"message"' | sed 's/.*"message": *"\([^"]*\)".*/\1/' | head -c 100)
        else
            sha=$(echo "$info" | grep -m1 'Grit::Commit/' | sed 's/.*Grit::Commit\/\([a-f0-9]\{40\}\).*/\1/' 2>/dev/null)
            author=$(echo "$info" | grep -m2 '<name>' | tail -1 | sed 's/<[^>]*>//g' | tr -d ' \n' 2>/dev/null)
            msg=$(echo "$info" | grep -m1 '<title>' | sed 's/<[^>]*>//g' | head -c 100)
        fi
        local prev=""
        mkdir -p "$state/$(dirname "$repo")" 2>/dev/null
        [ -f "$state/$repo.sha" ] && prev=$(cat "$state/$repo.sha" 2>/dev/null)
        if [ -n "$sha" ] && [ "$sha" != "$prev" ]; then
            # Commit BARU — cek author
            if [ -n "$author" ] && [ -n "${GITHUB_OWNER:-}" ] && [ "$author" != "$GITHUB_OWNER" ]; then
                PROBLEMS="${PROBLEMS}🚨 GITHUB: $repo commit BARU oleh ${author:-unknown}! msg: ${msg:-?}\n"
            elif [ -n "$author" ] && [ -n "${GITHUB_OWNER:-}" ] && [ "$author" = "$GITHUB_OWNER" ]; then
                log "github-monitor: $repo commit oleh owner ($sha)"
            fi
            echo "$sha" > "$state/$repo.sha"
        fi
    done
}


# ============================================================
# PILAR V — CRON FAILURE WATCH (2026-08-07)
# Hermes cron jobs yang FAILED (script exit != 0 / timeout) — sentinel
# lama cuma nge-watch cron hilang/berubah, BUKAN cron gagal. Job failure
# = indikasi service rusak / API down / script bug — harus alert.
# Sumber: /root/.hermes/cron/executions.db (status + error).
# ============================================================
cron_failure_watch() {
    [ "${CRON_FAIL_WATCH:-on}" != "on" ] && return 0
    local db="/root/.hermes/cron/executions.db"
    [ -f "$db" ] || return 0
    local since="$((NOW - 1800))"  # 30 menit terakhir
    local since_iso
    since_iso=$(date -u -d "@$since" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null)
    local failures state
    failures=$(python3 -c "
import sqlite3, sys
try:
    db = sqlite3.connect('$db')
    rows = db.execute(\"SELECT job_id, status, error FROM executions WHERE finished_at >= ? AND status = 'failed'\", ('$since_iso',)).fetchall()
    for job_id, status, error in rows:
        err = (error or '')[:120].replace('\n', ' ')
        print(f'{job_id}|{err}')
except Exception as e:
    print(f'ERR|{e}', file=sys.stderr)
" 2>/dev/null)
    [ -z "$failures" ] && return 0
    local line job_id err
    while IFS='|' read -r job_id err; do
        [ -z "$job_id" ] && continue
        # Dedup: cuma alert job yang BELUM pernah di-report (state file)
        state="$STATE_DIR/cron_fail_${job_id}.last"
        local prev
        prev=$(cat "$state" 2>/dev/null || echo 0)
        if [ "$prev" -lt "$since" ]; then
            PROBLEMS="${PROBLEMS}🔴 CRON FAILED: job ${job_id} — ${err}\\n"
            echo "$NOW" > "$state"
        fi
    done <<< "$failures"
    hunter_log "cron failure watch selesai"
}

# ============================================================
# PILAR T — HUNTER: anomaly detection (deface, corrupt, process)
# ============================================================
HUNTER_WATCH="${HUNTER_WATCH:-on}"
HEALER_WATCH="${HEALER_WATCH:-on}"
HUNTER_STATE="$STATE_DIR/hunter_state"
HUNTER_FINDINGS=""

hunter_init() {
    mkdir -p "$HUNTER_STATE" 2>/dev/null
    : > "$HUNTER_STATE/findings.txt" 2>/dev/null
}

hunter_log() { log "hunter: $*"; }

# Deteksi 1: deface artifact — cek KONTEN README/index (bukan nama file,
# karena nama file legit owner bisa cocok dengan pattern untuk dokumentasi)
hunter_deface_scan() {
    [ "$HUNTER_WATCH" != "on" ] && return 0
    local webroots="${WEB_ROOT_SCAN:-/var/www/html /srv/www}"
    local root f
    for root in $webroots; do
        [ -d "$root" ] || continue
        # Konten deface signature di README/index/html (public web root)
        f=$(grep -rilE "pwned by|hacked by|defaced by|this site is defaced" "$root" \
            --include="*.md" --include="*.html" --include="*.htm" 2>/dev/null | head -3)
        if [ -n "$f" ]; then
            HUNTER_FINDINGS="${HUNTER_FINDINGS}deface|high|$f\n"
        fi
    done
    hunter_log "deface scan selesai"
}

# Deteksi 2: data korup (state JSON invalid, config kosong)
hunter_corruption_scan() {
    [ "$HUNTER_WATCH" != "on" ] && return 0
    local files f
    files=$(find "$STATE_DIR" -name "*.json" 2>/dev/null | head -10)
    for f in $files; do
        if ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$f" 2>/dev/null; then
            HUNTER_FINDINGS="${HUNTER_FINDINGS}corrupt|high|$f\n"
        fi
    done
    for cf in ${HERMES_HOME:-$HOME/.hermes}/config.yaml /etc/sentinel-guard/config.env ${SECONDARY_CONFIG:-/etc/sentinel-guard-secondary/config.env} ${HERMES_HOME:-$HOME/.hermes}/.env; do
        if [ -f "$cf" ] && [ ! -s "$cf" ]; then
            HUNTER_FINDINGS="${HUNTER_FINDINGS}corrupt|high|$cf empty\n"
        fi
    done
    # jobs.json (cron registry) harus valid JSON — korup = semua cron job mati.
    # RACE: scheduler Hermes nulis jobs.json ~tiap 47 detik (burst) -> transient
    # invalid kalau kebaca pas mid-write. Teknik parse-stable: parse OK DAN
    # mtime gak berubah selama parse = beneran valid. Retry 3x.
    if [ -f /root/.hermes/cron/jobs.json ]; then
        ok=0
        for _try in 1 2 3; do
            m1=$(stat -c %Y /root/.hermes/cron/jobs.json 2>/dev/null || echo 0)
            if python3 -c "import json;json.load(open('/root/.hermes/cron/jobs.json'))" 2>/dev/null; then
                m2=$(stat -c %Y /root/.hermes/cron/jobs.json 2>/dev/null || echo 0)
                if [ "$m1" = "$m2" ]; then ok=1; break; fi
                sleep 2
                continue
            fi
            sleep 2
        done
        if [ "$ok" != "1" ]; then
            HUNTER_FINDINGS="${HUNTER_FINDINGS}corrupt|high|/root/.hermes/cron/jobs.json\n"
        fi
    fi
    # .env wajib punya minimal satu token aktif
    if [ -f ${HERMES_HOME:-$HOME/.hermes}/.env ] && ! grep -qE '(DEEPSEEK_API_KEY|OPENROUTER_API_KEY|TELEGRAM_BOT_TOKEN)=' ${HERMES_HOME:-$HOME/.hermes}/.env 2>/dev/null; then
        HUNTER_FINDINGS="${HUNTER_FINDINGS}corrupt|high|${HERMES_HOME:-$HOME/.hermes}/.env missing tokens\n"
    fi
    hunter_log "corruption scan selesai"
}

# Deteksi 3: proses anomali (miner / reverse shell)
hunter_process_scan() {
    [ "$HUNTER_WATCH" != "on" ] && return 0
    local patterns="${HUNTER_PROC_PATTERNS:-kdevtmpfsi xmrig kinsing minesweeper c3pool nanominer}"
    local pid cmd pat
    for pid in /proc/[0-9]*; do
        cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 150)
        for pat in $patterns; do
            if echo "$cmd" | grep -qi "$pat"; then
                HUNTER_FINDINGS="${HUNTER_FINDINGS}process|high|${pid##*/}:$cmd\n"
            fi
        done
    done
    hunter_log "process scan selesai"
}

# Deteksi 4: token health (Telegram bot, GitHub)
hunter_token_scan() {
    [ "$HUNTER_WATCH" != "on" ] && return 0
    local tgh gh_code
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
        tgh=$(curl -s --max-time 8 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe" 2>/dev/null | head -c 200)
        if ! echo "$tgh" | grep -q '"ok":true'; then
            HUNTER_FINDINGS="${HUNTER_FINDINGS}token|high|telegram bot token invalid\n"
        fi
    fi
    if [ -f /root/.git-credentials ]; then
        gh_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://api.github.com/rate_limit 2>/dev/null)
        if [ "$gh_code" = "401" ]; then
            HUNTER_FINDINGS="${HUNTER_FINDINGS}token|high|github token invalid\n"
        fi
    fi
    hunter_log "token scan selesai"
}

# Deteksi 5: listener port di luar whitelist
hunter_port_scan() {
    [ "$HUNTER_WATCH" != "on" ] && return 0
    local whitelist="${PORT_WHITELIST:-22 80 443 8080 8443}"
    local listeners p
    listeners=$(awk 'NR>1 && $4=="0A" {print $2}' /proc/net/tcp 2>/dev/null | cut -d: -f2 | while read h; do echo $((16#$h)); done 2>/dev/null | sort -un)
    for p in $listeners; do
        case " $whitelist " in
            *" $p "*) ;;
            *) HUNTER_FINDINGS="${HUNTER_FINDINGS}port|medium|listener on port $p\n" ;;
        esac
    done
    hunter_log "port scan selesai"
}

# HUNTER MAIN
hunter_scan() {
    [ "$HUNTER_WATCH" != "on" ] && return 0
    hunter_init
    hunter_deface_scan
    hunter_corruption_scan
    hunter_process_scan
    hunter_token_scan
    hunter_port_scan
    echo -e "$HUNTER_FINDINGS" > "$HUNTER_STATE/findings.txt" 2>/dev/null
    hunter_log "scan selesai: $(echo -e "$HUNTER_FINDINGS" | grep -c '|') temuan"
}

# ============================================================
# PILAR U — HEALER: auto-remediasi temuan hunter
# ============================================================
healer_log() { log "healer: $*"; }

healer_fix_deface() {
    local target="$1"
    if [ -f "$target" ]; then
        local qdir="$STATE_DIR/quarantine"
        mkdir -p "$qdir" 2>/dev/null
        mv "$target" "$qdir/$(basename "$target").$(date +%s)" 2>/dev/null
        healer_log "deface quarantined: $target"
        PROBLEMS="${PROBLEMS}⚕️ HEALER: deface di-quarantine: $target\n"
    fi
}

healer_fix_corrupt() {
    local target="$1"
    local base bak
    base=$(basename "$target")
    # Proteksi: file KRITIS TIDAK di-quarantine — kalau ke-quarantine
    # (misal jobs.json), SEMUA cron mati. Alert only, butuh tangan owner.
    case "$base" in
        jobs.json|config.yaml|config.env|SOUL.md|.env|auth.json)
            healer_log "KRITIS $target korup — TIDAK di-quarantine (alert only, manual)"
            PROBLEMS="${PROBLEMS}⚕️ HEALER: file KRITIS korup (alert only, manual): $target\n"
            return 0
            ;;
    esac
    for bak in "$BACKUP_DIR"/*; do
        if [ "$(basename "$bak")" = "$base" ]; then
            cp "$bak" "$target" 2>/dev/null && healer_log "restored $target dari backup" && return 0
        fi
    done
    local qdir="$STATE_DIR/quarantine"
    mkdir -p "$qdir" 2>/dev/null
    mv "$target" "${qdir}/${base}.corrupt.$(date +%s)" 2>/dev/null
    healer_log "no backup untuk $target — quarantine"
    PROBLEMS="${PROBLEMS}⚕️ HEALER: file korup di-quarantine: $target\n"
}

healer_fix_process() {
    local pid_target="$1"
    pid_target="${pid_target%%:*}"
    if kill -9 "$pid_target" 2>/dev/null; then
        healer_log "killed suspicious process PID $pid_target"
        PROBLEMS="${PROBLEMS}⚕️ HEALER: proses anomali PID $pid_target di-kill\n"
    fi
}

healer_fix_token() {
    local detail="$1"
    healer_log "token bermasalah: $detail (alert only, tidak auto-rotasi)"
    PROBLEMS="${PROBLEMS}𒌐 HUNTER: token bermasalah: $detail\n"
}

healer_fix_port() {
    local detail="$1"
    healer_log "port anomali: $detail (alert only)"
    PROBLEMS="${PROBLEMS}𒌐 HUNTER: port anomali: $detail\n"
}

# HEALER MAIN
healer_apply() {
    [ "$HEALER_WATCH" != "on" ] && return 0
    local findings_file="$HUNTER_STATE/findings.txt"
    [ -s "$findings_file" ] || return 0
    local line type _ target
    while IFS='|' read -r type _ target; do
        [ -z "$type" ] && continue
        case "$type" in
            deface)  healer_fix_deface "$target" ;;
            corrupt) healer_fix_corrupt "$target" ;;
            process) healer_fix_process "$target" ;;
            token)   healer_fix_token "$target" ;;
            port)    healer_fix_port "$target" ;;
        esac
    done < "$findings_file"
}

# ============================================================

# ============================================================
# MODULE V: FIM WATCH (OSSEC syscheck-style) — v3.4
# File Integrity Monitoring: baseline sha256+perm+owner untuk file
# kritis (/etc/passwd, shadow, sshd_config, crontab, dll).
# Perubahan = tanda tamper -> alert. Baseline dibuat run pertama
# (tanpa alert). Dedup alert per-file (FIM_DEDUP_SEC).
# FIM_UPDATE_BASELINE=on -> baseline ikut di-update saat alert
# (buat file yang legit sering berubah).
# ============================================================
fim_watch() {
    [ "${FIM_WATCH:-on}" != "on" ] && return 0
    local fim_files="${FIM_FILES:-/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/crontab /etc/hosts}"
    local bdir="$STATE_DIR/fim_baseline"
    mkdir -p "$bdir" 2>/dev/null
    local f key baseline current last last_ts
    for f in $fim_files; do
        [ -f "$f" ] || continue
        key=$(printf '%s' "$f" | md5sum | awk '{print $1}')
        baseline="$bdir/$key"
        current="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')|$(stat -c '%a|%U' "$f" 2>/dev/null)"
        if [ ! -f "$baseline" ]; then
            printf '%s\n' "$current" > "$baseline" 2>/dev/null
            continue
        fi
        if [ "$(cat "$baseline" 2>/dev/null)" != "$current" ]; then
            last="$bdir/$key.alert_ts"
            last_ts=$(cat "$last" 2>/dev/null || echo 0)
            if [ $((NOW - last_ts)) -gt "${FIM_DEDUP_SEC:-3600}" ]; then
                PROBLEMS="${PROBLEMS}🚨 FIM: $f BERUBAH (hash/perm/owner mismatch) — tanda tamper!\\n"
                echo "$NOW" > "$last" 2>/dev/null
                if [ "${FIM_UPDATE_BASELINE:-off}" = "on" ]; then
                    printf '%s\n' "$current" > "$baseline" 2>/dev/null
                elif [ "${FIM_AUTO_RESTORE:-off}" = "on" ]; then
                    # v3.5: restore dari backup kalau tersedia (OSSEC-style)
                    local bak
                    bak="$BACKUP_DIR/$(basename "$f").bak"
                    if [ -f "$bak" ]; then
                        cp -f "$bak" "$f" 2>/dev/null && PROBLEMS="${PROBLEMS}♻️ FIM: $f di-restore dari backup\n" || PROBLEMS="${PROBLEMS}🔴 FIM: restore $f GAGAL\n"
                        printf '%s\n' "$current" > "$baseline" 2>/dev/null
                    fi
                fi
            fi
        fi
    done
}

# ============================================================
# MODULE W: AUTH BAN WATCH (Fail2ban-style) — v3.4
# Count failed login PER-IP dalam BAN_FINDTIME detik -> IP yang lewat
# BAN_MAXRETRY -> ban (ufw/iptables kalau tersedia) + state file.
# Unban otomatis setelah BAN_TIME. Dedup: 1x per IP (state file).
# Idle kalau /var/log/auth.log tidak ada (container minimal).
# ============================================================
auth_ban_watch() {
    [ "${AUTH_BAN_WATCH:-on}" != "on" ] && return 0
    local auth_log="/var/log/auth.log"
    local findtime="${BAN_FINDTIME:-600}"
    local maxretry="${BAN_MAXRETRY:-5}"
    local bantime="${BAN_TIME:-3600}"
    # v3.5: journald fallback — container modern gak selalu punya auth.log
    if [ ! -f "$auth_log" ] && command -v journalctl >/dev/null 2>&1; then
        auth_log="$STATE_DIR/auth_journal.txt"
        journalctl -u ssh -u sshd --since "$findtime seconds ago" --no-pager -o cat 2>/dev/null | grep -iE "Failed password|Invalid user|authentication failure" > "$auth_log" 2>/dev/null
    fi
    [ -f "$auth_log" ] || return 0
    local since ban_dir count ip state_file
    ban_dir="$STATE_DIR/auth_ban"
    mkdir -p "$ban_dir" 2>/dev/null
    since=$(date -u -d "$findtime seconds ago" '+%b %e %H:%M' 2>/dev/null)
    while read -r count ip; do
        [ -n "$ip" ] || continue
        [ "$count" -lt "$maxretry" ] && continue
        case "$ip" in *[!0-9.]*|"") continue ;; esac
        # v3.5: IP whitelist (fail2ban ignoreip) — jangan ban diri sendiri/infra
        case " ${BAN_IP_WHITELIST:-} " in *" $ip "*) continue ;; esac
        state_file="$ban_dir/$ip"
        if [ ! -f "$state_file" ]; then
            echo "$NOW" > "$state_file" 2>/dev/null
            local banned=0
            if command -v ufw >/dev/null 2>&1; then ufw deny from "$ip" 2>/dev/null && banned=1; fi
            if command -v iptables >/dev/null 2>&1; then iptables -A INPUT -s "$ip" -j DROP 2>/dev/null && banned=1; fi
            if [ "$banned" -eq 0 ] && [ ! -f "$ban_dir/.no_firewall" ]; then
                echo "$NOW" > "$ban_dir/.no_firewall" 2>/dev/null
                PROBLEMS="${PROBLEMS}⚠️ AUTH BAN: IP $ip butuh di-ban tapi ufw/iptables tidak ada — pasang firewall atau gunakan state manual\n"
            fi
            PROBLEMS="${PROBLEMS}🚨 AUTH BAN: $ip di-ban (${count} failed login dalam ${findtime}s)\n"
        fi
    done < <(awk -v s="$since" 'BEGIN{IGNORECASE=1}
        /Failed password|Invalid user|authentication failure/ && $0 >= s {
            for(i=1;i<=NF;i++) if($i=="from") print $(i+1)
        }' "$auth_log" 2>/dev/null | sort | uniq -c | sort -rn)
    # Unban otomatis setelah bantime
    local f ip_ts ip
    for f in "$ban_dir"/*; do
        [ -f "$f" ] || continue
        ip_ts=$(cat "$f" 2>/dev/null || echo 0)
        if [ $((NOW - ip_ts)) -gt "$bantime" ]; then
            ip=$(basename "$f")
            if command -v iptables >/dev/null 2>&1; then iptables -D INPUT -s "$ip" -j DROP 2>/dev/null; fi
            if command -v ufw >/dev/null 2>&1; then ufw delete deny from "$ip" 2>/dev/null; fi
            rm -f "$f" 2>/dev/null
            log "auth_ban: unban $ip (bantime habis)"
        fi
    done
}

rootcheck_watch() {
    [ "${ROOTCHECK_WATCH:-on}" != "on" ] && return 0
    local wl="${ROOTCHECK_SETUID_WHITELIST:-}"
    # 1) setuid/setgid scan — baseline list
    local su_baseline="$STATE_DIR/rootcheck_setuid.baseline"
    local su_now su_old new_bin
    su_now=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)
    if [ ! -f "$su_baseline" ]; then
        printf '%s\n' "$su_now" > "$su_baseline" 2>/dev/null
    else
        su_old=$(cat "$su_baseline" 2>/dev/null)
        for new_bin in $(comm -13 <(printf '%s\n' "$su_old") <(printf '%s\n' "$su_now") 2>/dev/null); do
            case " $wl " in *" $new_bin "*) continue ;; esac
            PROBLEMS="${PROBLEMS}🚨 ROOTCHECK: setuid/setgid BARU: $new_bin — potensi privilege escalation!\\n"
        done
        printf '%s\n' "$su_now" > "$su_baseline" 2>/dev/null
    fi
    # 2) hidden process — double check (hindari transient race)
    local h1 h2 pid persistent=""
    h1=$(comm -23 <(ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort -n) <(ps -e -o pid= 2>/dev/null | tr -d ' ' | sort -n) 2>/dev/null)
    if [ -n "$h1" ]; then
        sleep 1
        h2=$(comm -23 <(ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort -n) <(ps -e -o pid= 2>/dev/null | tr -d ' ' | sort -n) 2>/dev/null)
        for pid in $h1; do
            case " $h2 " in *" $pid "*)
                # persisten di /proc — cek cmdline (kernel thread = kosong, skip)
                if [ -s "/proc/$pid/cmdline" ]; then
                    persistent="$persistent $pid"
                fi
                ;;
            esac
        done
        if [ -n "$persistent" ]; then
            PROBLEMS="${PROBLEMS}🟡 ROOTCHECK: proses hidden persisten (ada cmdline, gak di ps):${persistent}\\n"
        fi
    fi
    # 3) interface promiscuous
    local iface flags iname
    for iface in /sys/class/net/*/flags; do
        [ -f "$iface" ] || continue
        flags=$(cat "$iface" 2>/dev/null || echo 0)
        case "$flags" in 0x*) ;; *) continue ;; esac
        if [ $((flags & 0x40)) -ne 0 ] 2>/dev/null; then
            iname=$(basename "$(dirname "$iface")")
            # v3.5: whitelist interface (docker bridge dll legit promisc)
            case " ${ROOTCHECK_PROMISC_WHITELIST:-} " in *" $iname "*) continue ;; esac
            PROBLEMS="${PROBLEMS}🟡 ROOTCHECK: interface $iname PROMISC — kemungkinan sniffing!\\n"
        fi
    done
}

# PILAR v3.0 — eksekusi di main flow (sebelum alert block)
# ============================================================
if [ "${SENTINEL_FUNC_TEST:-0}" != "1" ]; then
rotate_log
self_integrity
config_watch
secret_vault
core_vault_backup
auto_sync_backups
life_loop
cron_self_register
cron_failure_watch
gateway_watch
    gateway_health_check
github_repo_monitor
hunter_scan
healer_apply
fim_watch
auth_ban_watch
rootcheck_watch

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
        MSG="🛰️ SENTINEL ALERT (v3.0 PHOENIX)
$(echo -e "$PROBLEMS")"
        send_alert "$MSG"
        echo "$ALERT_HASH" > "$LAST_FILE"
        echo "$NOW" > "$LAST_TS_FILE"
    fi
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $PROBLEMS" >> "$LOG_FILE" 2>/dev/null
fi

exit 0
fi
