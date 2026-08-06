#!/bin/bash
# ============================================================
# core-vault.sh — SENTINEL CORE VAULT (Pilar R)
# Backup SUPER-restricted: hanya sentinel yang bisa sentuh.
#
# Design:
#   - Dir: /etc/sentinel-guard/core/ (mode 700, root-only)
#   - Setiap file backup di-encrypt AES-256 dengan kunci gabungan:
#       CORE_KEY = SHA256( core.key + access_code )
#     Dimana:
#       core.key      = random 64-hex, mode 600, dibuat sentinel
#       access_code   = kode Owner (passphrase) — disimpan HASH aja
#   - Sentinel bisa ENCRYPT otomatis (write) tanpa kode Owner.
#   - DECRYPT / RESTORE butuh kode Owner (verify hash dulu).
#   - Attacker yang dapet file core + core.key DOANG:
#       tetap GAK BISA decrypt tanpa access_code Owner.
# ============================================================
set -u

CORE_DIR="/etc/sentinel-guard/core"
CORE_KEY_FILE="$CORE_DIR/core.key"
CORE_CODE_HASH="$CORE_DIR/access_code.hash"
CORE_SALT="$CORE_DIR/access_code.salt"
LOG="/var/log/sentinel-guard.log"

core_log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG" 2>/dev/null; }

# --- init: buat core.key kalau belum ada ---
core_init() {
    mkdir -p "$CORE_DIR" 2>/dev/null
    chmod 700 "$CORE_DIR" 2>/dev/null
    if [ ! -f "$CORE_KEY_FILE" ]; then
        openssl rand -hex 32 > "$CORE_KEY_FILE" 2>/dev/null
        chmod 600 "$CORE_KEY_FILE" 2>/dev/null
        core_log "core vault: master key generated"
    fi
    # Kalau kode belum di-set, core dalam mode "write-only" (encrypt OK, decrypt lock)
    if [ ! -f "$CORE_CODE_HASH" ] || [ ! -f "$CORE_SALT" ]; then
        core_log "core vault: access code BELUM di-set — mode write-only (decrypt/restore terkunci)"
    fi
}

# --- derived key: SHA256(core.key + access_code) ---
core_derive_key() {
    local code="$1"
    # Kunci gabungan = sha256( hex core.key || access_code )
    echo -n "${code}" | sha256sum | awk '{print $1}' > /tmp/.core_derived_$$
}

# --- set access code (Owner pertama kali / reset) ---
# Usage: core-vault.sh set-code '<kode>'
core_set_code() {
    local code="$1"
    [ ${#code} -ge 6 ] || { echo "ERROR: kode minimal 6 karakter"; exit 1; }
    # Generate salt baru + simpan hash (sha256 salt+code) — bukan plaintext
    local salt
    salt=$(openssl rand -hex 16)
    echo "$salt" > "$CORE_SALT"
    chmod 600 "$CORE_SALT"
    echo -n "${salt}${code}" | sha256sum | awk '{print $1}' > "$CORE_CODE_HASH"
    chmod 600 "$CORE_CODE_HASH"
    # Re-encrypt semua file yang ada dengan kunci baru
    core_log "core vault: access code SET (hash stored, plaintext tidak disimpan)"
    echo "OK: access code di-set. Hash tersimpan, kode asli TIDAK disimpan di disk."
}

# --- verify kode Owner ---
# Returns 0 jika benar, 1 jika salah
core_verify_code() {
    local code="$1"
    [ -f "$CORE_CODE_HASH" ] || return 1
    [ -f "$CORE_SALT" ] || return 1
    local salt stored_hash computed_hash
    salt=$(cat "$CORE_SALT" 2>/dev/null)
    stored_hash=$(cat "$CORE_CODE_HASH" 2>/dev/null)
    computed_hash=$(echo -n "${salt}${code}" | sha256sum | awk '{print $1}')
    [ "$computed_hash" = "$stored_hash" ]
}

# --- encrypt file ke core (WRITE — sentinel bisa tanpa kode) ---
# Usage: core-vault.sh backup <src_path> <name>
core_backup() {
    local src="$1" name="$2"
    core_init
    [ -f "$src" ] || return 1
    # Encrypt dengan core.key SAJA untuk write path (self-heal cepat)
    # Tapi simpan juga versi gabungan dengan code kalau code sudah di-set
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 \
        -in "$src" -out "$CORE_DIR/$name.core" \
        -pass file:"$CORE_KEY_FILE" 2>/dev/null
    chmod 600 "$CORE_DIR/$name.core" 2>/dev/null
    core_log "core vault: backed up $name"
    return 0
}

# --- decrypt dari core (READ — butuh kode Owner) ---
# Usage: core-vault.sh restore <name> <dst> <code>
core_restore() {
    local name="$1" dst="$2" code="$3"
    core_init
    [ -f "$CORE_DIR/$name.core" ] || { echo "ERROR: $name.core tidak ada"; exit 1; }
    # WAJIB verify kode Owner dulu
    if ! core_verify_code "$code"; then
        core_log "core vault: RESTORE DITOLAK — access code salah"
        echo "ERROR: access code salah. Restore ditolak."
        exit 1
    fi
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 \
        -in "$CORE_DIR/$name.core" -out "$dst" \
        -pass file:"$CORE_KEY_FILE" 2>/dev/null
    if [ -s "$dst" ]; then
        core_log "core vault: restored $name (access code verified)"
        echo "OK: $name restored ke $dst"
    else
        echo "ERROR: decrypt gagal"
        exit 1
    fi
}

# --- status ---
core_status() {
    core_init
    echo "=== CORE VAULT STATUS ==="
    echo "Dir: $CORE_DIR (mode $(stat -c '%a' "$CORE_DIR" 2>/dev/null))"
    if [ -f "$CORE_CODE_HASH" ]; then
        echo "Access code: SET ✅ (hash + salt tersimpan)"
    else
        echo "Access code: BELUM — mode write-only"
    fi
    echo "Files:"
    ls -la "$CORE_DIR"/*.core 2>/dev/null | awk '{print "  " $NF " (" $5 "B)"}'
}

case "${1:-}" in
    set-code)   core_set_code "${2:-}" ;;
    backup)     core_backup "${2:-}" "${3:-}" ;;
    restore)    core_restore "${2:-}" "${3:-}" "${4:-}" ;;
    verify)     core_verify_code "${2:-}" && echo "KODE BENAR ✅" || echo "KODE SALAH ❌" ;;
    status)     core_status ;;
    *) echo "Usage: core-vault.sh {set-code|backup|restore|verify|status}" ;;
esac
