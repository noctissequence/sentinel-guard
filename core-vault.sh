#!/bin/bash
# ============================================================
# core-vault.sh — SENTINEL CORE VAULT v2 (ASYMMETRIC, Pilar R)
# Backup SUPER-restricted: hanya Owner yang bisa decrypt.
#
# DESIGN v2 (anti-root total):
#   - RSA-4096 keypair:
#       core_public.pem   = di sistem, sentinel encrypt (write)
#       core_private.pem  = DI-ENCRYPT AES dgn kode Owner,
#                           plaintext DIHAPUS dari sistem.
#   - Sentinel auto-backup pakai PUBLIC key (tanpa kode).
#   - Decrypt/restore: butuh kode Owner untuk unlock private key.
#   - Attacker root penuh (dapet sistem + semua file):
#       public key doang -> TIDAK BISA decrypt.
#       private.enc -> butuh kode Owner -> TIDAK BISA.
# ============================================================
set -u

CORE_DIR="/etc/sentinel-guard/core"
PUB_KEY="$CORE_DIR/core_public.pem"
PRIV_ENC="$CORE_DIR/core_private.enc"
PRIV_TMP=""
LOG="/var/log/sentinel-guard.log"

core_log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG" 2>/dev/null; }

# --- init: pastikan struktur ---
core_init() {
    mkdir -p "$CORE_DIR" 2>/dev/null
    chmod 700 "$CORE_DIR" 2>/dev/null
    [ -f "$PUB_KEY" ] || {
        core_log "core vault: public key TIDAK ADA — generate keypair"
        openssl genrsa -out "$CORE_DIR/core_private.pem" 4096 2>/dev/null
        openssl rsa -in "$CORE_DIR/core_private.pem" -pubout -out "$PUB_KEY" 2>/dev/null
        chmod 600 "$PUB_KEY" "$CORE_DIR/core_private.pem" 2>/dev/null
        core_log "core vault: keypair generated (WAIT — private key harus di-encrypt + dihapus!)"
    }
}

# --- encrypt private key dengan kode Owner (sekali, saat setup) ---
# Usage: core-vault.sh seal-private '<kode>'
core_seal_private() {
    local code="$1"
    [ -f "$CORE_DIR/core_private.pem" ] || { echo "ERROR: core_private.pem tidak ada"; exit 1; }
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "$CORE_DIR/core_private.pem" -out "$PRIV_ENC" \
        -pass pass:"$code" 2>/dev/null
    chmod 600 "$PRIV_ENC" 2>/dev/null
    # HAPUS plaintext private key dari sistem — kritis!
    rm -f "$CORE_DIR/core_private.pem"
    core_log "core vault: private key ENCRYPTED + plaintext DIHAPUS"
    echo "OK: private key di-seal. Plaintext dihapus dari sistem."
}

# --- unlock private key (sementara, ke memori/tmp 600) ---
core_unlock_private() {
    local code="$1"
    [ -f "$PRIV_ENC" ] || return 1
    PRIV_TMP=$(mktemp /tmp/.core_priv_XXXXXX.pem)
    chmod 600 "$PRIV_TMP"
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
        -in "$PRIV_ENC" -out "$PRIV_TMP" \
        -pass pass:"$code" 2>/dev/null; then
        rm -f "$PRIV_TMP"
        PRIV_TMP=""
        return 1
    fi
    return 0
}

core_cleanup_priv() { [ -n "$PRIV_TMP" ] && rm -f "$PRIV_TMP"; PRIV_TMP=""; }

# --- encrypt file ke core (WRITE — sentinel auto, pakai PUBLIC key) ---
# Usage: core-vault.sh backup <src_path> <name>
core_backup() {
    local src="$1" name="$2"
    core_init
    [ -f "$src" ] || return 1
    [ -f "$PUB_KEY" ] || return 1
    # RSA encrypt: hybrid — random AES key di-encrypt RSA, data di-encrypt AES
    local aes_key tmp_enc
    aes_key=$(openssl rand -hex 32)
    tmp_enc=$(mktemp /tmp/.core_enc_XXXXXX)
    # AES-encrypt payload dengan random key
    echo -n "$aes_key" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 \
        -in /dev/stdin -out "$tmp_enc.aeskey" -pass pass:"x" 2>/dev/null
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 10000 \
        -in "$src" -out "$tmp_enc.data" -pass pass:"$aes_key" 2>/dev/null
    # Encrypt AES key dengan RSA public key
    openssl pkeyutl -encrypt -pubin -inkey "$PUB_KEY" \
        -in <(echo -n "$aes_key") -out "$tmp_enc.rsa" 2>/dev/null
    # Bundle: rsa key + data
    { echo "COREV2"; echo "RSA4096"; base64 < "$tmp_enc.rsa"; echo "DATA"; base64 < "$tmp_enc.data"; } > "$CORE_DIR/$name.core"
    chmod 600 "$CORE_DIR/$name.core" 2>/dev/null
    rm -f "$tmp_enc" "$tmp_enc.aeskey" "$tmp_enc.data" "$tmp_enc.rsa"
    core_log "core vault: backed up $name (RSA-encrypted)"
    return 0
}

# --- decrypt dari core (READ — butuh kode Owner) ---
# Usage: core-vault.sh restore <name> <dst> '<kode>'
core_restore() {
    local name="$1" dst="$2" code="$3"
    [ -f "$CORE_DIR/$name.core" ] || { echo "ERROR: $name.core tidak ada"; exit 1; }
    core_unlock_private "$code" || { echo "ERROR: access code salah. Restore ditolak."; exit 1; }
    local tmp_dec rsa_b64 data_b64 aes_key
    tmp_dec=$(mktemp /tmp/.core_dec_XXXXXX)
    # Parse bundle
    awk '/^DATA$/{f=1;next} f' "$CORE_DIR/$name.core" | base64 -d > "$tmp_dec.data" 2>/dev/null
    awk '/^RSA4096$/{f=1;next} /^DATA$/{f=0} f' "$CORE_DIR/$name.core" | base64 -d > "$tmp_dec.rsa" 2>/dev/null
    # Decrypt AES key dengan private key
    if ! openssl pkeyutl -decrypt -inkey "$PRIV_TMP" -in "$tmp_dec.rsa" -out "$tmp_dec.aeskey" 2>/dev/null; then
        rm -f "$tmp_dec" "$tmp_dec.data" "$tmp_dec.rsa" "$tmp_dec.aeskey"
        core_cleanup_priv
        echo "ERROR: decrypt gagal"
        exit 1
    fi
    aes_key=$(cat "$tmp_dec.aeskey")
    # Decrypt data
    if openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 \
        -in "$tmp_dec.data" -out "$dst" -pass pass:"$aes_key" 2>/dev/null && [ -s "$dst" ]; then
        core_log "core vault: restored $name (private key unlocked)"
        echo "OK: $name restored ke $dst"
    else
        echo "ERROR: decrypt data gagal"
        exit 1
    fi
    rm -f "$tmp_dec" "$tmp_dec.data" "$tmp_dec.rsa" "$tmp_dec.aeskey"
    core_cleanup_priv
}

# --- status ---
core_status() {
    echo "=== CORE VAULT STATUS (v2 asymmetric) ==="
    echo "Dir: $CORE_DIR (mode $(stat -c '%a' "$CORE_DIR" 2>/dev/null))"
    echo "Public key: $([ -f "$PUB_KEY" ] && echo 'ADA' || echo 'MISSING')"
    echo "Private key: $([ -f "$PRIV_ENC" ] && echo 'ENCRYPTED (sealed)' || echo 'belum di-seal!')"
    echo "Private plaintext: $([ -f "$CORE_DIR/core_private.pem" ] && echo '⚠️ MASIH ADA — harus dihapus!' || echo 'TIDAK ADA (aman)')"
    echo "Files:"
    ls -la "$CORE_DIR"/*.core 2>/dev/null | awk '{print "  " $NF " (" $5 "B)"}'
}

case "${1:-}" in
    seal-private) core_seal_private "${2:-}" ;;
    backup)       core_backup "${2:-}" "${3:-}" ;;
    restore)      core_restore "${2:-}" "${3:-}" "${4:-}" ;;
    status)       core_status ;;
    *) echo "Usage: core-vault.sh {seal-private|backup|restore|status}" ;;
esac
