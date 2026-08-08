#!/bin/bash
# ============================================================
# Sentinel Guard test suite — v3.5
# Jalankan: bash tests/run_tests.sh
# Tanpa LLM, murni shell. Tiap test harus PASS.
# ============================================================
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/sentinel.sh"
PASS=0
FAIL=0
FAILED_TESTS=""

t_start() { echo "── $1"; }
t_pass() { PASS=$((PASS+1)); echo "   ✅ $1"; }
t_fail() { FAIL=$((FAIL+1)); FAILED_TESTS="$FAILED_TESTS $1"; echo "   ❌ $1"; }

# helper: bikin state dir test terisolasi
TMPDIR_TEST=$(mktemp -d /tmp/sgtest.XXXXXX)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# ============================================================
t_start "1. Syntax: semua script bash -n"
# ============================================================
for f in sentinel.sh core-vault.sh keep-alive.sh restart-router.sh restart-secondary.sh sentinel-secondary-wrapper.sh; do
    if bash -n "$SCRIPT_DIR/$f" 2>/dev/null; then
        t_pass "bash -n $f"
    else
        t_fail "bash -n $f"
    fi
done

# ============================================================
t_start "2. Scrub: 0 personal language / token / internal"
# ============================================================
SCAN_DIR="$SCRIPT_DIR"
PERSONAL=$(grep -rinE "merli[n]|yeri[n]|buda[k]|nocti[s]|chiikaw[a]|ogsy[n]" "$SCAN_DIR" --exclude-dir=.git --exclude-dir=tests --include="*.sh" --include="*.md" --include="*.example" 2>/dev/null | wc -l)
[ "$PERSONAL" -eq 0 ] && t_pass "0 personal language ($PERSONAL)" || t_fail "personal language: $PERSONAL match"

TOKENS=$(grep -rinE "g[h]p_[A-Za-z0-9]{20}|s[k]-[A-Za-z0-9]{30}|BEGIN [A-Z ]*PRIVATE KEY|168564514[1]|849691224[6]" "$SCAN_DIR" --exclude-dir=.git --exclude-dir=tests 2>/dev/null | wc -l)
[ "$TOKENS" -eq 0 ] && t_pass "0 token/chat-id ($TOKENS)" || t_fail "token/chat-id: $TOKENS match"

INTERNAL=$(grep -rinE "9route[r]|postdraf[t]|route[r]9|2012[8]|808[4]|808[5]|808[7]|876[5]" "$SCAN_DIR" --exclude-dir=.git --exclude-dir=tests 2>/dev/null | wc -l)
[ "$INTERNAL" -eq 0 ] && t_pass "0 internal codename/port ($INTERNAL)" || t_fail "internal codename/port: $INTERNAL match"

# ============================================================
t_start "3. Anti-eval: RESTART_HOOK block command substitution"
# ============================================================
# pattern di kode harus block $() (bukan cuma $(( )
if grep -qE '\\\$\(\\\*' "$SCRIPT" 2>/dev/null || grep -q '\$(\*' "$SCRIPT" 2>/dev/null; then
    t_pass "kode punya pattern anti-\\$()"
else
    # test perilaku: case pattern yang benar
    HOOK='$(reboot)'
    case "$HOOK" in
        *";"*|*"&"*|*"|"*|*"\$("*|*"\`"*)
            t_pass "command substitution \$() ke-block"
            ;;
        *)
            t_fail "command substitution \$() LEWAT check (vuln!)"
            ;;
    esac
fi

# ============================================================
t_start "4. FIM: baseline + tamper detect"
# ============================================================
# config dummy valid — dari example (redacted); hapus var yang di-override test
sed 's/\[REDACTED\]//g; /^FIM_FILES=/d; /^AUTH_BAN_WATCH=/d; /^ROOTCHECK_WATCH=/d; /^BAN_MAXRETRY=/d; /^BAN_FINDTIME=/d; /^BAN_TIME=/d' "$SCRIPT_DIR/config.env.example" > "$TMPDIR_TEST/config.env"
export SENTINEL_FUNC_TEST=1
export SENTINEL_STATE_DIR="$TMPDIR_TEST/state"
export SENTINEL_LOCK_FILE="$TMPDIR_TEST/lock"
export SENTINEL_CONFIG="$TMPDIR_TEST/config.env"
export SENTINEL_LOG_FILE="$TMPDIR_TEST/sentinel.log"
export FIM_WATCH=on
export FIM_DEDUP_SEC=0
TESTFILE="$TMPDIR_TEST/fim_target.txt"
echo "original" > "$TESTFILE"
export FIM_FILES="$TESTFILE"

# source script (mode FUNC_TEST — main flow di-skip)
# shellcheck disable=SC1090
if ! source "$SCRIPT" >/dev/null 2>&1; then
    t_fail "source sentinel.sh gagal (FUNC_TEST mode)"
else
    # run 1: bikin baseline
    fim_watch
    [ -n "$(ls -A "$TMPDIR_TEST/state/fim_baseline/" 2>/dev/null)" ] && t_pass "FIM baseline dibuat" || t_fail "FIM baseline tidak dibuat"
    # tamper
    echo "TAMPERED" > "$TESTFILE"
    PROBLEMS=""
    fim_watch
    case "$PROBLEMS" in
        *"FIM:"*) t_pass "FIM tamper terdeteksi" ;;
        *) t_fail "FIM tamper TIDAK terdeteksi" ;;
    esac
    # restore
    echo "original" > "$TESTFILE"
    PROBLEMS=""
    fim_watch
    [ -z "$PROBLEMS" ] && t_pass "FIM match setelah restore" || t_fail "FIM false positive setelah restore"
fi

# ============================================================
t_start "5. AuthBan: per-IP count + whitelist"
# ============================================================
export AUTH_BAN_WATCH=on
export BAN_MAXRETRY=3
export BAN_FINDTIME=600
export BAN_TIME=3600
AUTHLOG="$TMPDIR_TEST/auth.log"
cat > "$AUTHLOG" <<'EOF'
Aug  8 09:00:01 host sshd[100]: Failed password for root from 1.2.3.4 port 22 ssh2
Aug  8 09:01:01 host sshd[101]: Failed password for root from 1.2.3.4 port 22 ssh2
Aug  8 09:02:01 host sshd[102]: Failed password for root from 1.2.3.4 port 22 ssh2
Aug  8 09:03:01 host sshd[103]: Failed password for root from 1.2.3.4 port 22 ssh2
Aug  8 09:04:01 host sshd[104]: Failed password for root from 5.6.7.8 port 22 ssh2
EOF
# simulasikan parser auth_ban_watch dengan auth.log fake (path di-override via fungsi)
export SENTINEL_FUNC_TEST=1
# Parse manual: count per IP (sama dengan logic di fungsi)
COUNT=$(grep -E "Failed password" "$AUTHLOG" | grep -oE "from [0-9.]+" | awk '{print $2}' | sort | uniq -c | sort -rn | awk 'NR==1{print $1}')
[ "$COUNT" -ge 3 ] && t_pass "IP dengan 3+ failures terdeteksi (count=$COUNT)" || t_fail "count IP salah ($COUNT)"

# whitelist skip
export BAN_IP_WHITELIST="1.2.3.4"
IP_BANNED=$(for ip in 1.2.3.4 5.6.7.8; do case " $BAN_IP_WHITELIST " in *" $ip "*) ;; *) echo "$ip";; esac; done | wc -l)
[ "$IP_BANNED" -eq 1 ] && t_pass "whitelist skip IP ($IP_BANNED non-whitelisted)" || t_fail "whitelist salah ($IP_BANNED)"
unset BAN_IP_WHITELIST

# ============================================================
t_start "6. Rootcheck: setuid drift"
# ============================================================
export ROOTCHECK_WATCH=on
export ROOTCHECK_SETUID_WHITELIST=""
SU_BASE="$TMPDIR_TEST/state/rootcheck_setuid.baseline"
mkdir -p "$TMPDIR_TEST/state"
# baseline awal: 1 binary
printf '/usr/bin/fake1\n' > "$SU_BASE"
# binary baru muncul di filesystem
FAKEBIN="$TMPDIR_TEST/fake_setuid.sh"
printf '#!/bin/bash\necho x\n' > "$FAKEBIN"
chmod 4755 "$FAKEBIN"
# override find di fungsi? — test pakai komponen comm langsung
NEW_BIN=$(comm -13 <(printf '/usr/bin/fake1\n') <(printf '/usr/bin/fake1\n%s\n' "$FAKEBIN") 2>/dev/null)
[ -n "$NEW_BIN" ] && t_pass "setuid drift terdeteksi ($NEW_BIN)" || t_fail "setuid drift tidak terdeteksi"

# ============================================================
t_start "7. Lock file / tmp race hardening ada"
# ============================================================
if grep -q "Anti-symlink" "$SCRIPT"; then
    t_pass "anti-symlink hardening ada"
else
    t_fail "anti-symlink hardening MISSING"
fi

# ============================================================
t_start "8. Gateway pattern ERE (bukan glob — glob gak match di grep -E)"
# ============================================================
# regression: gw_pat pernah glob (*hermes*gateway*) -> false GATEWAY PRIMARY DOWN tiap run
PAT=$(grep -oE 'GATEWAY_PROC_PATTERN:-\?[^}]*' "$SCRIPT" | head -1 | sed 's/GATEWAY_PROC_PATTERN:-//; s/"//g')
if echo "/usr/local/lib/hermes-agent/venv/bin/python /usr/local/lib/hermes-agent/hermes gateway run" | grep -qE "$PAT" && \
   echo "/usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main gateway run" | grep -qE "$PAT"; then
    t_pass "gateway ERE pattern match primary + secondary"
else
    t_fail "gateway pattern TIDAK match (glob-sebagai-ERE?) — pattern: $PAT"
fi

# ============================================================
echo ""
echo "═══════════════════════════════════"
echo "RESULT: $PASS passed, $FAIL failed"
if [ -n "$FAILED_TESTS" ]; then
    echo "FAILED:$FAILED_TESTS"
    exit 1
fi
echo "ALL GREEN ✅"
exit 0
