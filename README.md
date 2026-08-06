# 🛰️ Sentinel Guard

Dead-man's switch + security watchdog untuk server/container. Monitor service, deteksi serangan, auto-restart service yang down, kirim alert ke Telegram.

> ⚠️ **Repo ini pernah di-deface oleh hacker (@attacker, 2026-08-05)** — file asli sudah dipulihkan. Verifikasi integritas sebelum pakai: `sha256sum sentinel.sh`.

## Fitur

| Modul | Fungsi |
|---|---|
| **A — Cascade & Units** | Monitor systemd units, detect cascade failure, recovery orchestrator |
| **B — State Files** | Validasi JSON state files (deteksi corrupt) |
| **C — Port Watch** | Deteksi port baru yang kebuka (root cause fix pasca-hack) |
| **D — SSH Key Watch** | Authorized_keys berubah / key baru = alert + backup |
| **E — Process Watch** | Reverse shell / miner / proses mencurigakan (auto-kill) |
| **F — Cron/User Watch** | Cron baru, user baru, sudoers berubah |
| **G — File Integrity** | Tripwire: file kritis berubah → alert |
| **H — Auto-Lockdown** | Response terakhir: lock down kalau serangan terdeteksi |
| **I — Immutable Watch** | File kritis di-immutable (chattr +i) |
| **J — Auth Log Watch** | Brute force / login mencurigakan → auto-ban IP |
| **K — HTTP Service Watch** | **Container-aware (tanpa systemd)** — health check HTTP + auto-restart |

## Quick Start

```bash
# 1. Setup
mkdir -p /etc/sentinel-guard
cp config.env.example /etc/sentinel-guard/config.env
nano /etc/sentinel-guard/config.env   # isi TELEGRAM_BOT_TOKEN + chat ID

# 2. Install script
cp sentinel.sh /usr/local/bin/sentinel-guard.sh
chmod +x /usr/local/bin/sentinel-guard.sh

# 3. Cron tiap 2 menit
(crontab -l 2>/dev/null; echo "*/2 * * * * /usr/local/bin/sentinel-guard.sh") | crontab -

# Atau di Hermes Agent: buat cron job no_agent script=sentinel.sh setiap 2 menit
```

## Modul K — HTTP Service Watch (penting di container)

Di container biasanya **tidak ada systemd**, jadi Modul A tidak jalan. Modul K health check via HTTP:

```env
HTTP_WATCH=on
HTTP_SERVICES="myapp|http://127.0.0.1:8080/health|200"
MYAPP_RESTART_CMD="cd /path/to/app && nohup python3 server.py > /var/log/myapp.log 2>&1 &"
```

Kalau service down → auto-restart via `*_RESTART_CMD` → kalau masih down setelah restart → alert crash-loop.

## Alert Dedup

Alert yang sama dalam 1 jam tidak dikirim ulang (kecuali severity naik) — anti spam Telegram.

## Requirements

- `curl` (alert Telegram + HTTP watch)
- `md5sum`, `sha256sum` (integrity)
- systemd (opsional — Modul A skip otomatis kalau tidak ada)
- chattr (opsional — Modul I skip di container tanpa CAP_LINUX_IMMUTABLE)
