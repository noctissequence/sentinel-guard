#!/bin/bash
# ============================================================
# sentinel-secondary-wrapper.sh — Jalankan sentinel dengan config secondary
# Dipakai oleh cron Hermes (no_agent) untuk sentinel Merlin.
# ============================================================
export SENTINEL_CONFIG=/etc/sentinel-guard-secondary/config.env
exec /usr/local/bin/sentinel-guard.sh
