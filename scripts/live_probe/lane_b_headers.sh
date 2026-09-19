#!/usr/bin/env bash
# Lane B — Step 5 : relevé des en-têtes réels (jamais documentés dans les schémas).
# Lance chaque outil SANS paramètre de réduction, garde la première ligne.
# Usage: lane_b_headers.sh BIN [--host raspberry]
set -euo pipefail
BIN="${1:-/home/muchini/bmcp-test-0909/target/release/bridge-mcp}"
HOST="${2:-raspberry}"
ARC="/tmp/bridge-test-0909/lane-b/arc.tar"

echo "=== ssh_alert_list ==="
$BIN tool ssh_alert_list host="$HOST" 2>/dev/null | head -1
echo "=== ssh_template_list ==="
$BIN tool ssh_template_list host="$HOST" 2>/dev/null | head -1
echo "=== ssh_process_list ==="
$BIN tool ssh_process_list host="$HOST" 2>/dev/null | head -1
echo "=== ssh_cron_history ==="
$BIN tool ssh_cron_history host="$HOST" 2>/dev/null | head -1
echo "=== ssh_log_aggregate ==="
$BIN tool ssh_log_aggregate host="$HOST" log_files=/var/log/syslog 2>/dev/null | head -1
echo "=== ssh_k8s_top ==="
$BIN tool ssh_k8s_top host="$HOST" resource_type=nodes 2>/dev/null | head -1
echo "=== ssh_backup_list ==="
$BIN tool ssh_backup_list host="$HOST" archive_file="$ARC" 2>/dev/null | head -1
