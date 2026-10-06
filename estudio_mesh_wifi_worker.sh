#!/bin/sh
# SPDX-License-Identifier: MIT
# Supervise authenticated native handoffs. The native transaction owns all
# state and rollback decisions; this parent detects an uncatchable worker exit.
set -eu
umask 077
mode=${1:-receive}
case "$mode" in receive|serve|receive-config|serve-config) ;; *) exit 1 ;; esac
test "$(cat /sys/class/net/eth0/address)" = 02:00:00:00:00:19
ucode -e 'import { storage_ok } from "/tmp/estudio_mesh_storage.uc"; if (!storage_ok()) exit(9);'
exec 9>/tmp/codex-mesh-worker.lock
flock -n 9 || exit 1
trap 'rm -f /tmp/codex-mesh-apply/worker.pid' EXIT
mkdir -p /tmp/codex-mesh-apply
rm -f /tmp/codex-mesh-apply/worker.pid
ucode /tmp/estudio_mesh_wifi_apply.uc "$mode" &
worker=$!
printf '%s\n' "$worker" > /tmp/codex-mesh-apply/worker.pid.new
mv /tmp/codex-mesh-apply/worker.pid.new /tmp/codex-mesh-apply/worker.pid
stop() {
    kill -TERM "$worker" 2>/dev/null || true
}
trap stop TERM INT HUP
status=0
wait "$worker" || status=$?
if [ "$status" != 0 ]; then
    ucode /tmp/estudio_mesh_wifi_apply.uc recover || exit 1
fi
rm -f /tmp/codex-mesh-apply/worker.pid
exit "$status"
