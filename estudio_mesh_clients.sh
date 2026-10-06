#!/bin/sh
# SPDX-License-Identifier: MIT
# RAM-only collection service. It publishes local observations, never mesh
# registration, controller client updates, or configuration acknowledgements.
set -eu
umask 077
node=0
if [ "${1:-}" = --node ]; then
    test "$#" = 4
    node=1;context=$2;wired_context=$3;root=$4
    test -f "$context" && test -f "$wired_context"
else
    context=${1:--}
    root=${2:-/tmp/estudio-mesh-clients}
fi
case "$root" in /tmp/*) ;; *) exit 2;; esac
mkdir -p "$root"
exec 9>"$root/lock"
flock -n 9 || exit 1
# A killed owner can leave its bounded capture child alive briefly. Children
# must not retain the owner lock or share a replacement owner's output file.
generation=$(cat /proc/sys/kernel/random/uuid)
next="$root/next.$generation.json"
errors="$root/error.$generation.log"
rm -f "$root/status.json" "$root"/next.*.json "$root"/error.*.log
child=
sequence=0
cycle="$root/cycle.$generation"
if [ "$node" = 1 ]; then mkdir "$cycle"; fi
collect_node() {
    # Refresh this runtime's native bridge classification after link recreation.
    # Other explicitly supplied collector contexts retain their own owner.
    if [ "$context" = /tmp/codex-mesh-join/private/wifi-context.json ] &&
       [ "$wired_context" = /tmp/codex-mesh-join/private/wired-context.json ]; then
        ucode /tmp/estudio_mesh_clients.uc - context > "$cycle/wifi-context.json"
        ucode /tmp/estudio_mesh_client_context.uc "$cycle/wifi-context.json" "$cycle/wired-context.json"
        mv "$cycle/wifi-context.json" "$context"
        mv "$cycle/wired-context.json" "$wired_context"
    fi
    context_before=$(sha256sum "$context" "$wired_context")
    ucode /tmp/estudio_mesh_clients.uc "$context" observe "$root/wifi-history.json" > "$cycle/wifi-first.json"
    ucode /tmp/estudio_mesh_wired_clients.uc "$wired_context" observe > "$cycle/wired-first.json"
    ucode /tmp/estudio_mesh_clients.uc "$context" snapshot "$cycle/wifi-first.json" > "$cycle/wifi-last.json"
    ucode /tmp/estudio_mesh_wired_clients.uc "$wired_context" > "$cycle/wired-last.json"
    test "$context_before" = "$(sha256sum "$context" "$wired_context")"
    ucode /tmp/estudio_mesh_client_report.uc --snapshot "$cycle/wifi-last.json" > "$cycle/wifi-report.json"
    ucode /tmp/estudio_mesh_client_report.uc --snapshot "$cycle/wired-first.json" > "$cycle/wired-report.json"
    ucode /tmp/estudio_mesh_client_node.uc "$context" "$wired_context" "$cycle" "$generation" "$sequence"
}
stop() {
    if [ -n "$child" ]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
    rm -f "$next" "$errors" "$root/status.json" "$root/status.next"
    if [ "$node" = 1 ]; then
        rm -f "$cycle"/wifi-first.json "$cycle"/wifi-last.json "$cycle"/wired-first.json "$cycle"/wired-last.json "$cycle"/wifi-report.json "$cycle"/wired-report.json "$cycle"/coverage.json "$cycle"/wifi-context.json "$cycle"/wired-context.json
        rmdir "$cycle" 2>/dev/null || true
    fi
    exit 0
}
trap stop TERM INT HUP
while :; do
    sequence=$((sequence+1))
    if [ "$node" = 1 ]; then
        # A function-call redirection makes ash save fd 9 on another fd so
        # it can restore it afterward. Close it permanently in the child;
        # otherwise an orphan worker prevents a replacement owner starting.
        (
            exec 9>&-
            collect_node
        ) > "$next" 2> "$errors" &
    else
        ucode /tmp/estudio_mesh_clients.uc "$context" observe "$root/snapshot.json" > "$next" 2> "$errors" 9>&- &
    fi
    child=$!
    if wait "$child"; then
        child=
        if [ "$node" = 1 ]; then
            mv "$cycle/coverage.json" "$root/coverage.json"
            mv "$next" "$root/current.json"
            mv "$cycle/wifi-last.json" "$root/wifi-history.json"
        else
            mv "$next" "$root/snapshot.json"
        fi
        state=observed
    else
        child=
        rm -f "$next"
        state=unavailable
    fi
    mv "$errors" "$root/error.log"
    printf '{"state":"%s","pid":%s,"updated_at":%s,"generation":"%s","collection_id":"%s:%s"}\n' "$state" "$$" "$(date +%s)" "$generation" "$generation" "$sequence" > "$root/status.next"
    mv "$root/status.next" "$root/status.json"
    sleep 2 9>&-
done
