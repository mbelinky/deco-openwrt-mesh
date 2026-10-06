#!/bin/sh
# SPDX-License-Identifier: MIT
# Read-only collector. The service CLI owns device identity and RAM-only checks.
# Stream to the caller: never accumulate diagnostic files on the spare.
set -eu
section() { printf '\nESTUDIO_MEMORY_SECTION %s\n' "$1"; }
read_proc() {
    section "$1"
    if [ -r "$2" ]; then cat "$2" || printf 'UNAVAILABLE\n';
    else printf 'UNAVAILABLE\n'; fi
}
read_proc boot_start /proc/sys/kernel/random/boot_id
read_proc uptime /proc/uptime
read_proc meminfo /proc/meminfo
read_proc vmstat /proc/vmstat
read_proc buddyinfo /proc/buddyinfo
read_proc zoneinfo /proc/zoneinfo
read_proc slabinfo /proc/slabinfo
read_proc pressure /proc/pressure/memory
section processes
# Do not collect command lines, environment, configuration or file contents.
for path in /proc/[0-9]*/status; do
    [ -r "$path" ] || continue
    awk '/^(Name|Pid|PPid|VmPeak|VmSize|VmHWM|VmRSS|RssAnon|RssFile|RssShmem|VmData|VmStk|VmExe|VmLib|VmPTE|VmSwap|Threads):/ {print}' "$path" 2>/dev/null || true
    printf '\n'
done
section filesystems
df -k / /tmp
section temporary_kib
for path in /tmp /tmp/oem-mesh-peer /tmp/codex-mesh-join /tmp/estudio-mesh-resident /tmp/codex-wpad-live-cycle; do
    [ ! -e "$path" ] || du -sk "$path"
done
read_proc boot_end /proc/sys/kernel/random/boot_id
section complete
printf '1\n'
