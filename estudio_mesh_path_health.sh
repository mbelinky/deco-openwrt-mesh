#!/bin/sh
# SPDX-License-Identifier: MIT
# Read-only local-path check for the resident's owned management namespace.
# A failed internet endpoint is not evidence that its wireless parent failed.
set -u
unavailable() { printf '%s\n' unavailable; exit 0; }
if [ "$#" != 0 ]; then
    [ "$#" = 2 ] && [ "$1" = --radio ] || unavailable
    case "$2" in
        5g) port=sixbh.1; station=deco-sixsta; phy=phy1; mac=02:00:00:00:00:06
            frequency=5240; authentication=WPA2-PSK
            parents='02:00:00:00:00:15|02:00:00:00:00:1f|02:00:00:00:00:11|02:00:00:00:00:14';;
        6g) port=standby.1; station=deco-standby; phy=phy2; mac=02:00:00:00:00:07
            frequency=6135; authentication=SAE
            parents='02:00:00:00:00:16|02:00:00:00:00:1a|02:00:00:00:00:17';;
        *) unavailable;;
    esac
    [ "$(cat /sys/class/net/eth0/address 2>/dev/null)" = 02:00:00:00:00:19 ] || unavailable
    ucode -e 'import { storage_ok } from "/tmp/estudio_mesh_storage.uc"; if (!storage_ok()) exit(9);' || unavailable
    [ -e /tmp/estudio-mesh-resident/run.sh ] || unavailable
    [ -x /tmp/oem-mesh-peer/usr/sbin/tcpdump ] || unavailable
    index=$(cat "/sys/class/net/$port/ifindex" 2>/dev/null) || unavailable
    station_index=$(cat "/sys/class/net/$station/ifindex" 2>/dev/null) || unavailable
    original_parent=
    radio_ready() {
        [ "$(cat "/sys/class/net/$port/ifindex" 2>/dev/null)" = "$index" ] || return 1
        [ "$(cat "/sys/class/net/$station/ifindex" 2>/dev/null)" = "$station_index" ] || return 1
        [ "$(cat "/sys/class/net/$station/address" 2>/dev/null)" = "$mac" ] || return 1
        [ "$(cat "/sys/class/net/$port/address" 2>/dev/null)" = "$mac" ] || return 1
        [ "$(basename "$(readlink -f "/sys/class/net/$station/phy80211" 2>/dev/null)")" = "$phy" ] || return 1
        [ "$(basename "$(readlink -f "/sys/class/net/$port/master" 2>/dev/null)")" = br-sixbh ] || return 1
        [ "$(cat /sys/kernel/debug/ieee80211/phy2/user_power 2>/dev/null)" = 10 ] || return 1
        [ -z "$(ip -4 -o addr show dev "$port" 2>/dev/null)" ] || return 1
        state=$(wpa_cli -p /var/run/wpa_supplicant -i "$station" status 2>/dev/null) || return 1
        printf '%s\n' "$state" | grep -qx wpa_state=COMPLETED || return 1
        printf '%s\n' "$state" | grep -qx "freq=$frequency" || return 1
        printf '%s\n' "$state" | grep -qx "key_mgmt=$authentication" || return 1
        parent=$(printf '%s\n' "$state" | sed -n 's/^bssid=//p')
        printf '%s\n' "$parent" | grep -Eq "^($parents)$" || return 1
        [ -z "$original_parent" ] || [ "$parent" = "$original_parent" ] || return 1
    }
    radio_ready || unavailable
    original_parent=$parent
    root=$(mktemp -d /tmp/estudio-radio-path.XXXXXX) || unavailable
    capture_pid=
    radio_cleanup() {
        if [ -n "$capture_pid" ]; then
            kill "$capture_pid" 2>/dev/null || true
            wait "$capture_pid" 2>/dev/null || true
        fi
        rm -f "$root/reply" "$root/status"
        rmdir "$root"
    }
    trap radio_cleanup EXIT
    trap 'exit 130' INT TERM HUP
    # ETH_P_ALL sees replies at the VLAN before bridge input redirects ARP
    # sockets to the bridge device. The OEM arping utility cannot count them
    # here. Count only gateway replies addressed to this station's probe MAC;
    # never borrow the management/client MAC or assign another IPv4 address.
    filter="arp and ether src 02:00:00:00:00:13 and ether dst $mac and arp[6:2] = 2 and arp[14:4] = 0xc0a84401 and arp[24:4] = 0"
    capture_started=$(cut -d . -f 1 /proc/uptime)
    timeout 4 chroot /tmp/oem-mesh-peer /usr/sbin/tcpdump -p -n -e -l -s 96 -c 1 -i "$port" "$filter" > "$root/reply" 2> "$root/status" &
    capture_pid=$!
    listening=0
    for attempt in $(seq 1 2); do
        if grep -q "listening on $port," "$root/status"; then listening=1; break; fi
        kill -0 "$capture_pid" 2>/dev/null || break
        sleep 1
    done
    [ "$listening" = 1 ] || unavailable
    probe_code=0
    timeout 2 chroot /tmp/oem-mesh-peer /bin/busybox arping -D -c 1 -w 1 -I "$port" -s 0.0.0.0 198.18.68.1 > /dev/null 2>&1 || probe_code=$?
    case "$probe_code" in 0|1) ;; *) unavailable;; esac
    capture_code=0
    wait "$capture_pid" || capture_code=$?
    capture_pid=
    radio_ready || unavailable
    if [ "$capture_code" = 0 ] && grep -q 'Reply 198.18.68.1 is-at 02:00:00:00:00:13' "$root/reply"; then
        printf '%s\n' reachable
    elif { [ "$capture_code" = 124 ] || [ "$capture_code" = 0 ]; } &&
         [ "$(($(cut -d . -f 1 /proc/uptime)-capture_started))" -ge 3 ] &&
         ! grep -q '[^[:space:]]' "$root/reply" && grep -q '^0 packets captured$' "$root/status" &&
         grep -q '^0 packets dropped by kernel$' "$root/status"; then
        # BusyBox timeout preserves tcpdump's successful SIGTERM exit. A
        # completed, loss-free capture window with no reply is the failure
        # witness; an early process exit remains unavailable.
        printf '%s\n' unreachable
    else
        unavailable
    fi
    exit 0
fi
namespace=codex-sixbh-client
identity=02:00:00:00:00:0c
join_file=/tmp/codex-mesh-join/private/join-ip
expected=$(cat "$join_file" 2>/dev/null) || unavailable
printf '%s\n' "$expected" | awk -F . '
    NF==4 && $1=="192" && $2=="168" && $3 ~ /^(68|69|70|71)$/ &&
    $4 ~ /^(0|[1-9][0-9]?[0-9]?)$/ && $4<=255 &&
    $0!="198.18.68.0" && $0!="198.18.68.1" && $0!="198.18.71.255" {ok=1}
    END {exit !ok}' || unavailable
namespace_inode() {
    # BusyBox ls is present in the RAM image; coreutils stat is not.
    ls -Lid "/var/run/netns/$namespace" 2>/dev/null |
        awk 'NF==2 && $1 ~ /^[0-9]+$/ {print $1; ok=1} END {exit !ok}'
}
inode=$(namespace_inode) || unavailable
ready() {
    [ "$(namespace_inode)" = "$inode" ] || return 1
    [ "$(cat "$join_file" 2>/dev/null)" = "$expected" ] || return 1
    link=$(ip -n "$namespace" -o link show dev br-lan 2>/dev/null) || return 1
    printf '%s\n' "$link" | awk -v mac="$identity" '
        {flags=$3; gsub(/[<>]/,"",flags); if(flags !~ /(^|,)UP(,|$)/) exit 1}
        {for(i=1;i<NF;i++) if($i=="link/ether" && $(i+1)==mac) ok=1}
        END {exit !ok}' || return 1
    address=$(ip -n "$namespace" -4 -o address show dev br-lan 2>/dev/null) || return 1
    printf '%s\n' "$address" | awk -v wanted="$expected/22" '
        {for(i=1;i<NF;i++) if($i=="inet" && $(i+1)==wanted) ok=1}
        END {exit !ok}' || return 1
    for target in 198.18.68.1 198.18.68.101; do
        route=$(ip -n "$namespace" -4 route get "$target" 2>/dev/null) || return 1
        printf '%s\n' "$route" | awk -v source="$expected" '
            {for(i=1;i<NF;i++) {
                if($i=="dev" && $(i+1)=="br-lan") device=1
                if($i=="src" && $(i+1)==source) address=1
            }} END {exit !(device && address)}' || return 1
    done
}
ready || unavailable
state=unreachable
# Both targets are on the existing mesh LAN. Bind the source interface and
# execute inside the namespace; the host's independent uplink cannot satisfy
# this check. The wired peer also tolerates controller-only ICMP loss/restart.
for target in 198.18.68.1 198.18.68.101; do
    if ip netns exec "$namespace" ping -I br-lan -q -c 1 -W 1 "$target" >/dev/null 2>&1; then
        state=reachable
        break
    fi
done
ready || unavailable
printf '%s\n' "$state"
