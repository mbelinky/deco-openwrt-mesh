#!/bin/sh
# SPDX-License-Identifier: MIT
# Add the QCA four-address association element to the netifd-owned station.
# Netifd owns interfaces, VLANs and credentials. This service supplies the Deco
# association element, restores VLAN multicast compatibility and, in resident
# mode, recovers a lost association through verified stock parents.
set -eu
umask 077
test "$(cat /sys/class/net/eth0/address)" = 02:00:00:00:00:19
ucode -e 'import { storage_ok } from "/tmp/estudio_mesh_storage.uc"; if (!storage_ok()) exit(9);'
exec 9>/tmp/estudio-deco-backhaul.lock
flock -n 9 || exit 1
iface=deco-sixsta
radio=$(uci -q get wireless.deco_backhaul.device)
case "$radio" in
    radio2) phy=phy2; frequency=6135; channel=37; authentication=SAE
        main_bssid=02:00:00:00:00:16; alternate_bssid=02:00:00:00:00:1a
        alternate_parent_bssid=02:00:00:00:00:17; secondary_parent_bssid=;;
    radio1) phy=phy1; frequency=5240; channel=48; authentication=WPA2-PSK
        main_bssid=02:00:00:00:00:15; alternate_bssid=02:00:00:00:00:1f
        alternate_parent_bssid=02:00:00:00:00:14; secondary_parent_bssid=02:00:00:00:00:11;;
    *) exit 1;;
esac
status=/tmp/estudio-deco-backhaul-status.json
last_record=
phase=startup
parent_target=$main_bssid
parent_action=disabled
parent_attempts=0
parent_lost_at=0
parent_attempted_at=0
parent_mode=auto
parent_preferred=
parent_policy_revision=
parent_policy_apply_at=0
preferred_recheck_at=0
preferred_scan_at=0
parent_path_state=unavailable
parent_path_identity=
parent_path_checked_at=0
parent_path_next_check=0
parent_failed_bssids=
standby_state=disabled
standby_index=0
standby_bssid=
multilink_enabled=$(uci -q get wireless.deco_backhaul.deco_multilink || echo 0)
case "$multilink_enabled" in 0|1) ;; *) exit 1;; esac
if [ "$multilink_enabled" = 1 ]; then
    test "$radio" = radio1
    test -e /tmp/estudio-mesh-resident/run.sh
    . /tmp/estudio_mesh_links.sh
fi
trap 'code=$?; if [ "$code" != 0 ]; then logger -t estudio-deco-backhaul "exit=$code pid=$$ phase=$phase ifindex=${index:-0} last=$last_record"; fi' EXIT
record() {
    data=$(printf '{"state":"%s","ifindex":%s,"pid":%s,"action":"%s","parent_target":"%s","parent_action":"%s","parent_attempts":%s,"parent_control_version":%s,"parent_mode":"%s","parent_preferred":"%s","parent_policy_revision":"%s","parent_path_state":"%s","parent_path_checked_at":%s}' "$1" "$2" "$$" "$3" "$parent_target" "$parent_action" "$parent_attempts" "$auto_parent" "$parent_mode" "$parent_preferred" "$parent_policy_revision" "$parent_path_state" "$parent_path_checked_at")
    data="${data%\}},\"standby_state\":\"$standby_state\",\"standby_ifindex\":$standby_index,\"standby_bssid\":\"$standby_bssid\"}"
    if [ "$multilink_enabled" = 1 ]; then
        data="${data%\}},\"multilink_enabled\":true,\"link_data\":\"$link_data\",\"link_broadcast\":\"$link_broadcast\",\"link_primary_index\":$link_primary_index,\"link_secondary_index\":$link_secondary_index,\"link_observed_at\":$link_observed_at,\"secondary_path_state\":\"$link_secondary_path_state\",\"secondary_path_checked_at\":$link_secondary_path_checked_at,\"relay_resume_state\":\"$link_relay_resume_state\"}"
    fi
    if [ "$data" != "$last_record" ]; then
        printf '%s\n' "$data" > "$status.new"
        mv "$status.new" "$status"
        last_record=$data
    fi
}
stop() {
    result=0
    if [ "$multilink_enabled" = 1 ]; then
        mesh_links_retire_relay || { logger -t estudio-deco-backhaul 'relay shutdown rejected'; result=1; }
        mesh_links_stop
    fi
    rm -f "$status" "$status.new"
    exit "$result"
}
trap stop TERM INT HUP
check_config() {
    test "$(uci -q get wireless.deco_backhaul.device)" = "$radio"
    test "$(uci -q get wireless.deco_backhaul.mode)" = sta
    test "$(uci -q get wireless.deco_backhaul.ifname)" = "$iface"
    test "$(uci -q get wireless.deco_backhaul.macaddr)" = 02:00:00:00:00:06
    if [ "$radio" = radio2 ]; then
        test "$(uci -q get wireless.deco_backhaul.encryption)" = sae
        test "$(uci -q get wireless.deco_backhaul.ieee80211w)" = 2
        test "$(uci -q get wireless.deco_backhaul.sae_pwe)" = 1
    else
        test "$(uci -q get wireless.deco_backhaul.encryption)" = psk2+ccmp
        test "$(uci -q get wireless.deco_backhaul.ieee80211w)" = 0
    fi
    test "$(uci -q get wireless.deco_backhaul.wds)" = 1
    # Bound this RAM deployment to the verified main-Deco radio and ES channel.
    test "$(uci -q get wireless.deco_backhaul.bssid)" = "$main_bssid"
    test "$(uci -q get wireless.$radio.country)" = ES
    test "$(uci -q get wireless.$radio.channel)" = "$channel"
    test "$(uci -q get wireless.$radio.txpower)" = 10
    test "$(uci -q get wireless.radio2.country)" = ES
    test "$(uci -q get wireless.radio2.channel)" = 37
    test "$(uci -q get wireless.radio2.txpower)" = 10
    test "$(cat /sys/module/ath11k/parameters/frame_mode)" = 1
    mcast_requested=$(uci -q get wireless.deco_backhaul.deco_vlan_mcast || true)
    mcast_requested=${mcast_requested:-0}
    case "$mcast_requested" in 0|1) ;; *) return 1;; esac
    auto_parent=$(uci -q get wireless.deco_backhaul.deco_auto_parent || true)
    auto_parent=${auto_parent:-0}
    case "$auto_parent" in 0|1) ;; *) return 1;; esac
    if [ "$auto_parent" = 1 ]; then
        test -f /tmp/estudio-mesh-resident/run.sh
        test -f /tmp/estudio_mesh_path_health.sh
    fi
}
check_config
ctl() { wpa_cli -p /var/run/wpa_supplicant -i "$iface" "$@"; }
standby_association() {
    standby_state=disabled
    standby_index=0
    standby_bssid=
    [ "$(uci -q get wireless.deco_standby || true)" = wifi-iface ] || return 0
    standby_state=rejected
    [ "$radio" = radio1 ] || return 0
    for standby_field in device:radio2 mode:sta ifname:deco-standby macaddr:02:00:00:00:00:07 network:sixstandby_link wds:1 encryption:sae ieee80211w:2 sae_pwe:1 bssid:02:00:00:00:00:16; do
        standby_key=${standby_field%%:*}; standby_value=${standby_field#*:}
        [ "$(uci -q get "wireless.deco_standby.$standby_key" || true)" = "$standby_value" ] || return 0
    done
    [ "$(uci -q get network.sixstandby_link.proto || true)" = none ] || return 0
    [ "$(uci -q get network.sixstandby_link.device || true)" = deco-standby ] || return 0
    [ "$(uci -q get wireless.radio2.country || true)" = ES ] || return 0
    [ "$(uci -q get wireless.radio2.txpower || true)" = 10 ] || return 0
    [ "$(cat /sys/kernel/debug/ieee80211/phy2/user_power)" = 10 ] || return 0
    standby_state=waiting
    standby_index=$(cat /sys/class/net/deco-standby/ifindex 2>/dev/null || echo 0)
    [ "$standby_index" != 0 ] || return 0
    standby_state=rejected
    [ "$(cat /sys/class/net/deco-standby/address)" = 02:00:00:00:00:07 ] || return 0
    [ "$(basename "$(readlink -f /sys/class/net/deco-standby/phy80211)")" = phy2 ] || return 0
    [ ! -e /sys/class/net/deco-standby/master ] || return 0
    [ -z "$(ip -4 -o addr show dev deco-standby)" ] || return 0
    standby_state=waiting
    [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby ping 2>/dev/null || true)" = PONG ] || return 0
    standby_element=dd1f8cfdf000000101000100000200000000160000000000000000000000000000
    standby_current=$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby vendor_elem_get 13 2>/dev/null || true)
    if [ -z "$standby_current" ]; then
        [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby vendor_elem_add 13 "$standby_element" 2>/dev/null || true)" = OK ] || return 0
        [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby reassociate 2>/dev/null || true)" = OK ] || return 0
    elif [ "$standby_current" != "$standby_element" ]; then
        standby_state=rejected; return 0
    fi
    # Netifd keeps the saved bootstrap profile. Follow the actual primary
    # parent only through this interface's single native supplicant network.
    standby_networks=$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby list_networks 2>/dev/null || true)
    [ "$(printf '%s\n' "$standby_networks" | awk 'NR > 1 && $1 ~ /^[0-9]+$/ {n++} END {print n+0}')" = 1 ] || return 0
    standby_id=$(printf '%s\n' "$standby_networks" | awk 'NR > 1 && $1 ~ /^[0-9]+$/ {print $1}')
    standby_saved=$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby get_network "$standby_id" bssid 2>/dev/null || true)
    case "$standby_saved" in 02:00:00:00:00:16|02:00:00:00:00:1a|02:00:00:00:00:17) ;; *) return 0;; esac
    standby_target=$standby_saved
    standby_primary=$(ctl status 2>/dev/null || true)
    if [ "$(cat /sys/class/net/deco-sixsta/address 2>/dev/null || true)" = 02:00:00:00:00:06 ] &&
       [ "$(basename "$(readlink -f /sys/class/net/deco-sixsta/phy80211 2>/dev/null)")" = phy1 ] &&
       printf '%s\n' "$standby_primary" | grep -qx 'wpa_state=COMPLETED' &&
       printf '%s\n' "$standby_primary" | grep -qx 'freq=5240' &&
       printf '%s\n' "$standby_primary" | grep -qx 'key_mgmt=WPA2-PSK'; then
        case "$(printf '%s\n' "$standby_primary" | sed -n 's/^bssid=//p')" in
            02:00:00:00:00:15) standby_target=02:00:00:00:00:16;;
            02:00:00:00:00:1f) standby_target=02:00:00:00:00:1a;;
            02:00:00:00:00:14) standby_target=02:00:00:00:00:17;;
            02:00:00:00:00:11)
                # secondary_parent is a verified five-only parent. Do not keep a
                # secondary association to a different stock node alive.
                if ! printf '%s\n' "$standby_networks" | grep -q '\[DISABLED\]'; then
                    [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby disable_network "$standby_id" 2>/dev/null || true)" = OK ] || return 0
                fi
                standby_state=suspended
                return 0;;
        esac
    fi
    if printf '%s\n' "$standby_networks" | grep -q '\[DISABLED\]'; then
        standby_state=associating
        [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby set_network "$standby_id" bssid "$standby_target" 2>/dev/null || true)" = OK ] || return 0
        [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby enable_network "$standby_id" 2>/dev/null || true)" = OK ] || return 0
        return 0
    fi
    if [ "$standby_saved" != "$standby_target" ]; then
        standby_state=associating
        [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby set_network "$standby_id" bssid "$standby_target" 2>/dev/null || true)" = OK ] || return 0
        [ "$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby reassociate 2>/dev/null || true)" = OK ] || return 0
        return 0
    fi
    standby_state=associating
    standby_status=$(wpa_cli -p /var/run/wpa_supplicant -i deco-standby status 2>/dev/null || true)
    for standby_line in freq=6135 key_mgmt=SAE wpa_state=COMPLETED; do
        printf '%s\n' "$standby_status" | grep -qx "$standby_line" || return 0
    done
    standby_bssid=$(printf '%s\n' "$standby_status" | sed -n 's/^bssid=//p')
    case "$standby_bssid" in 02:00:00:00:00:16|02:00:00:00:00:1a|02:00:00:00:00:17) ;; *) standby_bssid=; return 0;; esac
    standby_state=connected
}
leaf_parent_allowed() {
    if [ "$multilink_enabled" = 1 ]; then
        mesh_links_close_relay || return 1
    fi
    private_ssid=$(uci -q get wireless.deco_backhaul.ssid)
    [ -n "$private_ssid" ] || return 1
    for section in $(uci show wireless | sed -n 's/^wireless\.\([^.=]*\)=wifi-iface$/\1/p'); do
        if [ "$(uci -q get "wireless.$section.mode" || true)" = ap ] &&
           [ "$(uci -q get "wireless.$section.ssid" || true)" = "$private_ssid" ]; then
            return 1
        fi
    done
    # A runtime hostapd BSS need not have a UCI section. Keep this leaf's
    # parent fixed while any private mesh AP exists, and defer changes if
    # the actual radio inventory cannot be read. Relay lifecycle ownership
    # must close the private AP before permitting a different upstream.
    private_objects=$(ubus list 'hostapd.*' 2>/dev/null) || return 1
    [ -n "$private_objects" ] || return 1
    for private_object in $private_objects; do
        private_state=$(ubus call "$private_object" get_status 2>/dev/null) || return 1
        private_running_ssid=$(printf '%s' "$private_state" | jsonfilter -e '@.ssid' 2>/dev/null) || return 1
        [ -n "$private_running_ssid" ] && [ "$private_running_ssid" != "$private_ssid" ] || return 1
    done
    return 0
}
station_network() {
    parent_networks=$(ctl list_networks 2>/dev/null || true)
    parent_count=$(printf '%s\n' "$parent_networks" | awk 'NR > 1 && $1 ~ /^[0-9]+$/ {n++} END {print n+0}')
    [ "$parent_count" = 1 ] || return 1
    parent_id=$(printf '%s\n' "$parent_networks" | awk 'NR > 1 && $1 ~ /^[0-9]+$/ {print $1}')
}
read_parent_policy() {
    [ "$auto_parent" = 1 ] || return 0
    policy=/tmp/codex-mesh-join/private/node-parent-policy.json
    [ -f "$policy" ] && [ ! -L "$policy" ] || return 0
    [ "$(wc -c < "$policy")" -le 2048 ] || return 0
    policy_data=$(cat "$policy")
    policy_field() { jsonfilter -s "$policy_data" -e "@.$1" 2>/dev/null || true; }
    revision=$(policy_field revision)
    [ "${#revision}" = 32 ] || return 0
    case "$revision" in *[!0-9a-f]*) return 0;; esac
    if [ "$revision" != "$parent_policy_revision" ]; then
        [ "$(policy_field version)" = 1 ] || return 0
        [ "$(policy_field device_id)" = 520C7831F7302242F81407BC050E7E7C4B5C697F ] || return 0
        [ "$(policy_field controller)" = 52AC6DE2B63BB051EB29D46337989727DC28F87A ] || return 0
        [ "$(policy_field boot_id)" = "$(cat /proc/sys/kernel/random/boot_id)" ] || return 0
        policy_auto=$(policy_field auto)
        preferred_device=$(policy_field preferred_device)
        case "$policy_auto:$preferred_device" in
            true:) preferred_bssid=; policy_mode=auto;;
            false:52AC6DE2B63BB051EB29D46337989727DC28F87A) preferred_bssid=$main_bssid; policy_mode=preferred;;
            false:5355353F82EA7AF944FFF5582BFE58BA00CA10BF) preferred_bssid=$alternate_bssid; policy_mode=preferred;;
            false:6D44C8260C8599BC54A3F345F4494FCF1516ECD4) preferred_bssid=$alternate_parent_bssid; policy_mode=preferred;;
            false:DDF89F67F85C238B2E57D57FF79A782C67EAED6A)
                [ "$radio" = radio1 ] || return 0
                preferred_bssid=$secondary_parent_bssid; policy_mode=preferred;;
            *) return 0;;
        esac
        check_config
        leaf_parent_allowed || { parent_action=private_ap_rejected; return 0; }
        if [ "$policy_mode" = auto ]; then
            # An unavailable preference can coexist with a healthy fallback
            # association. Release its saved supplicant pin as well as the
            # preference, preserving the actual working link without a roam.
            auto_state=$(ctl status 2>/dev/null || true)
            if printf '%s\n' "$auto_state" | grep -qx wpa_state=COMPLETED &&
               printf '%s\n' "$auto_state" | grep -qx "freq=$frequency" &&
               printf '%s\n' "$auto_state" | grep -qx "key_mgmt=$authentication"; then
                auto_bssid=$(printf '%s\n' "$auto_state" | sed -n 's/^bssid=//p')
                case "$auto_bssid" in
                    "$main_bssid"|"$alternate_bssid"|"$alternate_parent_bssid"|"$secondary_parent_bssid")
                        [ -n "$auto_bssid" ] || return 0
                        station_network || { parent_action=network_owner_rejected; return 0; }
                        auto_pin=$(ctl get_network "$parent_id" bssid 2>/dev/null || true)
                        if [ "$auto_pin" != "$auto_bssid" ]; then
                            [ "$(ctl set_network "$parent_id" bssid "$auto_bssid" 2>/dev/null || true)" = OK ] || return 0
                        fi;;
                    *) return 0;;
                esac
            fi
        fi
        parent_mode=$policy_mode
        parent_preferred=$preferred_bssid
        parent_policy_revision=$revision
        preferred_recheck_at=0
        preferred_scan_at=0
        # Allow the controller's command reply to leave before replacing its
        # transport link. Preference acceptance is separate from association.
        parent_policy_apply_at=$(($(cut -d . -f 1 /proc/uptime)+4))
        if [ "$parent_mode" = auto ]; then parent_policy_apply_at=0; fi
    fi
    [ "$parent_policy_apply_at" != 0 ] || return 0
    policy_now=$(cut -d . -f 1 /proc/uptime)
    [ "$policy_now" -ge "$parent_policy_apply_at" ] || return 0
    parent_state=$(ctl status 2>/dev/null || true)
    if [ "$(printf '%s\n' "$parent_state" | sed -n 's/^bssid=//p')" = "$parent_preferred" ] &&
       [ "$(printf '%s\n' "$parent_state" | sed -n 's/^wpa_state=//p')" = COMPLETED ]; then
        parent_policy_apply_at=0
        return 0
    fi
    leaf_parent_allowed || { parent_action=private_ap_rejected; return 0; }
    station_network || { parent_action=network_owner_rejected; return 0; }
    parent_policy_apply_at=$((policy_now+30))
    if [ "$(ctl set_network "$parent_id" bssid "$parent_preferred" 2>/dev/null || true)" = OK ] &&
       [ "$(ctl reassociate 2>/dev/null || true)" = OK ]; then
        parent_policy_apply_at=0
        parent_target=$parent_preferred
        parent_attempted_at=$policy_now
        parent_attempts=$((parent_attempts+1))
        logger -t estudio-deco-backhaul "app preferred parent=$parent_target"
    fi
}
return_to_preferred() {
    if [ "$parent_mode" != preferred ] || [ "$parent_bssid" = "$parent_preferred" ]; then
        preferred_recheck_at=0
        preferred_scan_at=0
        return 0
    fi
    # Preserve a working fallback for two minutes before trying the preferred
    # radio again. A failed return gets the same delay after fallback recovery.
    # This is our native retry policy, not a claim to reproduce awnd's timers.
    preferred_now=$(cut -d . -f 1 /proc/uptime)
    if [ "$preferred_recheck_at" = 0 ]; then
        preferred_recheck_at=$((preferred_now+120))
    fi
    [ "$preferred_now" -ge "$preferred_recheck_at" ] || return 0
    if [ "$preferred_scan_at" = 0 ]; then
        # Scan only the validated current channel; never switch channels or
        # drop the alternate connection merely to look for a preferred parent.
        if [ "$(ctl scan freq="$frequency" 2>/dev/null || true)" = OK ]; then
            preferred_scan_at=$preferred_now
            parent_action=preferred_scan
        else
            preferred_recheck_at=$((preferred_now+30))
        fi
        return 0
    fi
    preferred_elapsed=$((preferred_now-preferred_scan_at))
    [ "$preferred_elapsed" -ge 3 ] || return 0
    preferred_bss=$(ctl bss "$parent_preferred" 2>/dev/null || true)
    preferred_age=$(printf '%s\n' "$preferred_bss" | sed -n 's/^age=//p')
    case "$preferred_age" in ''|*[!0-9]*) preferred_age=999;; esac
    if [ "$(printf '%s\n' "$preferred_bss" | sed -n 's/^bssid=//p')" = "$parent_preferred" ] &&
       [ "$(printf '%s\n' "$preferred_bss" | sed -n 's/^freq=//p')" = "$frequency" ] &&
       [ "$preferred_age" -le 10 ] && [ "$preferred_age" -le "$((preferred_elapsed+1))" ]; then
        preferred_scan_at=0
        preferred_recheck_at=$((preferred_now+120))
        check_config
        leaf_parent_allowed || { parent_action=private_ap_rejected; return 0; }
        station_network || { parent_action=network_owner_rejected; return 0; }
        [ "$(cat /sys/class/net/deco-sixsta/ifindex 2>/dev/null || true)" = "$index" ] || return 0
        if [ "$(ctl set_network "$parent_id" bssid "$parent_preferred" 2>/dev/null || true)" = OK ] &&
           [ "$(ctl reassociate 2>/dev/null || true)" = OK ]; then
            parent_target=$parent_preferred
            parent_attempted_at=$preferred_now
            parent_attempts=$((parent_attempts+1))
            parent_action=preferred_retry
            logger -t estudio-deco-backhaul "retry visible preferred parent=$parent_target"
        else
            parent_action=control_failed
        fi
    elif [ "$preferred_elapsed" -gt 12 ]; then
        preferred_scan_at=0
        preferred_recheck_at=$((preferred_now+30))
    fi
}
check_parent_path() {
    path_now=$(cut -d . -f 1 /proc/uptime)
    if [ "$parent_path_identity" != "$index:$parent_bssid" ]; then
        parent_path_identity=$index:$parent_bssid
        parent_path_next_check=0
        parent_path_state=unavailable
        parent_lost_at=0
    fi
    if [ "$path_now" -ge "$parent_path_next_check" ]; then
        parent_path_checked_at=$path_now
        parent_path_next_check=$((path_now+5))
        parent_path_state=$(sh /tmp/estudio_mesh_path_health.sh 2>/dev/null || true)
        case "$parent_path_state" in
            reachable|unreachable|unavailable) ;;
            *) parent_path_state=unavailable;;
        esac
        if [ "$(cat /sys/class/net/deco-sixsta/ifindex 2>/dev/null || true)" != "$index" ]; then
            parent_path_state=unavailable
        fi
    fi
    # Missing local setup is not evidence against a parent. Only actual failed
    # probes enter the same bounded loss/retry policy as a lost association.
    [ "$parent_path_state" != unreachable ]
}
recover_parent() {
    [ "$auto_parent" = 1 ] || return 0
    # Close the admitted relay before selecting a different upstream.
    # Unknown private APs still reject any parent change. Recheck actual state.
    parent_state=$(ctl status 2>/dev/null || true)
    parent_bssid=$(printf '%s\n' "$parent_state" | sed -n 's/^bssid=//p')
    parent_ready=$(printf '%s\n' "$parent_state" | sed -n 's/^wpa_state=//p')
    parent_freq=$(printf '%s\n' "$parent_state" | sed -n 's/^freq=//p')
    parent_auth=$(printf '%s\n' "$parent_state" | sed -n 's/^key_mgmt=//p')
    if [ "$parent_ready" = COMPLETED ] && [ "$parent_freq" = "$frequency" ] && [ "$parent_auth" = "$authentication" ]; then
        case "$parent_bssid" in
            "$main_bssid"|"$alternate_bssid"|"$alternate_parent_bssid"|"$secondary_parent_bssid")
                parent_target=$parent_bssid
                if check_parent_path; then
                    [ "$parent_path_state" != reachable ] || parent_failed_bssids=
                    parent_lost_at=0
                    parent_action=connected
                    return_to_preferred
                    return 0
                fi
                ;;
        esac
    else
        parent_path_identity=
        parent_path_state=unavailable
        parent_path_checked_at=0
    fi
    if [ "$multilink_enabled" = 1 ]; then
        mesh_links_close_relay || { parent_action=relay_close_rejected; return 0; }
    fi
    # Use monotonic time: wall-clock correction must not cause rapid switching.
    parent_now=$(cut -d . -f 1 /proc/uptime)
    preferred_scan_at=0
    preferred_recheck_at=0
    if [ "$parent_lost_at" = 0 ]; then parent_lost_at=$parent_now; fi
    parent_action=waiting
    [ "$((parent_now-parent_lost_at))" -ge 20 ] || return 0
    [ "$((parent_now-parent_attempted_at))" -ge 30 ] || return 0
    check_config
    leaf_parent_allowed || { parent_action=private_ap_rejected; return 0; }
    # Only touch this interface's single native network, never another radio.
    station_network || { parent_action=network_owner_rejected; return 0; }
    case " $parent_failed_bssids " in
        *" $parent_target "*) ;;
        *) parent_failed_bssids="$parent_failed_bssids $parent_target";;
    esac
    # Prefer the direct controller path on each new failure. Try the wider
    # verified set only when earlier candidates failed in this same outage;
    # successful traffic ends that failure history.
    parent_next=
    for parent_candidate in "$main_bssid" "$alternate_bssid" "$secondary_parent_bssid" "$alternate_parent_bssid"; do
        [ -n "$parent_candidate" ] || continue
        case " $parent_failed_bssids " in *" $parent_candidate "*) continue;; esac
        parent_next=$parent_candidate
        break
    done
    if [ -z "$parent_next" ]; then
        parent_failed_bssids=$parent_target
        parent_next=$main_bssid
        [ "$parent_target" != "$main_bssid" ] || parent_next=$alternate_bssid
    fi
    parent_attempted_at=$parent_now
    parent_attempts=$((parent_attempts+1))
    if [ "$(ctl set_network "$parent_id" bssid "$parent_next" 2>/dev/null || true)" = OK ]; then
        parent_target=$parent_next
        if [ "$(ctl reassociate 2>/dev/null || true)" = OK ]; then
            parent_action=reassociate
            logger -t estudio-deco-backhaul "recover parent=$parent_target attempt=$parent_attempts"
            return 0
        fi
    fi
    parent_action=control_failed
}
element="dd1f8cfdf00000010100010000$(printf '%s' "$main_bssid" | tr -d ':')0000000000000000000000000000"
seen=
mcast_attempt_index=
mcast_attempts=0
while :; do
    phase=standby_association
    standby_association
    if [ "$multilink_enabled" = 1 ]; then mesh_links_reconcile; fi
    phase=interface_lookup
    index=$(cat "/sys/class/net/$iface/ifindex" 2>/dev/null || true)
    if [ -z "$index" ]; then
        if [ "$multilink_enabled" = 1 ]; then mesh_links_close_relay || logger -t estudio-deco-backhaul 'relay close rejected'; fi
        seen=
        record waiting 0 none
        sleep 1
        continue
    fi
    if [ "$index" != "$seen" ]; then
        preferred_scan_at=0
        preferred_recheck_at=0
        phase=configuration_validation
        check_config
        phase=interface_identity
        test "$(cat /sys/class/net/$iface/address)" = 02:00:00:00:00:06
        test "$(basename "$(readlink -f /sys/class/net/$iface/phy80211)")" = "$phy"
        phase=radio_power
        test "$(cat /sys/kernel/debug/ieee80211/phy2/user_power)" = 10
        # Netifd recreates the station with its bootstrap main BSSID. The
        # accepted app preference still applies to the new native interface.
        # Reconcile once after recreation, preserving ordinary fallback on an
        # unchanged interface when the preferred parent is unavailable.
        if [ "$parent_mode" = preferred ]; then
            parent_policy_apply_at=$(($(cut -d . -f 1 /proc/uptime)+4))
        fi
    fi
    phase=supplicant_readiness
    if [ "$(wpa_cli -p /var/run/wpa_supplicant -i "$iface" ping 2>/dev/null || true)" != PONG ]; then
        if [ "$multilink_enabled" = 1 ]; then mesh_links_close_relay || logger -t estudio-deco-backhaul 'relay close rejected'; fi
        record waiting "$index" none
        sleep 1
        continue
    fi
    # A recreated netifd interface starts with compatibility disabled. Only
    # enable it for the validated private WDS station, with echo protection.
    mcast_path="/sys/kernel/debug/ieee80211/$phy/netdev:$iface/accept_3addr_vlan_mcast"
    phase=multicast_restore
    echo_path="/sys/kernel/debug/ieee80211/$phy/netdev:$iface/vlan_mcast_echo_drops"
    if [ "$mcast_requested" = 1 ] && { [ ! -f "$mcast_path" ] || [ ! -f "$echo_path" ]; }; then
        if [ "$(cat "/sys/class/net/$iface/ifindex" 2>/dev/null || true)" != "$index" ]; then continue; fi
        record rejected "$index" multicast_driver_unavailable
        exit 1
    fi
    if [ -f "$mcast_path" ] && [ "$(cat "$mcast_path" 2>/dev/null || true)" != "$mcast_requested" ]; then
        if ! printf '%s\n' "$mcast_requested" > "$mcast_path"; then
            if [ "$(cat "/sys/class/net/$iface/ifindex" 2>/dev/null || true)" != "$index" ]; then continue; fi
            # Supplicant's socket can be ready before netifd finishes setting
            # four-address mode. The kernel must keep rejecting enablement
            # until then; wait on this interface without burning respawns.
            if [ "$mcast_attempt_index" != "$index" ]; then
                mcast_attempt_index=$index
                mcast_attempts=0
            fi
            mcast_attempts=$((mcast_attempts+1))
            if [ "$mcast_attempts" -lt 15 ]; then
                record waiting "$index" multicast_initializing
                sleep 1
                continue
            fi
            record rejected "$index" multicast_option_failed
            exit 1
        fi
    fi
    mcast_attempts=0
    if [ "$(cat "/sys/class/net/$iface/ifindex" 2>/dev/null || true)" != "$index" ]; then continue; fi
    phase=association_element
    current=$(wpa_cli -p /var/run/wpa_supplicant -i "$iface" vendor_elem_get 13 2>/dev/null || true)
    if [ "$current" = "$element" ]; then
        phase=parent_policy
        read_parent_policy
        phase=parent_recovery
        recover_parent
        record configured "$index" preserved
        if [ "$multilink_enabled" = 1 ]; then mesh_links_resume_relay; fi
    elif [ -z "$current" ]; then
        # A disappearing interface is an ordinary reload, not an instruction
        # to touch another interface or overwrite a different owner's element.
        if [ "$(wpa_cli -p /var/run/wpa_supplicant -i "$iface" vendor_elem_add 13 "$element" 2>/dev/null || true)" = OK ] &&
           [ "$(cat /sys/class/net/$iface/ifindex 2>/dev/null || true)" = "$index" ] &&
           [ "$(wpa_cli -p /var/run/wpa_supplicant -i "$iface" reassociate 2>/dev/null || true)" = OK ]; then
            record configured "$index" added
        fi
    else
        record rejected "$index" foreign_element
        exit 1
    fi
    seen=$index
    sleep 1
done
