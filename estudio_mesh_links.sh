#!/bin/sh
# SPDX-License-Identifier: MIT
# Sourced by the native backhaul owner. Netifd owns both VLANs; this owner
# atomically selects forwarding classes and prevents uplink relay/duplicates.
link_data=
link_broadcast=
link_primary_index=0
link_secondary_index=0
link_observed_at=0
link_key=
link_secondary_path_state=unavailable
link_secondary_path_checked_at=0
link_secondary_path_identity=
link_secondary_path_next_check=0
link_relay_disabled=0
link_relay_resume_state=inactive
mesh_links_close_relay() {
    # Serialize watchdog, operator cleanup and the backhaul owner's resume.
    if (umask 077; exec 8>/tmp/estudio-mesh-relay-lifecycle.lock;
        flock -x 8; mesh_links_close_relay_locked); then
        if [ -e /tmp/estudio-mesh-relay/closing ]; then
            link_relay_disabled=1; link_key=
        fi
        return 0
    else
        ml_close_result=$?
        if [ -e /tmp/estudio-mesh-relay/closing ]; then
            link_relay_disabled=1; link_key=
        fi
        return "$ml_close_result"
    fi
}
mesh_links_retire_relay() {
    # Close and retire under the same lock, before upstream objects disappear.
    # A host fixture keeps its own files; the native retire action preserves it.
    (umask 077; exec 8>/tmp/estudio-mesh-relay-lifecycle.lock;
        flock -x 8;
        mesh_links_close_relay_locked &&
        ucode /tmp/estudio_mesh_relay_resume.uc retire >/dev/null)
}
mesh_links_resume_relay() {
    ml_resume_previous=$link_relay_resume_state
    [ -e /tmp/estudio-mesh-relay/owner.json ] || { link_relay_resume_state=inactive; return 0; }
    if [ -e /tmp/estudio-mesh-relay/closing ] && [ ! -e /tmp/estudio-mesh-relay/closed ]; then
        mesh_links_close_relay || { link_relay_resume_state=rejected; return 1; }
    fi
    if ml_resume_reply=$(umask 077; exec 8>/tmp/estudio-mesh-relay-lifecycle.lock;
        # A native Wi-Fi transaction can hold this lock while verifying a
        # recreated uplink. Keep reconciling that uplink instead of blocking
        # the helper and leaving its interface index/status stale.
        flock -n -x 8 || exit 75;
        ucode /tmp/estudio_mesh_relay_resume.uc resume 2>/dev/null); then
        case "$ml_resume_reply" in
            opened)
                link_relay_disabled=0; link_key=
                mesh_links_apply "${link_data:-}" "${link_broadcast:-}" || return 1
                link_relay_resume_state=active;;
            active)
                if [ "$link_relay_disabled" = 1 ]; then
                    link_relay_disabled=0; link_key=
                    mesh_links_apply "${link_data:-}" "${link_broadcast:-}" || return 1
                fi
                link_relay_resume_state=active;;
            expired)
                mesh_links_close_relay || return 1
                link_relay_resume_state=expired;;
            waiting|inactive|template_changed) link_relay_resume_state=$ml_resume_reply;;
            *) return 1;;
        esac
    else
        ml_resume_error=$?
        if [ "$ml_resume_error" = 75 ]; then
            link_relay_resume_state=waiting
        else
            link_relay_resume_state=rejected
        fi
    fi
    if [ "$ml_resume_previous" != "$link_relay_resume_state" ]; then
        logger -t estudio-deco-backhaul "relay resume=$link_relay_resume_state"
    fi
}
mesh_links_close_relay_locked() {
    # A registered RAM relay belongs to this owner. Unknown private radios
    # remain protected by the parent guard; never infer ownership from names.
    ml_close_root=/tmp/estudio-mesh-relay
    [ -e "$ml_close_root/owner.json" ] || return 0
    [ -d "$ml_close_root" ] && [ ! -L "$ml_close_root" ] || return 1
    for ml_close_file in owner owner.json; do
        [ -f "$ml_close_root/$ml_close_file" ] && [ ! -L "$ml_close_root/$ml_close_file" ] || return 1
    done
    [ "$(wc -c < "$ml_close_root/owner.json")" -le 4096 ] || return 1
    ml_close_json=$(cat "$ml_close_root/owner.json")
    ml_close_field() { jsonfilter -s "$ml_close_json" -e "@.$1" 2>/dev/null; }
    ml_close_version=$(ml_close_field version)
    case "$ml_close_version" in 1|2) ;; *) return 1;; esac
    [ "$(ml_close_field boot_id)" = "$(cat /proc/sys/kernel/random/boot_id)" ] || return 1
    ml_close_token=$(cat "$ml_close_root/owner")
    [ "${#ml_close_token}" = 32 ] || return 1
    case "$ml_close_token" in *[!0-9a-f]*) return 1;; esac
    [ "$(ml_close_field token)" = "$ml_close_token" ] || return 1
    # Withdraw this owner's controller request before fencing a closed relay.
    ml_retry=/tmp/estudio-mesh-resident/control/relay-retry.json
    if [ -e "$ml_retry" ]; then
        [ -f "$ml_retry" ] && [ ! -L "$ml_retry" ] || return 1
        [ "$(jsonfilter -i "$ml_retry" -e '@.token')" = "$ml_close_token" ] || return 1
        rm "$ml_retry" || return 1
    fi
    ml_close_ap_mac=$(ml_close_field ap_bssid)
    case "$ml_close_ap_mac" in
        02:00:00:00:00:04|02:00:00:00:00:21) ;;
        *) return 1;;
    esac
    ml_close_radios=deco-r5
    ml_close_items='ap:deco-r5 trunk:br-decorelay main:decorelay.1 guest:decorelay.2 upstream:br-sixbh'
    ml_close_ap2_mac=
    if [ "$ml_close_version" = 2 ]; then
        # The two-band stock experiment owns this unit's observed private
        # radios, not an arbitrary extra interface or a name-derived address.
        [ "$ml_close_ap_mac" = 02:00:00:00:00:21 ] || return 1
        ml_close_ap2_mac=$(ml_close_field ap2_bssid)
        [ "$ml_close_ap2_mac" = 02:00:00:00:00:20 ] || return 1
        ml_close_radios="$ml_close_radios deco-r2"
        ml_close_items="$ml_close_items ap2:deco-r2"
    fi
    case "$(ml_close_field parent_bssid)" in
        02:00:00:00:00:15|02:00:00:00:00:1f|02:00:00:00:00:11|02:00:00:00:00:14) ;;
        *) return 1;;
    esac
    ml_close_mask=$(ml_close_field original_main_mask)
    case "$ml_close_mask" in ''|*[!0-9]*) return 1;; esac
    [ "$ml_close_mask" -le 65535 ] || return 1
    if [ "$(ml_close_field provisioning)" = true ]; then
        # An unarmed service installation owns no downstream objects yet.
        [ "$ml_close_version" = 2 ] && [ "$(ml_close_field mode)" = service ] || return 1
        [ "$(ml_close_field generation)" = 0 ] || return 1
        [ "$(ml_close_field interfaces.upstream)" = "$(cat /sys/class/net/br-sixbh/ifindex)" ] || return 1
        [ -f "$ml_close_root/closed" ] && [ ! -L "$ml_close_root/closed" ] &&
            [ "$(cat "$ml_close_root/closed")" = 1 ] || return 1
        for ml_close_item in ap:deco-r5 ap2:deco-r2 trunk:br-decorelay main:decorelay.1 guest:decorelay.2; do
            [ "$(ml_close_field interfaces.${ml_close_item%%:*})" = 0 ] || return 1
            [ ! -e "/sys/class/net/${ml_close_item#*:}" ] || return 1
        done
        ml_close_current_mask=$(cat /sys/class/net/br-sixbh/bridge/group_fwd_mask)
        [ "$((ml_close_current_mask))" = "$ml_close_mask" ] || return 1
        link_relay_disabled=1; link_key=
        return 0
    fi
    ml_close_partial=0
    if [ -e "$ml_close_root/closing" ]; then
        [ ! -L "$ml_close_root/closing" ] && [ "$(cat "$ml_close_root/closing")" = "$ml_close_token" ] || return 1
        ml_close_partial=1
    fi
    for ml_close_item in $ml_close_items; do
        ml_close_key=${ml_close_item%%:*}; ml_close_name=${ml_close_item#*:}
        ml_close_index=$(ml_close_field interfaces.$ml_close_key)
        case "$ml_close_index" in ''|*[!0-9]*) return 1;; esac
        [ "$ml_close_index" -gt 0 ] || return 1
        if [ -e "/sys/class/net/$ml_close_name" ]; then
            [ "$(cat "/sys/class/net/$ml_close_name/ifindex")" = "$ml_close_index" ] || return 1
        else
            # Netifd can remove an out-of-band AP while reloading its PHY.
            # An absent radio needs no destructive action. Validate every
            # surviving owned object below before fencing/removing it.
            [ "$ml_close_key" != upstream ] && {
                [ "$ml_close_key" = ap ] || [ "$ml_close_key" = ap2 ] ||
                [ "$ml_close_partial" = 1 ] || [ -f "$ml_close_root/closed" ];
            } || return 1
        fi
    done
    if [ -e "$ml_close_root/closed" ]; then
        [ ! -L "$ml_close_root/closed" ] && [ "$(cat "$ml_close_root/closed")" = 1 ] || return 1
        for ml_close_name in $ml_close_radios br-decorelay decorelay.1 decorelay.2; do
            [ ! -e "/sys/class/net/$ml_close_name" ] || return 1
        done
        return 0
    fi
    for ml_close_name in $ml_close_radios; do
        [ -e "/sys/class/net/$ml_close_name" ] || continue
        ml_close_expected_mac=$ml_close_ap_mac; ml_close_expected_phy=phy1
        if [ "$ml_close_name" = deco-r2 ]; then
            ml_close_expected_mac=$ml_close_ap2_mac; ml_close_expected_phy=phy0
        fi
        [ "$(cat "/sys/class/net/$ml_close_name/address")" = "$ml_close_expected_mac" ] || return 1
        [ "$(basename "$(readlink -f "/sys/class/net/$ml_close_name/phy80211")")" = "$ml_close_expected_phy" ] || return 1
        [ "$(basename "$(readlink -f "/sys/class/net/$ml_close_name/master")")" = br-decorelay ] || return 1
        ml_close_status=$(ubus call "hostapd.$ml_close_name" get_status 2>/dev/null) || return 1
        [ "$(printf '%s' "$ml_close_status" | jsonfilter -e '@.ssid')" = "$(uci -q get wireless.deco_backhaul.ssid)" ] || return 1
    done
    if [ -e /sys/class/net/br-decorelay ]; then
        [ -e /sys/class/net/br-decorelay/bridge ] && [ ! -e /sys/class/net/br-decorelay/master ] || return 1
        [ "$(cat /sys/class/net/br-decorelay/address)" = 02:00:00:00:00:03 ] || return 1
        for ml_close_port in $(ls /sys/class/net/br-decorelay/brif); do
            [ "$ml_close_port" != deco-r5 ] || continue
            if [ "$ml_close_port" = deco-r2 ]; then
                [ "$ml_close_version" = 2 ] || return 1
                continue
            fi
            # hostapd's four-address station ports share the owned AP MAC.
            ml_close_port_mac=$(cat "/sys/class/net/$ml_close_port/address")
            if [ "$ml_close_port_mac" = "$ml_close_ap_mac" ]; then
                ml_close_expected_phy=phy1
            elif [ "$ml_close_version" = 2 ] && [ "$ml_close_port_mac" = "$ml_close_ap2_mac" ]; then
                ml_close_expected_phy=phy0
            else
                return 1
            fi
            [ "$(basename "$(readlink -f "/sys/class/net/$ml_close_port/phy80211")")" = "$ml_close_expected_phy" ] || return 1
            [ "$(iw dev "$ml_close_port" info | awk '$1 == "type" {print $2}')" = AP/VLAN ] || return 1
        done
    fi
    for ml_close_vid in 1 2; do
        ml_close_name=decorelay.$ml_close_vid
        [ -e "/sys/class/net/$ml_close_name" ] || continue
        [ -e "/sys/class/net/$ml_close_name/lower_br-decorelay" ] || return 1
        [ "$(sed -n 's/.*VID: *\([0-9]*\).*/\1/p' "/proc/net/vlan/$ml_close_name")" = "$ml_close_vid" ] || return 1
        ml_close_master=br-sixbh
        [ "$ml_close_vid" = 1 ] || ml_close_master=br-sixguest
        [ "$(basename "$(readlink -f "/sys/class/net/$ml_close_name/master")")" = "$ml_close_master" ] || return 1
    done
    ml_close_current_mask=$(cat /sys/class/net/br-sixbh/bridge/group_fwd_mask)
    [ "$((ml_close_current_mask))" = "$((ml_close_mask | 8192))" ] ||
        { [ "$ml_close_partial" = 1 ] && [ "$((ml_close_current_mask))" = "$ml_close_mask" ]; } || return 1
    # Fence both traffic domains before removing the radio. Retain a token
    # checkpoint so an interrupted close can safely finish the same objects.
    printf '%s\n' "$ml_close_token" > "$ml_close_root/closing" || return 1
    link_relay_disabled=1
    mesh_links_apply "${link_data:-}" "${link_broadcast:-}" || return 1
    for ml_close_name in $ml_close_radios; do
        if [ -e "/sys/class/net/$ml_close_name" ]; then
            ubus call hostapd config_remove "$(printf '{"iface":"%s"}' "$ml_close_name")" >/dev/null || return 1
        fi
        [ ! -e "/sys/class/net/$ml_close_name" ] || return 1
    done
    for ml_close_vid in 1 2; do
        [ ! -e "/sys/class/net/decorelay.$ml_close_vid" ] || ip link del dev decorelay.$ml_close_vid || return 1
    done
    if [ -e /sys/class/net/br-decorelay ]; then
        [ -z "$(ls /sys/class/net/br-decorelay/brif)" ] || return 1
        ip link del dev br-decorelay || return 1
    fi
    ip link set dev br-sixbh type bridge group_fwd_mask "$ml_close_mask" || return 1
    printf '1\n' > "$ml_close_root/closed" || return 1
    link_key=
    logger -t estudio-deco-backhaul 'owned downstream relay closed'
    return 0
}
mesh_links_relay_ports() {
    # Recognize the downstream trunk from its actual two 802.1Q uppers.
    # An incomplete layout closes both domains rather than trusting names.
    ml_relay_valid=0; ml_relay_identity=none
    [ -e /sys/class/net/br-decorelay ] || return 0
    ml_relay_identity=closed
    [ "$link_relay_disabled" = 0 ] || return 0
    [ -e /sys/class/net/br-decorelay/bridge ] || return 0
    [ ! -e /sys/class/net/br-decorelay/master ] || return 0
    for ml_relay_vid in 1 2; do
        ml_relay_name=decorelay.$ml_relay_vid
        [ -e "/sys/class/net/$ml_relay_name/lower_br-decorelay" ] || return 0
        [ -f "/proc/net/vlan/$ml_relay_name" ] || return 0
        ml_relay_actual_vid=$(sed -n 's/.*VID: *\([0-9]*\).*/\1/p' "/proc/net/vlan/$ml_relay_name")
        [ "$ml_relay_actual_vid" = "$ml_relay_vid" ] || return 0
        ml_relay_bridge=br-sixbh
        [ "$ml_relay_vid" = 1 ] || ml_relay_bridge=br-sixguest
        [ "$(basename "$(readlink -f "/sys/class/net/$ml_relay_name/master" 2>/dev/null)")" = "$ml_relay_bridge" ] || return 0
    done
    for ml_relay_bridge in br-sixbh br-decorelay; do
        ml_relay_mask=$(cat "/sys/class/net/$ml_relay_bridge/bridge/group_fwd_mask")
        [ "$((ml_relay_mask & 8192))" = 8192 ] || return 0
    done
    ml_relay_valid=1
    ml_relay_identity=$(cat /sys/class/net/decorelay.1/ifindex):$(cat /sys/class/net/decorelay.2/ifindex):$(cat /sys/class/net/br-decorelay/ifindex)
}
mesh_links_apply() {
    ml_data=$1; ml_broadcast=$2
    case "$ml_data:$ml_broadcast" in
        sixbh.1:sixbh.1|standby.1:standby.1|standby.1:sixbh.1|:) ;; *) return 1;; esac
    mesh_links_relay_ports
    ml_rules=/tmp/estudio-mesh-links.nft
    {
        if nft list table bridge estudio_mesh_links >/dev/null 2>&1; then
            echo 'delete table bridge estudio_mesh_links'
        fi
        echo 'add table bridge estudio_mesh_links'
        echo 'add chain bridge estudio_mesh_links ingress { type filter hook prerouting priority -300; policy accept; }'
        echo 'add chain bridge estudio_mesh_links forward { type filter hook forward priority -210; policy accept; }'
        echo 'add rule bridge estudio_mesh_links forward iifname { "sixbh.1", "standby.1", "sixbh.2", "standby.2" } oifname { "sixbh.1", "standby.1", "sixbh.2", "standby.2" } counter drop'
        # The owned relay is a tagged trunk for the same stock child. Its
        # VLAN uppers carry upstream traffic; forwarding directly between
        # radio ports would reflect a copy back into that child.
        echo 'add rule bridge estudio_mesh_links forward meta ibrname "br-decorelay" meta obrname "br-decorelay" counter drop'
        if [ "$ml_relay_valid" = 1 ]; then
            # Group traffic heard behind the relay may be echoed through Main.
            # Reject those copies before learning, but permit unicast replies
            # through another active path. A source match is not packet identity.
            for ml_reflect_vid in 1 2; do
                printf 'add set bridge estudio_mesh_links relay_sources_%s { type ether_addr; flags dynamic,timeout; timeout 15s; size 512; }\n' "$ml_reflect_vid"
                printf 'add rule bridge estudio_mesh_links ingress iifname "decorelay.%s" ether saddr != { 02:00:00:00:00:13, 02:00:00:00:00:19 } update @relay_sources_%s { ether saddr timeout 15s }\n' "$ml_reflect_vid" "$ml_reflect_vid"
                printf 'add rule bridge estudio_mesh_links ingress iifname { "sixbh.%s", "standby.%s" } ether daddr & 02:00:00:00:00:01 != 00:00:00:00:00:00 ether saddr @relay_sources_%s counter drop comment "relay-reflection-vlan%s"\n' "$ml_reflect_vid" "$ml_reflect_vid" "$ml_reflect_vid" "$ml_reflect_vid"
            done
            # Discovery travels between mesh nodes on the main VLAN, never
            # to ordinary AP clients or through the guest VLAN.
            for ml_relay_control in 'ether type 0x893a ether daddr { ff:ff:ff:ff:ff:ff, 02:00:00:00:00:02 }' 'ether type 0x88b7 @ll,112,40 0x00037f0000'; do
                printf 'add rule bridge estudio_mesh_links ingress iifname "decorelay.2" %s counter drop\n' "$ml_relay_control"
                if [ -n "$ml_broadcast" ]; then
                    printf 'add rule bridge estudio_mesh_links forward iifname "decorelay.1" %s oifname != "%s" counter drop\n' "$ml_relay_control" "$ml_broadcast"
                else
                    printf 'add rule bridge estudio_mesh_links forward iifname "decorelay.1" %s counter drop\n' "$ml_relay_control"
                fi
            done
        else
            echo 'add rule bridge estudio_mesh_links ingress meta ibrname "br-decorelay" counter drop'
            echo 'add rule bridge estudio_mesh_links ingress iifname "decorelay.*" counter drop'
            echo 'add rule bridge estudio_mesh_links forward oifname "decorelay.*" counter drop'
        fi
        for ml_vid in 1 2; do
            ml_class_data=;ml_class_broadcast=
            [ -z "$ml_data" ] || ml_class_data=${ml_data%.*}.$ml_vid
            [ -z "$ml_broadcast" ] || ml_class_broadcast=${ml_broadcast%.*}.$ml_vid
        for ml_port in sixbh.$ml_vid standby.$ml_vid; do
            printf 'add rule bridge estudio_mesh_links ingress iifname "%s" ether type { 0x893a, 0x88cc } counter accept\n' "$ml_port"
            printf 'add rule bridge estudio_mesh_links ingress iifname "%s" ether type 0x88b7 @ll,112,40 0x00037f0000 counter accept\n' "$ml_port"
            for ml_relay_control in 'ether type 0x893a ether daddr { ff:ff:ff:ff:ff:ff, 02:00:00:00:00:02 }' 'ether type 0x88b7 @ll,112,40 0x00037f0000'; do
                if [ "$ml_relay_valid" = 1 ] && [ "$ml_vid" = 1 ] && [ "$ml_port" = "$ml_class_broadcast" ]; then
                    printf 'add rule bridge estudio_mesh_links forward iifname "%s" %s oifname != "decorelay.1" counter drop\n' "$ml_port" "$ml_relay_control"
                else
                    printf 'add rule bridge estudio_mesh_links forward iifname "%s" %s counter drop\n' "$ml_port" "$ml_relay_control"
                fi
            done
            if [ "$ml_port" != "$ml_class_data" ] && [ "$ml_port" != "$ml_class_broadcast" ]; then
                printf 'add rule bridge estudio_mesh_links ingress iifname "%s" counter drop\n' "$ml_port"
            elif [ "$ml_port" != "$ml_class_broadcast" ]; then
                printf 'add rule bridge estudio_mesh_links ingress iifname "%s" ether daddr & 02:00:00:00:00:01 != 00:00:00:00:00:00 counter drop\n' "$ml_port"
            fi
            if [ "$ml_port" != "$ml_class_broadcast" ]; then
                printf 'add rule bridge estudio_mesh_links forward oifname "%s" ether daddr & 02:00:00:00:00:01 != 00:00:00:00:00:00 counter drop\n' "$ml_port"
            fi
            # A learned destination may legitimately answer on the broadcast
            # uplink. Unknown unicast uses only the preferred data port via
            # its bridge flood flag, rather than dropping a learned route.
            if [ "$ml_port" != "$ml_class_data" ] && [ "$ml_port" != "$ml_class_broadcast" ]; then
                printf 'add rule bridge estudio_mesh_links forward oifname "%s" ether daddr & 02:00:00:00:00:01 == 00:00:00:00:00:00 counter drop\n' "$ml_port"
            fi
        done
        done
    } > "$ml_rules"
    nft --check -f "$ml_rules"
    nft -f "$ml_rules"
}
mesh_links_reconcile() {
    [ "${multilink_enabled:-0}" = 1 ] || return 0
    phase=multilink_vlan_type
    test "$(uci -q get network.sixdual_vlan.type)" = 8021q
    phase=multilink_vlan_name
    test "$(uci -q get network.sixdual_vlan.name)" = standby.1
    test "$(uci -q get network.sixdual_vlan.ifname)" = deco-standby
    test "$(uci -q get network.sixdual_vlan.vid)" = 1
    test "$(uci -q get network.sixdual.proto)" = none
    test "$(uci -q get network.sixdual.device)" = standby.1
    phase=multilink_guest_config
    test "$(uci -q get network.sixguest.proto)" = none
    test "$(uci -q get network.sixguest.device)" = br-sixguest
    test "$(uci -q get network.sixguest_bridge.type)" = bridge
    test "$(uci -q get network.sixguest_bridge.name)" = br-sixguest
    test "$(uci -q get network.sixguest_bridge.ipv6)" = 0
    test "$(uci -q get network.sixguest_bridge.ports)" = 'sixbh.2 standby.2'
    for ml_guest in sixguest_vlan:deco-sixsta:sixbh.2 sixguest_dual_vlan:deco-standby:standby.2; do
        ml_section=${ml_guest%%:*};ml_rest=${ml_guest#*:}
        test "$(uci -q get network.$ml_section.type)" = 8021q
        test "$(uci -q get network.$ml_section.ifname)" = "${ml_rest%%:*}"
        test "$(uci -q get network.$ml_section.name)" = "${ml_rest#*:}"
        test "$(uci -q get network.$ml_section.vid)" = 2
    done
    phase=multilink_associations
    ml_primary=$(wpa_cli -p /var/run/wpa_supplicant -i deco-sixsta status 2>/dev/null || true)
    ml_primary_valid=0
    if printf '%s\n' "$ml_primary" | grep -qx 'wpa_state=COMPLETED' &&
       printf '%s\n' "$ml_primary" | grep -qx 'freq=5240' &&
       printf '%s\n' "$ml_primary" | grep -qx 'key_mgmt=WPA2-PSK' &&
       printf '%s\n' "$ml_primary" | grep -Eq '^bssid=(02:00:00:00:00:15|02:00:00:00:00:1f|02:00:00:00:00:11|02:00:00:00:00:14)$'; then
        ml_primary_valid=1
    fi
    # Supplicant completion can precede netifd's four-address setup. Keep
    # secondary forwarding closed until its driver has accepted echo-protected
    # tagged multicast, exactly as the primary owner waits for initialization.
    ml_secondary_ready=0
    ml_mcast=/sys/kernel/debug/ieee80211/phy2/netdev:deco-standby/accept_3addr_vlan_mcast
    if [ "$standby_state" = connected ] && [ -e "$ml_mcast" ] &&
       [ -e /sys/kernel/debug/ieee80211/phy2/netdev:deco-standby/vlan_mcast_echo_drops ]; then
        if [ "$(cat "$ml_mcast")" = 1 ] || printf 1 > "$ml_mcast"; then
            ml_secondary_ready=1
        fi
    fi
    if [ "$ml_secondary_ready" = 1 ]; then
        # A completed association is not proof that this radio can carry
        # traffic. Probe with its own MAC and no IPv4 address, keeping ordinary
        # client forwarding untouched while an inactive link is checked.
        ml_path_identity=$standby_index:$standby_bssid:$(cat /sys/class/net/standby.1/ifindex 2>/dev/null || echo 0)
        if [ "$ml_path_identity" != "$link_secondary_path_identity" ]; then
            link_secondary_path_identity=$ml_path_identity
            link_secondary_path_next_check=0
            link_secondary_path_state=unavailable
        fi
        ml_path_now=$(cut -d . -f 1 /proc/uptime)
        if [ "$ml_path_now" -ge "$link_secondary_path_next_check" ]; then
            link_secondary_path_checked_at=$ml_path_now
            link_secondary_path_next_check=$((ml_path_now+5))
            link_secondary_path_state=$(sh /tmp/estudio_mesh_path_health.sh --radio 6g 2>/dev/null || true)
            case "$link_secondary_path_state" in
                reachable|unreachable|unavailable) ;;
                *) link_secondary_path_state=unavailable;;
            esac
        fi
        [ "$link_secondary_path_state" = reachable ] || ml_secondary_ready=0
    else
        link_secondary_path_state=unavailable
        link_secondary_path_identity=
        link_secondary_path_next_check=0
    fi
    ml_next_data=; ml_next_broadcast=
    if [ "$ml_primary_valid" = 1 ]; then
        ml_next_data=sixbh.1; ml_next_broadcast=sixbh.1
        # Both active paths must terminate at the same verified stock node.
        if [ "$ml_secondary_ready" = 1 ]; then
            case "$(printf '%s\n' "$ml_primary" | sed -n 's/^bssid=//p'):$standby_bssid" in
                02:00:00:00:00:15:02:00:00:00:00:16|02:00:00:00:00:1f:02:00:00:00:00:1a|02:00:00:00:00:14:02:00:00:00:00:17)
                    ml_next_data=standby.1;;
            esac
        fi
    elif [ "$ml_secondary_ready" = 1 ]; then
        ml_next_data=standby.1; ml_next_broadcast=standby.1
    fi
    ml_primary_index=$(cat /sys/class/net/sixbh.1/ifindex 2>/dev/null || echo 0)
    ml_secondary_index=$(cat /sys/class/net/standby.1/ifindex 2>/dev/null || echo 0)
    ml_guest_primary_index=$(cat /sys/class/net/sixbh.2/ifindex 2>/dev/null || echo 0)
    ml_guest_secondary_index=$(cat /sys/class/net/standby.2/ifindex 2>/dev/null || echo 0)
    if [ "$(basename "$(readlink -f /sys/class/net/standby.1/master 2>/dev/null)")" != br-sixbh ] ||
       [ "$(basename "$(readlink -f /sys/class/net/standby.2/master 2>/dev/null)")" != br-sixguest ]; then
        ml_next_data=sixbh.1; ml_next_broadcast=sixbh.1
        [ "$ml_primary_valid" = 1 ] || { ml_next_data=; ml_next_broadcast=; }
    fi
    mesh_links_relay_ports
    ml_key=$ml_next_data:$ml_next_broadcast:$ml_primary_index:$ml_secondary_index:$ml_guest_primary_index:$ml_guest_secondary_index:$ml_relay_identity
    if [ "$ml_key" != "$link_key" ]; then
        phase=multilink_port_flags
        for ml_port in sixbh.1 standby.1 sixbh.2 standby.2; do
            if [ -e "/sys/class/net/$ml_port/brport/learning" ]; then
                phase=multilink_port_$ml_port
                # Netlink waits for the network configuration lock and sets
                # both flags together. The legacy sysfs setter can reject a
                # write while netifd is still reconciling the bridge.
                ml_port_learning=off; ml_port_learning_value=0; ml_port_flood=off; ml_port_flood_value=0
                ml_port_main=${ml_port%.*}.1
                if [ "$ml_port_main" = "$ml_next_data" ] || [ "$ml_port_main" = "$ml_next_broadcast" ]; then
                    ml_port_learning=on; ml_port_learning_value=1
                fi
                if [ "$ml_port_main" = "$ml_next_data" ]; then
                    ml_port_flood=on; ml_port_flood_value=1
                fi
                if ! ip link set dev "$ml_port" type bridge_slave learning "$ml_port_learning" flood "$ml_port_flood" isolated on; then
                    link_data=; link_broadcast=; link_observed_at=0
                    return 0
                fi
                test "$(cat "/sys/class/net/$ml_port/brport/learning")" = "$ml_port_learning_value"
                test "$(cat "/sys/class/net/$ml_port/brport/unicast_flood")" = "$ml_port_flood_value"
                test "$(cat "/sys/class/net/$ml_port/brport/isolated")" = 1
            fi
        done
        phase=multilink_rules
        mesh_links_apply "$ml_next_data" "$ml_next_broadcast"
        phase=multilink_fdb_flush
        if [ -e /sys/class/net/br-sixbh/bridge/flush ]; then
            if ! printf 1 > /sys/class/net/br-sixbh/bridge/flush; then
                link_data=; link_broadcast=; link_observed_at=0
                return 0
            fi
        fi
        if [ -e /sys/class/net/br-sixguest/bridge/flush ]; then
            if ! printf 1 > /sys/class/net/br-sixguest/bridge/flush; then
                link_data=; link_broadcast=; link_observed_at=0
                return 0
            fi
        fi
        link_key=$ml_key
    fi
    link_data=$ml_next_data; link_broadcast=$ml_next_broadcast
    link_primary_index=$ml_primary_index; link_secondary_index=$ml_secondary_index
    link_observed_at=$(date +%s)
}
mesh_links_stop() {
    [ "${multilink_enabled:-0}" = 1 ] || return 0
    # Keep the inactive-port gate until netifd removes its configured VLAN.
    link_relay_disabled=1
    mesh_links_apply sixbh.1 sixbh.1
    ip link set dev standby.1 nomaster 2>/dev/null || true
    ip link set dev standby.2 nomaster 2>/dev/null || true
}
