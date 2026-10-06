#!/bin/sh /etc/rc.common
# SPDX-License-Identifier: MIT
# Native procd owns the bus adapter and the confined pairing lifecycle.
START=95
STOP=10
USE_PROCD=1
start_service() {
    /usr/sbin/deco-oem-exec prepare || return 1
    procd_open_instance bus
    procd_set_param command /usr/sbin/deco-oem-exec bus
    procd_set_param respawn 3600 2 5
    procd_set_param term_timeout 3
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
service_started() {
    for attempt in $(seq 1 15); do
        if [ -S /tmp/deco-runtime/tmp/deco-native/legacy-ubus.sock ]; then
            /usr/sbin/deco-wps-service start
            return $?
        fi
        sleep 1
    done
    return 1
}
stop_service() {
    local stopped=0
    if [ -S /tmp/deco-runtime/tmp/deco-native/legacy-ubus.sock ]; then
        /usr/sbin/deco-wps-service stop && stopped=1
    fi
    # If the adapter is unavailable, use the same native owners to cancel
    # windows and remove instances before rc.common stops the bus adapter.
    if [ "$stopped" = 0 ]; then
        rm -f /tmp/deco-runtime/tmp/deco-wps.enabled
        for iface in phy0-ap0 phy1-ap0; do
            ubus call "hostapd.$iface" wps_cancel >/dev/null 2>&1 || true
        done
        ubus call service delete '{"name":"deco-wps"}' >/dev/null 2>&1 || true
    fi
    for attempt in $(seq 1 10); do
        if [ -z "$(pidof wpsd-oem)" ]; then
            /usr/sbin/deco-oem-exec clean-control
            return $?
        fi
        sleep 1
    done
    return 1
}
