#!/bin/sh
# SPDX-License-Identifier: MIT
# Native entry points for the confined, RAM-only OEM pairing runtime.
set -eu
umask 077
test "$(cat /sys/class/net/eth0/address)" = 02:00:00:00:00:19
test "$(wc -l </proc/mtd)" -eq 1
root=/tmp/deco-runtime
control=/var/run/hostapd/deco-wps-control
case "${0##*/}" in
    deco-wps-service) role=service ;;
    wpsd) role=pairing ;;
    deco-oem-exec) role=${1:-}; shift ;;
    *) exit 1 ;;
esac
if [ "$role" = clean-control ]; then
    test "$#" -eq 0
    test -z "$(pidof wpsd-oem)"
    test ! -L "$control"
    if [ -d "$control" ]; then
        for socket in "$control"/wpa_ctrl_*; do
            [ -e "$socket" ] || continue
            test -S "$socket" && test ! -L "$socket"
            rm "$socket"
        done
        rmdir "$control"
    fi
    exit 0
fi
if [ "$role" = prepare ]; then
    test "$#" -eq 0
    if [ ! -d "$root" ]; then
        mkdir "$root"
        tar -xf /usr/share/deco/oem-userspace.tar -C "$root"
        mkdir -p "$root/tmp/run" "$root/tmp/wps" "$root/tmp/deco-native" "$root/dev" "$root/var"
        touch "$root/codex-isolated-peer" "$root/dev/console"
        printf '%s' 520C7831F7302242F81407BC050E7E7C4B5C697F > "$root/tmp/sync-cached-DEV_ID"
        # The original firmware invokes its own compiled applets by name.
        # -R selects a root but does not itself request a mount namespace.
        # -p does, so this must run the OEM utilities inside that root.
        applets=$(/sbin/ujail -E -i -N -c -p -C "$root/adapter-caps.json" -R "$root" \
            -n deco-prepare -- /bin/busybox --list </dev/null)
        test -n "$applets"
        for applet in $applets; do
            test -e "$root/bin/$applet" || ln -s busybox "$root/bin/$applet"
        done
        ln -s /tmp/deco-native/legacy-ubus.sock "$root/tmp/run/ubus.sock"
        # The unmodified C daemon queries board identity through getfirm,
        # while OEM Lua reads the cached value. Both use this guarded spare's
        # recovered identity; no factory partitions are exposed to the jail.
        cat > "$root/usr/bin/getfirm" <<'IDENTITY'
#!/bin/sh
test "$#" -eq 1 && test "$1" = DEV_ID || exit 1
cat /tmp/sync-cached-DEV_ID
printf '\n'
IDENTITY
        chmod 755 "$root/usr/bin/getfirm"
    fi
    test -f "$root/codex-isolated-peer"
    exit 0
fi
test -f "$root/codex-isolated-peer"
export ADAPTER_CONFINED=1 ADAPTER_SERVICE_ROOT="$root"
case "$role" in
    bus)
        test "$#" -eq 0
        exec 9>/tmp/deco-native-bus.lock
        flock -n 9
        rm -f "$root/tmp/deco-native/legacy-ubus.sock"
        set -- /usr/bin/lua /ubus-compat.lua /tmp/deco-native/legacy-ubus.sock /tmp/deco-native/upstream.sock
        ;;
    service)
        test "$#" -eq 1
        case "$1" in start|stop|reconcile|watch) ;; *) exit 1;; esac
        set -- /usr/sbin/deco-wps-service "$1"
        ;;
    pairing)
        export ADAPTER_HOSTAPD_GID="$(id -g network)"
        test ! -L "$control"
        mkdir -p "$control"
        chown root:network "$control"
        chmod 710 "$control"
        export ADAPTER_WPA_CTRL_DIR="$control"
        set -- /usr/sbin/wpsd "$@"
        ;;
    *) exit 1 ;;
esac
exec /sbin/ujail -E -i -N -c -p -C "$root/adapter-caps.json" \
    -e ADAPTER_CONFINED -e ADAPTER_SERVICE_ROOT -e ADAPTER_HOSTAPD_GID \
    -e ADAPTER_WPA_CTRL_DIR -R "$root" \
    -V "$root/dev/console:/dev/console" -w /dev/null -r /dev/urandom \
    -V "$root/tmp:/var" -V /var/run/hostapd:/var/run/hostapd \
    -V /var/run/ubus/ubus.sock:/tmp/deco-native/upstream.sock \
    -n "deco-wps-$role" -- "$@"
