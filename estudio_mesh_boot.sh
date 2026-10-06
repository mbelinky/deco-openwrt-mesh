#!/bin/sh
# SPDX-License-Identifier: MIT
# Restore immutable, privately packaged startup inputs. Leave recovery armed
# until this boot has established genuine mesh, configuration and traffic.
set -eu
umask 077
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
test "$(cat /sys/class/net/eth0/address)" = 02:00:00:00:00:19
ucode -e 'import { storage_ok } from "/etc/estudio-boot/storage.uc"; if (!storage_ok()) exit(9);'
test "$(uname -r)" = 6.18.52
test ! -e /tmp/estudio-mesh-resident
test ! -e /tmp/oem-mesh-peer
test -z "$(iw dev | sed -n 's/.*Interface //p')"
test "$(sha256sum /usr/sbin/wpad | cut -d ' ' -f 1)" = 52c1a96b24dbfe17c8ebc1f4f4ad3d33f69a510cd9402de622e99641b54053fb
sha256sum -c /etc/estudio-boot/archive-checks >/dev/null
tar -xzf /etc/estudio-boot/payload.tar.gz -C /
sha256sum -c /etc/estudio-boot/file-checks >/dev/null
rm /etc/estudio-boot/payload.tar.gz
assets=/tmp/estudio-boot-assets
mkdir -p /tmp/oem-mesh-peer
tar -xf "$assets/oem-userspace.tar" -C /tmp/oem-mesh-peer
rm "$assets/oem-userspace.tar"
mkdir -p /tmp/oem-mesh-peer/private/device-root/config /tmp/oem-mesh-peer/tmp/.uci
mkdir -p /tmp/oem-mesh-peer/dev /tmp/oem-mesh-peer/var
touch /tmp/oem-mesh-peer/codex-isolated-peer
cp "$assets/group-info" /tmp/oem-mesh-peer/private/group-info
cp "$assets/group.openssh" /tmp/oem-mesh-peer/private/group.openssh
cp "$assets/private-wireless" /tmp/oem-mesh-peer/private/device-root/config/wireless
set --
apk info > "$assets/installed-packages"
test -s "$assets/installed-packages"
while read -r name package; do
    test -n "$name" && test -n "$package"
    if ! grep -Fxq "$name" "$assets/installed-packages"; then
        set -- "$@" "$assets/packages/$package"
    fi
done < "$assets/packages.list"
if test "$#" -gt 0; then
    apk --repositories-file /dev/null --no-network --allow-untrusted --force-non-repository --simulate add "$@" > "$assets/apk-preview"
    if grep -Eq 'Upgrading|Downgrading|Removing|Replacing' "$assets/apk-preview"; then exit 1; fi
    apk --repositories-file /dev/null --no-network --allow-untrusted --force-non-repository add "$@" > "$assets/apk-install"
fi
rm -rf "$assets/packages"
touch /tmp/oem-mesh-peer/dev/console
export ADAPTER_CONFINED=1
timeout 55 unshare --mount --net --pid --fork --kill-child -- \
    /sbin/ujail -E -i -c -p -C /tmp/oem-mesh-peer/adapter-caps.json \
    -e ADAPTER_CONFINED -R /tmp/oem-mesh-peer -w /dev/null -r /dev/urandom \
    -V /tmp/oem-mesh-peer/dev/console:/dev/console -V /tmp/oem-mesh-peer/tmp:/var \
    -n estudio-factory-prepare -- /bin/sh /private/factory-setup.sh > "$assets/factory-prepare.log" 2>&1
grep -q '^OEM_FACTORY_PROFILE_AND_DEFAULTS_READY$' "$assets/factory-prepare.log"
test -d /tmp/oem-mesh-peer/etc/profile.d
test -s /tmp/oem-mesh-peer/etc/config/sync
mkdir -p /tmp/codex-wps-pinned/runtime
apk --repositories-file /dev/null --no-network --allow-untrusted --force-non-repository extract --destination /tmp/codex-wps-pinned/runtime /tmp/codex-wps-pinned/wpad-mbedtls.apk >/dev/null
sha256sum -c "$assets/wpad-checks" >/dev/null
test ! -d /sys/module/br_netfilter
modprobe veth
modprobe nft_meta_bridge
modprobe nft_reject_bridge
modprobe nf_conntrack_bridge
test ! -d /sys/module/br_netfilter
for radio in 0 1 2; do
    test "$(uci get wireless.default_radio$radio.disabled)" = 1
    uci set wireless.radio$radio.country=ES
    uci set wireless.radio$radio.txpower=10
done
uci commit wireless
iw reg set ES
for phy in 0 1 2; do iw phy phy$phy set txpower limit 1000; done
mkdir /tmp/estudio-mesh-resident/control
ucode /etc/estudio-boot/fresh-state.uc
sh /etc/rc.common /tmp/estudio_mesh_resident start
last_success=0
healthy=0
for attempt in $(seq 1 115); do
    ucode /etc/estudio-boot/status.uc > "$assets/status.json"
    phase=$(jsonfilter -i "$assets/status.json" -e '@.phase')
    # The resident starts asynchronously; no announcement timestamp exists yet.
    success=$(jsonfilter -i "$assets/status.json" -e '@.announcement_encryption.last_success_at') || success=0
    if test "$phase" = online && test -n "$success" && test "$success" -gt "$last_success"; then
        last_success=$success
        healthy=$((healthy + 1))
        if test "$healthy" -ge 2; then break; fi
    fi
    test "$phase" != failed
    sleep 2
done
test "$healthy" -ge 2
for address in 198.18.68.1 1.1.1.1; do
    ip netns exec codex-sixbh-client ping -c 3 -W 2 "$address" > "$assets/traffic-$address"
    grep -q '3 packets transmitted, 3 packets received, 0% packet loss' "$assets/traffic-$address"
    if grep -q DUP "$assets/traffic-$address"; then exit 1; fi
done
# U-Boot has already removed this command from flash before entering Linux.
# Re-arm only a healthy boot loaded by the permanent, inactive-slot path.
if grep -qE '(^| )estudio.persistent=1( |$)' /proc/cmdline; then
    test "$(wc -l </proc/mtd)" -eq 2
    test "$(cat /sys/class/mtd/mtd0/flags)" = 0x400
    chmod 700 "$assets/fw_printenv"
    ln -s fw_printenv "$assets/fw_setenv"
    printf '%s\n' '/dev/mtd0 0x0000 0x40000 0x20000 2' > "$assets/fw_env.config"
    "$assets/fw_printenv" -c "$assets/fw_env.config" > "$assets/environment-before" 2> "$assets/environment-warning"
    test ! -s "$assets/environment-warning"
    grep -qx 'tp_boot_idx=1' "$assets/environment-before"
    if grep -q '^bootcmd=' "$assets/environment-before"; then exit 1; fi
    command=$(cat "$assets/permanent-bootcmd")
    timeout 30 "$assets/fw_setenv" -c "$assets/fw_env.config" bootcmd "$command"
    "$assets/fw_printenv" -c "$assets/fw_env.config" bootcmd > "$assets/bootcmd-after" 2> "$assets/environment-warning"
    test ! -s "$assets/environment-warning"
    test "$(cat "$assets/bootcmd-after")" = "bootcmd=$command"
    "$assets/fw_printenv" -c "$assets/fw_env.config" > "$assets/environment-after" 2> "$assets/environment-warning"
    test ! -s "$assets/environment-warning"
    grep -v '^bootcmd=' "$assets/environment-after" > "$assets/environment-after-other"
    cmp "$assets/environment-before" "$assets/environment-after-other"
    printf '%s\n' verified > "$assets/permanent-rearmed"
fi
guard=$(cat /etc/codex-ram-guard.pid)
test "$(tr '\000' ' ' < /proc/$guard/cmdline)" = "/bin/sh -c sleep 300; /sbin/reboot -f "
kill -STOP "$guard"
for child in $(pidof sleep || true); do
    if test "$(awk '{print $4}' /proc/$child/stat)" = "$guard"; then
        test "$(tr '\000' ' ' < /proc/$child/cmdline)" = "sleep 300 "
        kill "$child"
    fi
done
kill -KILL "$guard"
printf '%s\n' verified > "$assets/healthy"
