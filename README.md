# OpenWrt integration with TP-Link Deco

Experimental MIT-licensed adapter sources for native transport, configuration,
client/app reporting, backhaul recovery, guest filtering and startup components.
It is not a portable installation or a replacement firmware download.

The private MVP passed on one XE75 EU v3 spare: app-managed membership and
configuration, native controller responses, bounded stability/recovery,
simulated guest isolation, automatic startup and a physical power cycle.
Physical guest Wi-Fi, roaming, OTA, arbitrary assignment changes, other units
and indefinite unattended reliability were not established.

This copy replaces device MACs, node IDs, local addresses and location labels
with consistent synthetic values. The synthetic values do not admit a real
unit. Do not install the source or change its identity guards to bypass that
restriction. Public provisioning requires a separate design and validation.

The deployment controller, host access and credential integration, private
acceptance probes, immutable bundle assembler and installers are excluded.
Thus the included startup fragments and runtime generator are review material,
not a complete runnable deployment. Original OEM modules/binaries are absent.

## Components

- `estudio_mesh_tipc.c`: native TIPC management transport and bounded observers.
- `estudio_mesh_runtime.py`, Lua adapters: confinement and OEM protocol boundary.
- `estudio_mesh_wifi_apply.uc`, client/policy modules: native configuration,
  client reporting and guest/isolation rules.
- Backhaul, link, relay and lifecycle sources: recovery and startup behavior.
- `patches/hostapd-rx-disconnect-reasons.patch`: isolated diagnostic patch;
  retains its upstream hostapd license boundary.

The source filenames preserve their internal references; they are not unit
names. Read [DEPENDENCIES.md](DEPENDENCIES.md), [NOTICE.md](NOTICE.md) and
[LICENSE-STATUS.md](LICENSE-STATUS.md). `source-manifest.json` records this copy's
bytes. This repository publishes a sanitized experimental source snapshot, not a
deployable release or a complete implementation independent of OEM software.

Hardware support is a separate [OpenWrt draft PR](https://github.com/openwrt/openwrt/pull/25666)
in the [XE75 OpenWrt fork](https://github.com/mbelinky/openwrt-deco-xe75).
Those draft hardware sources have not been boot-tested and do not produce the
private prototype image. Mesh integration is not part of that hardware PR.
