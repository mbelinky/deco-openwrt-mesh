# Source provenance and license boundaries

The allowlist contains the project's adapter sources and one hostapd diagnostic
patch. OEM roots, firmware, decompiler output, GPL archives, packet captures,
private configuration and third-party tool checkouts are excluded.

The adapters call OEM interfaces; that does not make those original modules part
of this release. These source files are local adapter implementation candidates,
not a grant covering TP-Link binaries, SDKs or firmware. The original adapter
release license is MIT, as selected by the project owner. See
[LICENSE](LICENSE) and [LICENSE-STATUS.md](LICENSE-STATUS.md). This grant covers
our original adapter code only; it does not relicense the hostapd patch context,
kernel code or OEM dependencies.

`patches/hostapd-rx-disconnect-reasons.patch` changes the logging priority in
`src/ap/ieee802_11.c`. The pinned OpenWrt hostapd recipe identifies upstream
`https://w1.fi/hostap.git`, commit
`831364bf02710ad09c2f27d3efa92abeeb5634c0`, and `BSD-3-Clause`. Preserve hostapd's
Jouni Malinen/contributor notices and its per-file notices when distributing
modified hostapd. No hostapd binary or complete source tree is included here.

The kernel adapter and wireless modifications belong in the separate hardware
source tree. Their inherited Linux/OpenWrt/TP-Link licenses do not become the
mesh project's blanket license, and a mesh license does not relicense them.

The source review preserves protocol field names and compatibility behavior.
It does not establish a legal right to redistribute proprietary dependencies.
No third-party copyright notice is removed, replaced or attributed to us.

TP-Link and Deco names identify compatibility. This project is independent and
is not affiliated with or endorsed by TP-Link.
