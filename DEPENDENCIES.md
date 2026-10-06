# Runtime dependency boundary

The working prototype is not independent of OEM software. A recipient needs
lawfully obtained, compatible original inputs; none is shipped in this source
copy. No license for those inputs is inferred from a public GPL source archive.

| Dependency | Used for | Distribution in this copy |
| --- | --- | --- |
| OEM `tmpcli`, `tmpsvr`, original `tmp-luci` | Original TMP/TDP requests, discovery and dispatch | Excluded |
| OEM `sync-server` and original scripts/configuration | Original configuration transfer | Excluded |
| OEM `luci.model.sync`, `luci.model.crypto`, `luci.sys.config` and matching Lua dependencies | Group validation, encryption/decryption, XML/configuration conversion | Excluded |
| OEM `wpsd` and original control-library functions | Original pairing protocol | Excluded |
| Factory profiles/defaults, board identity, calibration, group credentials and private SSH keys | Per-device/group admission and original configuration | Excluded; private inputs must never be committed |
| OpenWrt ucode, UCI, ubus, nftables, hostapd, namespace/chroot/jail tools and matching modules | Native execution, filtering and radio control | Obtain upstream; no binaries included |
| Deco type-5 TIPC kernel adapter and optional mac80211 VLAN multicast patch | Native management transport and backhaul interoperability | Separate hardware source tree |

Guest filtering and native reporting are implemented in our source, while OEM
configuration cryptography/transport and pairing remain dependency boundaries.
Replacing those dependencies is later work, not a condition hidden in the MVP.

This review does not distribute OEM files or install them automatically. The
private bundle assembler, extraction recipes, credential lookup and device
installer are deliberately outside the allowlist. There is no public firmware
image or generic startup/provisioning command.
