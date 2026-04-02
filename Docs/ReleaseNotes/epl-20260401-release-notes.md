# Release Notes — epl-20260401

**Date:** April 1, 2026
**Base:** upstream/niap2

---

## 1. shiba-yocto-scripts

DDR memory configuration and OP-TEE secure region fixes for 1GB DRAM hardware.

| Commit | Description |
|--------|-------------|
| Fix DDR config for 1GB hardware and reserve OP-TEE secure region | Set DRAM size to match actual 1GB MT52L256M32D1PF hardware. Reserve OP-TEE secure DDR region in device trees to prevent TZC panic at boot. |

---

## 2. shiba-yocto-meta-shiba

Board-level DDR size configuration update.

| Commit | Description |
|--------|-------------|
| Set DDR size to 1024MB for 1GB DRAM support | Update machine configuration to reflect 1GB physical DRAM on target hardware. |

---

## 3. shiba-meta-secure-boot

### 3.1 U-Boot Environment Fix (uboot-env-nowhere)

| Commit | Description |
|--------|-------------|
| Fix boot hang caused by stale u-boot env on eMMC | Prevent boot hang when stale U-Boot environment variables exist on eMMC by configuring ENV_IS_NOWHERE. |
| Fix "no /fwu-mdata node ?" warning at boot | Suppress spurious FWU metadata warning during normal boot sequence. |

### 3.2 Firewall Rule Management (firewall-move)

| Commit | Description |
|--------|-------------|
| Add numbered show output and move command for firewall rules | Display firewall rules with sequential numbering. Add `move` command to reorder rules by number. |
| Show firewall rules as v4/v6 split with separate numbering, move by stack | Split IPv4 and IPv6 rules into separate numbered lists. Move command operates per IP stack. |
| Enforce cross-stack rule-name uniqueness, use #V4/#V6 headers | Prevent duplicate rule names across IPv4/IPv6 stacks. Add #V4/#V6 section headers in rule files. |

**Impact:**
- `firewall show` now displays numbered rules per stack (v4/v6)
- `firewall move <from> <to>` reorders rules within a stack
- Rule names must be unique across both IPv4 and IPv6 tables

### 3.3 SKB Drop Counter Module (ftrace-ratelimit)

| Commit | Description |
|--------|-------------|
| Add skb-drop-counter kernel module for per-reason drop statistics | Out-of-tree kernel module that hooks kfree_skb tracepoint and exposes per-reason packet drop counts via debugfs (`/sys/kernel/debug/skb_drop_counter/`). |
| Auto-load skb-drop-counter module at boot | Install `/etc/modules-load.d/skb-drop-counter.conf` for automatic module loading by systemd at boot. |

**Impact:**
- Per-reason SKB drop counters available via debugfs for network diagnostics
- Module loads automatically at boot without manual intervention

### 3.4 VPN Identity for NIAP FCS_IPSEC_EXT.1.14 (vpn-remote-id)

| Commit | Description |
|--------|-------------|
| Add pubkey local-id/remote-id for NIAP FCS_IPSEC_EXT.1.14 | Support explicit local-id and remote-id configuration for pubkey authentication in both StrongSwan (swanctl.conf) and LibreSwan (ipsec.conf). Required by NIAP for reference identifier matching during IPsec SA establishment. |
| Support DN identity with spaces in local-id/remote-id commands | Accept Distinguished Names with spaces (e.g. `C=US, O=MyOrg, CN=peer`) by joining multiple CLI arguments. StrongSwan and LibreSwan both quote DN values in config files. |

**NIAP Compliance:**
- FCS_IPSEC_EXT.1.14: Peer certificate presented identifier matched against configured reference identifier

**Supported Identity Types:**

| Type | Example | StrongSwan | LibreSwan |
|------|---------|------------|-----------|
| IP | `192.168.1.100` | `id = 192.168.1.100` | `leftid=192.168.1.100` |
| FQDN | `vpn.example.com` | `id = vpn.example.com` | `leftid=@vpn.example.com` |
| Email | `user@example.com` | `id = user@example.com` | `leftid=user@example.com` |
| DN | `C=US, O=MyOrg, CN=peer` | `id = "C=US, O=MyOrg, CN=peer"` | `leftid="C=US, O=MyOrg, CN=peer"` |

**CLI Commands:**
- `security vpn set pubkey local-id <id>`
- `security vpn set pubkey remote-id <id>`
- `security vpn del pubkey local-id`
- `security vpn del pubkey remote-id`
