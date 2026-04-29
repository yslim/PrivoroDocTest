# Release Notes — epl-20260413

**Date:** April 13, 2026
**Base:** upstream/develop

---

## 1. New Features

### 1.1 Serial Console Management (serial-console-disable)

| Commit | Description |
|--------|-------------|
| Add serial console disable command with safety prompt | Add CLI commands to enable/disable the serial console service. Disable displays a warning and y/N confirmation prompt. Operations execute in disable → mask → stop order so that disable/mask complete before the service stops, even when run from a serial console session. |

**CLI Commands:**

| Command | Description |
|---------|-------------|
| `system serial-console show status` | Show serial console service status |
| `system serial-console set service enable` | Enable the service (unmask → enable → start) |
| `system serial-console set service disable` | Disable the service (with confirmation prompt) |

### 1.2 Firewall ICMPv4/ICMPv6 Split (firewall-icmp-split)

| Commit | Description |
|--------|-------------|
| Split firewall icmp into icmp4/icmp6 with expanded type lists, type-code, and logging | Split `firewall icmp` into `firewall icmp4` (IPv4) and `firewall icmp6` (IPv6). Expand ICMPv4 types from 9 to 20 and ICMPv6 types from 12 to 15. Add `type-code` subcommand for arbitrary ICMP type/code pairs and `--logging` flag for NIAP FAU_GEN.1 audit compliance. |

**CLI Commands:**

| Command | Description |
|---------|-------------|
| `firewall icmp4 add <direction> <action> <type> <zone> <source> <rule-name> [--logging]` | Add ICMPv4 rule by named type |
| `firewall icmp4 add <direction> <action> type-code <type\|type/code> <zone> <source> <rule-name> [--logging]` | Add ICMPv4 rule with numeric type/code (e.g. 3/4) |
| `firewall icmp4 del <direction> <rule-name>` | Delete ICMPv4 rule |
| `firewall icmp4 move <direction> <zone> <from> <to>` | Reorder ICMPv4 rule |
| `firewall icmp6 add/del/move ...` | ICMPv6 (same subcommand structure) |
| `firewall show icmp4` | Show ICMPv4 rules |
| `firewall show icmp6` | Show ICMPv6 rules |

---

## 2. Bug Fixes

### 2.1 Firewall Save/Reset (fix-firewall)

| Commit | Description |
|--------|-------------|
| Fix firewall save confirm default and reset permission denied | Change `firewall save` confirmation default from `[Y/n]` to `[y/N]` so that empty input or EOF safely triggers rollback. Fix `firewall reset` failing to delete root-owned files created by XFRM scripts. |
| Fix watchdog timeout not rolling back XFRM bypass policies | Watchdog timeout only rolled back iptables v4/v6 rules but skipped XFRM bypass policy rollback, leaving stale xfrm policies in the kernel. |

**CLI Commands:**

| Command | Description |
|---------|-------------|
| `firewall save` | Save firewall rules (confirm default: N, watchdog now rolls back XFRM policies on timeout) |
| `firewall reset` | Reset firewall staging area |

### 2.2 Terminal Echo Broken After Exit (fix-readline-terminal-restore)

| Commit | Description |
|--------|-------------|
| Fix terminal echo broken after idle timeout or signal exit | `rl.Close()` was never called on idle timeout or signal exit because `os.Exit()` does not run deferred functions, leaving the terminal in raw mode (echo disabled). Explicitly close readline before `os.Exit()` to restore terminal state. |

---

## 3. Security Hardening

### 3.1 StrongSwan FIPS Mode Enforcement (strongswan-fips-mode)

| Commit | Description |
|--------|-------------|
| Enforce FIPS mode in strongSwan OpenSSL plugin | Install `fips_mode = 1` in charon's OpenSSL plugin configuration. Without this setting, the non-FIPS default provider loads alongside the FIPS provider, leaving non-approved algorithms (MD5, DES, RC4) reachable at runtime. With FIPS mode enabled, only NIAP-approved algorithms are available for IPsec. |

**NIAP Compliance:**
- FCS_COP.1: FIPS-approved cryptographic algorithms only
- FCS_IPSEC.1: IPsec restricted to approved cipher suites
