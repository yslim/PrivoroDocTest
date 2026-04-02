# PR Title
EPL updates: U-Boot env fix, firewall rule management, SKB drop counter, VPN identity

# PR Body

## Summary
- Fix boot hang from stale U-Boot env on eMMC and suppress FWU metadata warning
- Add numbered display, move command, and v4/v6 split for firewall rules
- Add skb-drop-counter kernel module for per-reason packet drop diagnostics
- Add pubkey local-id/remote-id for NIAP FCS_IPSEC_EXT.1.14 compliance

## 1. U-Boot Environment Fix

| Commit | Description |
|--------|-------------|
| Fix boot hang caused by stale u-boot env on eMMC | Configure ENV_IS_NOWHERE to prevent boot hang from stale environment variables |
| Fix "no /fwu-mdata node ?" warning at boot | Suppress spurious FWU metadata warning during normal boot |

## 2. Firewall Rule Management

| Commit | Description |
|--------|-------------|
| Add numbered show output and move command | Display rules with sequential numbering, add `move` command |
| Show rules as v4/v6 split with separate numbering | Split IPv4/IPv6 rules into separate numbered lists, move per stack |
| Enforce cross-stack rule-name uniqueness | Prevent duplicate names across v4/v6, add #V4/#V6 headers |

**CLI changes:**
- `firewall filter show` / `firewall nat show` — numbered output per v4/v6 stack
- `firewall filter move <from> <to>` / `firewall nat move <from> <to>` — reorder rules

## 3. SKB Drop Counter Module

| Commit | Description |
|--------|-------------|
| Add skb-drop-counter kernel module | Hooks kfree_skb tracepoint, exposes per-reason drop counts via debugfs |
| Auto-load module at boot | Installs `/etc/modules-load.d/skb-drop-counter.conf` |

**Usage:** `cat /sys/kernel/debug/skb_drop_counter/*`

## 4. VPN Identity — NIAP FCS_IPSEC_EXT.1.14

| Commit | Description |
|--------|-------------|
| Add pubkey local-id/remote-id | Explicit identity configuration for StrongSwan and LibreSwan pubkey auth |
| Support DN identity with spaces | Accept DN values like `C=US, O=MyOrg, CN=peer` in CLI commands |

**Supported identity types:**

| Type | StrongSwan | LibreSwan |
|------|------------|-----------|
| IP | `id = 192.168.1.100` | `leftid=192.168.1.100` |
| FQDN | `id = vpn.example.com` | `leftid=@vpn.example.com` |
| Email | `id = user@example.com` | `leftid=user@example.com` |
| DN | `id = "C=US, O=MyOrg, CN=peer"` | `leftid="C=US, O=MyOrg, CN=peer"` |

**CLI commands:**
- `security vpn set pubkey local-id <id>`
- `security vpn set pubkey remote-id <id>`
- `security vpn del pubkey local-id`
- `security vpn del pubkey remote-id`

## Test Plan
- [ ] Boot on eMMC with stale env — no hang
- [ ] Firewall: numbered show, move rules, v4/v6 split
- [ ] SKB drop counter: module auto-loads at boot, debugfs counters work
- [ ] VPN identity: set/del/show for IP, FQDN, Email, DN on both engines
- [ ] VPN identity: save + reload round-trip preserves values
- [ ] VPN identity: DN with spaces works without quotes in CLI input
