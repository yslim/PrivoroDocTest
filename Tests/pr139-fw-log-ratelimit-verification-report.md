---
title: "PR #139 — Firewall Audit-LOG Rate-Limit Tuning — Verification Report"
subtitle: "privoro/shiba-meta-secure-boot#139 · Merge 98af47e2 · Base develop"
author: "Privoro / Akita firewall team"
date: "2026-07-28"
geometry: margin=2cm
fontsize: 10pt
---

**PR:** privoro/shiba-meta-secure-boot#139 — *"firewall: SCLI-tunable audit LOG rate limit (Supported IP Transport)"*
**Merge commit:** `98af47e2` (base `develop`)
**Verified:** 2026-07-28, statically (source at `develop`) and on-device (`shiba-wbu7dq`, grey, running an image built from `develop`)
**Verdict: PASS — behaves as described; no defect found. The one coverage gap in the PR's own report (the OTA migration path) was filled and also passes.**

---

## Scope

PR #139 does three things:
1. **Policy split** — moves the `AKITA_LOG_*` / `*_DROP` LOG rate-limit rules out of `00_filter_header.rules` into a new `10_fw_logging.rules` (IPv4 + IPv6).
2. **SCLI `firewall log`** — `show` / `rate` / `reset-default`, staged and applied via `firewall save`.
3. **Migration** — `iptables-rules-init.sh` brings an already-initialised (OTA-updated) device from the old inline-LOG layout to the split layout on the next boot.

---

## Static review

| Check | Result |
|-------|--------|
| Policy split is lossless — old header rules == new header + `10_fw_logging.rules` | PASS — compared rules-only (comments stripped), IPv4 + IPv6 byte-identical |
| All LOG chains actually moved into `10_fw_logging.rules` | PASS — 11 chains present; `--target all` covers them |
| SCLI edits only `10_fw_logging.rules` (single owner of LOG rules) | PASS |
| Migration premise — the live header is byte-identical to the template (SCLI never edits `00_filter_header.rules`) | PASS — no SCLI reference to `00_filter_header` anywhere |
| `SYN_FLOOD` rules at risk of loss during migration | N/A — already a separate file (`20_fw_syn_flood.rules`), untouched by this PR |
| Go `build` / `vet`, migration script `sh -n` | PASS |

No merge-blocking defect found statically.

---

## On-device

### Full SCLI cycle (reproduces the PR report)

| Step | Result |
|------|--------|
| `firewall log show` | All 11 live LOG chains listed, IPv4 + IPv6, correct defaults (audit/VPN 10/min burst 20; SYN/half-open/ICMP 5/min). IPv6 correctly lacks `IPOPT_RR_DROP`. |
| `firewall log rate --rate 100 --unit min --burst 200 --target audit` | Staged: `100/min, burst 200 (IPv4 + IPv6)` |
| `firewall save` (watchdog, confirm) | **Live kernel** `AKITA_LOG_ACCEPT/DROP` → `100/min burst 200` (v4 + v6); `ANTI_SPOOF_DROP` stayed `10/min`, `SYN_FLOOD_DROP` stayed `5/min` — **precise targeting confirmed** |
| `firewall log reset-default` + `save` | Live kernel restored to shipped `10/min burst 20` (v4 + v6) |

### Migration path — the gap in the PR's own report

The PR report tested factory-grey (fresh flash), which **skips** migration. The at-risk case — a field device updated by OTA, which still has the old inline-LOG `/etc` layout — was **not** covered. Reproduced it here: backed up `/etc/iptables_rules`, fabricated the old layout (inlined the LOG block back into the header, removed `10_fw_logging.rules`), then ran the **real** `iptables-rules-init.sh`.

| Step | Result |
|------|--------|
| Migration ran | `rc=0`; `10_fw_logging.rules` re-created (v4 + v6) |
| Header == template after migration (the PR's core assumption) | PASS — byte-identical, v4 + v6 |
| **Assembled ruleset identical before/after** | PASS — v4 + v6; **no duplicate LOG rules, no loss** |
| Assembled ruleset validates in kernel (`iptables-restore --test`) | PASS — v4 + v6 (the `never matched protocol: ah` line is a harmless module-not-loaded warning under `--test`, not an error) |

A migrated device therefore ends up identical to a freshly-flashed one, at the assembled-ruleset level.

---

## Cleanup / state

- Test artifacts removed from the device; `/etc/iptables_rules` restored from backup (split layout intact); live kernel back at default `10/min burst 20`.
- No change left on the device from this verification.

## Note (out of scope, unrelated to #139)

`/usr/lib/shiba/shiba-variant` is absent on this image — the variant marker file did not get installed. It has no bearing on #139, but it is worth a separate look at how this image was built, since other code (e.g. OTA cross-variant guard) reads that file.
