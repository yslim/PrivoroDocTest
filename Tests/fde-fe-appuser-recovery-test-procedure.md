---
title: "Dual-DAR FDE/FE — Admin Recovery + self-contained backends — On-Device Test Procedure"
subtitle: "branch fde-fe-admin-recovery (7eb7fde5)"
author: "Privoro / Akita security team"
date: "2026-07-20"
geometry: margin=2cm
fontsize: 10pt
---

# Overview

On-device verification for the `fde-fe-admin-recovery` branch. Three change
groups land together here and **none has been exercised on hardware yet**:

1. **Admin recovery keyslot** (replaces the old TPM recovery-hash escrow).
   Data FDE = LUKS keyslot 0 (recovery) + keyslot 1 (user); inner FE = a second
   gocryptfs conf (`gocryptfs.recovery.conf`) wrapping the same master key.
   Unified `create-passphrase`, recovery-based `reset-passphrase`,
   `recovery-passphrase change`, and a **separate** recovery FIA_AFL lockout.
2. **Offline RSA-OTP algorithm rework** — the finalized CryptPack day-file
   algorithm, verified in-process by the FIPS C helper `fe-offline-verify`.
3. **Self-contained backends — one sudo entry per user-facing command.** Each
   command maps to a single backend that does the whole operation as root, so the
   appuser sudoers is one line per command and the security gates cannot be
   bypassed:
   - **FDE** `fde-data-mount.sh` prompts on the tty, unlocks + mounts, and drives
     any owed forced change in-process (`--current-file` into
     `fde-data-change-passphrase.sh`).  `fde-data-{unmount,status,change-passphrase}.sh`
     likewise self-contained.
   - **FE** `gocryptfs-fe.sh mount` reads PIN2 + RSA PIN + tokencode, runs the
     online RSA-OTP **in-process** via `scli … internal-mfa-auth` (the /auth JSON
     loop stays in Go → **no jq**) or the offline day-file gate, then opens.  The
     OTP gate is **bound inside `mount`** — the `mount-online` (open-trusting-
     prior-auth) subcommand is removed, so appuser cannot bypass 2FA.
     `gocryptfs-fe.sh {change,unmount,status}` complete the set.
   `security fde/fe` (admin) and the appuser front-end reach the **same** backends.

**appuser account, GUI, and the `fde-user`/`fe-user` front-ends are shoor's** —
this branch delivers the self-contained backends + the appuser sudoers they need.
Phases **5–7** exercise the appuser side and require shoor's account/wrappers
present in the build.

**Target**: STM32MP15, red variant (`shiba-*-red`). FE / appuser are red-only.

**Operator-typed secrets.** Every passphrase / PIN / tokencode is typed by the
human tester at the console (or GUI pty). Steps needing a secret are marked
**🔑**. Do not script secret entry.

**Result key** — mark each case: `[P]` pass · `[F]` fail · `[B]` blocked ·
`[-]` not yet run. Fill the date + notes on the Result line.

\newpage

# Results summary

| Phase | Area | Status |
|-------|------|--------|
| 0 | Build / install sanity | [-] |
| 1 | Data FDE — recovery keyslot (admin) | [P] r184 (T1.1/1.2/1.3/1.7) |
| 2 | Data FDE — FIA_AFL lockouts | [~] partial (pw_retry strike/reset) |
| 3 | Inner FE — recovery conf (admin) | [-] |
| 4 | OTP offline algorithm (FIPS) | [-] |
| 5 | appuser path (needs shoor's front-end) | [-] |
| 6 | Security boundary (sudoers scoping / bypass / env) | [-] |
| 7 | pty (GUI model) | [-] |
| 8 | Dual-DAR teardown + admin regression | [-] |

\newpage

# 0. Prerequisites

## 0.1 Build & deploy

**Option A — full SWU (recommended, end-to-end):**

```bash
# on the build host (orb)
bitbake swu-image-secure
# copy to device, then on device:
/usr/sbin/update-sw.sh /home/root/<image>.swu && systemctl reboot
```

**Option B — quick partial deploy (scli + shell backends only):**

```bash
GOOS=linux GOARCH=arm GOARM=7 go build \
  -C recipes-admin/cmd-line-interface/files/scli -o /tmp/scli-armhf .
TARGET=root@<device-ip>
scp /tmp/scli-armhf "$TARGET:/usr/bin/scli"
scp recipes-admin/shiba-config-scripts/files/config-scripts/fde-data-*.sh "$TARGET:/usr/sbin/"
scp recipes-security/gocryptfs/gocryptfs-init/gocryptfs-fe.sh "$TARGET:/usr/sbin/"
scp recipes-admin/shiba-config-scripts/files/config-scripts/appuser-fde \
    recipes-admin/shiba-config-scripts/files/config-scripts/appuser-fe "$TARGET:/usr/bin/"
scp recipes-admin/user-accounts/files/scli-sudoers "$TARGET:/etc/sudoers.d/scli"   # then visudo -c
ssh "$TARGET" 'chmod 755 /usr/bin/scli /usr/sbin/fde-data-*.sh /usr/sbin/gocryptfs-fe.sh /usr/bin/appuser-*'
```
Note: `fe-offline-verify` (C helper) and any TPM-handle changes need a real
build (Option A); Option B cannot deploy the compiled helper.

## 0.2 Confirm variant

```bash
cat /usr/lib/shiba/shiba-variant     # must be: red
```

## T0 — Build / install sanity

- **T0.1** (shoor) `appuser` account + front-end present (account, GUI/wrappers,
  and any `fde-user`/`fe-user` scli tree are shoor's).
  Result: `[-]` __________
- **T0.2** sudoers valid + matches the reference below:
  `visudo -cf /etc/sudoers.d/scli` → parsed OK; the `appuser` rule lists exactly
  the 8 self-contained backends and `Defaults env_reset` is present.
  Result: `[-]` __________
- **T0.3** Backends present: `ls /usr/sbin/fde-data-{mount,unmount,status,chg-reason,change-passphrase}.sh /usr/sbin/gocryptfs-fe.sh /usr/sbin/fe-offline-verify`.
  Result: `[-]` __________

## 0.3 appuser sudoers — reference (one entry per command, no bypass)

The self-contained backends let appuser's sudoers be exactly one line per
user-facing command. `mfa-mtls-request.sh` is **not** listed (the FE `mount`
backend calls it in-process as root); admin-only subcommands
(`gocryptfs-fe.sh reset|recovery-change|init|mount-online`, `fde-data-reset-passphrase.sh`,
…) are **excluded**, so 2FA / recovery cannot be bypassed.

```
Defaults env_reset                 # backends honour FDE_KEK_LIB/DATA_PART env -> must strip

appuser ALL=(root) NOPASSWD: \
    /usr/sbin/fde-data-mount.sh "", \
    /usr/sbin/fde-data-unmount.sh "", \
    /usr/sbin/fde-data-status.sh "", \
    /usr/sbin/fde-data-change-passphrase.sh "", \
    /usr/sbin/gocryptfs-fe.sh mount, \
    /usr/sbin/gocryptfs-fe.sh change, \
    /usr/sbin/gocryptfs-fe.sh unmount, \
    /usr/sbin/gocryptfs-fe.sh status
```

The `""` (no-argument) form on the FDE scripts matters: it forbids appuser from
passing `fde-data-change-passphrase.sh --current-file <own file>` (which would
skip the current-passphrase check).  The in-process forced change reaches
`--current-file` only from `fde-data-mount.sh` running as root, not via sudo.

\newpage

# 1. Data FDE — recovery keyslot (admin, `security fde …`)

- **T1.1 🔑 create-passphrase** — enter recovery + user default.
  Expected: `cryptsetup luksDump /dev/disk/by-partlabel/data` shows **keyslot 0
  and 1** enrolled.
  Result: `[-]` __________
- **T1.2 🔑 first mount → forced change** — `security fde mount`, enter the user
  default. Expected: forced-change banner (reason=reset) → prompts a new
  passphrase → `/data` mounted; `mount | grep /data` present.
  Result: `[-]` __________
- **T1.3 🔑 remount** — `security fde unmount` then `security fde mount` with the
  new passphrase. Expected: mounts, no forced change.
  Result: `[-]` __________
- **T1.4 🔑 change-passphrase** — `security fde change-passphrase` (current →
  new). Expected: re-key succeeds; old passphrase now fails, new works.
  Result: `[-]` __________
- **T1.5 🔑 reset-passphrase (recovery)** — `security fde reset-passphrase`,
  authenticate with the **recovery** passphrase, set a new user default.
  Expected: user slot re-keyed; next mount forces a change.
  Result: `[-]` __________
- **T1.6 🔑 recovery-passphrase change** — `security fde recovery-passphrase
  change` (old recovery → new). Expected: succeeds; a subsequent reset works
  with the NEW recovery passphrase only.
  Result: `[-]` __________
- **T1.7 show status** — `security fde show status`. Expected: provisioned /
  unlocked / mounted state + keyslot + counters reported.
  Result: `[-]` __________
- **T1.8 luks-erase** — `security fde luks-erase`. Expected: refuses while FE
  mounted; otherwise destroys both keyslots + evicts /data-bound TPM handles
  (20/21, 30/31); status shows erased.
  Result: `[-]` __________
- **T1.9 🔑 re-create** — `create-passphrase` again on the orphaned header.
  Expected: re-provisions cleanly.
  Result: `[-]` __________

# 2. Data FDE — FIA_AFL lockouts

- **T2.1 🔑 user lockout** — mount with a wrong passphrase repeatedly.
  Expected: after the max tries, timed lockout; auto-unlock after the TPM-Clock
  interval; status shows remaining tries / lockout time.
  Result: `[-]` __________
- **T2.2 🔑 separate recovery lockout** — in `reset-passphrase`, enter a wrong
  recovery passphrase 3×. Expected: recovery slot locks **independently** (user
  slot not affected; a user mount still works).
  Result: `[-]` __________
- **T2.3 unlock-pw-retry** — `security fde unlock-pw-retry`. Expected: clears
  **both** the user and recovery lockouts.
  Result: `[-]` __________

\newpage

# 3. Inner FE — recovery conf (admin, `security fe …`)

Requires the data FDE mounted first (`require_data_mounted`).

- **T3.1 🔑 create-passphrase** — recovery + user default.
  Expected: `/data/.securefs/` has **both** `gocryptfs.conf` and
  `gocryptfs.recovery.conf`.
  Result: `[-]` __________
- **T3.2 🔑 mount (offline OTP)** — `security fe mount`; enter FE passphrase
  (PIN2 ≥15), RSA PIN, tokencode with the proxy **unreachable**. Expected: the
  self-contained `mount` backend runs `internal-mfa-auth` → exit 3 (unreachable)
  → offline day-file gate passes → `/securefs` mounted → forced change on first
  mount (driven via the shared `change` backend).
  Result: `[-]` __________
- **T3.3 🔑 mount (online OTP)** — same with the MFA proxy reachable. Expected:
  `internal-mfa-auth` validates `/auth` in-process (exit 0) → the same `mount`
  backend opens the store (no separate `mount-online`).  NB: online mounts no
  longer refresh day-data (admin `security mfa sync` does); a server New-PIN
  challenge here falls back to offline (set the new PIN via `mfa sync`).
  Result: `[-]` __________
- **T3.3b 🔑 online OTP denied** — mount with a wrong tokencode, proxy reachable.
  Expected: `internal-mfa-auth` exit 4 → `mount` strikes FIA_AFL + refuses (no
  silent offline fallback on an explicit denial).
  Result: `[-]` __________
- **T3.4 🔑 change-passphrase** — `security fe change-passphrase` (verifies
  current first, then new). Expected: re-wrap succeeds.
  Result: `[-]` __________
- **T3.5 🔑 reset-passphrase (recovery)** — recovery conf → new user default →
  forced change next mount.
  Result: `[-]` __________
- **T3.6 🔑 recovery-passphrase change** — rotate `gocryptfs.recovery.conf`.
  Result: `[-]` __________
- **T3.7 FE lockouts + unlock** — user + separate recovery lockout;
  `security fe unlock-pw-retry` clears both.
  Result: `[-]` __________
- **T3.8 unmount** — `security fe unmount`. Expected: `/securefs` down, `/data`
  still mounted.
  Result: `[-]` __________

# 4. OTP offline algorithm (FIPS `fe-offline-verify`)

- **T4.1 🔑 offline match** — with valid day-files present, an offline mount
  (T3.2) accepts the real RSA PIN + tokencode. Confirms the finalized algorithm
  `SHA256(salt‖pepper‖pin.lower()+tok)`, 18-bit pepper, ±2 slots.
  Result: `[-]` __________
- **T4.2 FIPS provider** — `fe-offline-verify` refuses if the OpenSSL fips
  provider is absent (built with `fips=yes`, fail-closed). Spot-check:
  `openssl list -providers` shows `fips`.
  Result: `[-]` __________
- **T4.3 🔑 anti-replay** — reuse the same tokencode/slot immediately.
  Expected: rejected (single-use slot; TPM last-accepted-slot floor).
  Result: `[-]` __________

\newpage

# 5. appuser path (requires shoor's front-end)

The self-contained backends are ours; the appuser account + front-end (GUI, or a
`fde-user`/`fe-user` scli tree) and `/securefs` data access are **shoor's**.  Run
these against a build that carries them.  Each appuser command must reach exactly
one backend (per the 0.3 sudoers) and behave like the admin path (phases 1/3).

- **T5.1** appuser reaches FDE mount via the front-end → `/data` mounted; the
  forced change is prompted when owed (same as T1.2).
  Result: `[-]` __________
- **T5.2** appuser FDE unmount / status / 🔑 change-passphrase behave as admin.
  Result: `[-]` __________
- **T5.3 🔑** appuser reaches FE mount via the front-end (PIN2 + RSA OTP, online
  or offline) → `/securefs` mounted; FE change / unmount / status work.
  Result: `[-]` __________
- **T5.4** appuser can read/write the intended user data area, and TSF material
  is protected — as appuser (must all FAIL): touch `/data/anything`; rename
  `/data/.securefs`; rename `/data/.mfa`; write under `/securefs` root.
  (`/securefs/app` ownership is part of shoor's FE-access work.)
  Result: `[-]` __________

# 6. Security boundary (sudoers / env / guard)

- **T6.1 admin backend denied** — as appuser, run (must be DENIED by sudo):
  `sudo /usr/sbin/fde-data-reset-passphrase.sh`,
  `sudo /usr/sbin/gocryptfs-fe.sh reset`,
  `sudo /usr/sbin/gocryptfs-fe.sh recovery-change`,
  `sudo /usr/sbin/gocryptfs-fe.sh init`.
  Result: `[-]` __________
- **T6.2 2FA-bypass denied** — as appuser:
  `sudo /usr/sbin/gocryptfs-fe.sh mount-online` → DENIED (not in sudoers; also the
  dispatch is removed).  Confirms appuser cannot open the FE store without passing
  the OTP gate bound inside `mount`.
  Result: `[-]` __________
- **T6.3 argument scoping** — as appuser:
  `sudo /usr/sbin/fde-data-change-passphrase.sh --current-file /tmp/x` → DENIED
  (the `""` rule forbids arguments).  Confirms appuser cannot re-key with an
  attacker-supplied "current" file.
  Result: `[-]` __________
- **T6.4 allowed backend reachable** — `sudo /usr/sbin/gocryptfs-fe.sh status`
  runs (sudo permits the 8 listed entries).
  Result: `[-]` __________
- **T6.5 env_reset** — as appuser:
  `sudo FDE_KEK_LIB=/tmp/evil.sh /usr/sbin/fde-data-status.sh`. Expected: the env
  override is stripped (evil path not used).
  Result: `[-]` __________

\newpage

# 7. pty (GUI model)

The FDE backend self-prompts on the tty, so it runs directly in a GUI-spawned
pty (the FE backend reads secrets on stdin from its front-end).

- **T7.1 🔑 FDE mount inside a pty** — run the self-contained FDE mount through a
  pty, e.g. `script -q /dev/null -c 'sudo /usr/sbin/fde-data-mount.sh'` (or
  `python3 -c 'import pty; pty.spawn(["sudo","/usr/sbin/fde-data-mount.sh"])'`).
  Expected: the no-echo passphrase prompt works in the pty; mount succeeds.
  Confirms the GUI-spawns-a-pty model needs no code change.
  Result: `[-]` __________
- **T7.2 🔑 Ctrl-C restore** — press Ctrl-C at the passphrase prompt. Expected:
  tty echo is restored (`fde-read-passphrase.sh` `trap cleanup INT`); the shell is
  usable afterward.
  Result: `[-]` __________

# 8. Dual-DAR teardown + admin regression

- **T8.1 teardown order** — with FE mounted, `security fde unmount` → refuses;
  `security fe unmount` then `security fde unmount` → succeeds.
  Result: `[-]` __________
- **T8.2 🔑 admin regression** — confirm the shared-function refactor did not
  change admin behavior: `security fde mount/unmount/change-passphrase/show
  status` and `security fe mount/unmount/change-passphrase/show status` all
  behave as before.
  Result: `[-]` __________

\newpage

# Known limitations (self-contained FE mount) — verify behaviour, not bugs

- **New-PIN during mount → offline fallback.** A server-forced RSA New-PIN
  challenge during `mount` cannot complete (the in-process `internal-mfa-auth`
  reads the exhausted creds pipe); it falls back to the offline gate.  Set the new
  PIN via `security mfa sync` / `create-passphrase`.  (Fix path: reopen fd 0 to
  `/dev/tty` for challenges.)
- **Online mount no longer refreshes day-data.** Admin `security mfa sync` keeps
  the offline day-files current; online `mount` only validates + opens.
- **Dead shell fns.** `fe_mount`, `fe_mount_online`, `fe_pw_retry_strike` and their
  dispatch entries are left in `gocryptfs-fe.sh` (unused after `fe_mount_secure`);
  harmless, pending cleanup.

# On-device results log

**2026-07-20 · shiba-25q3ml · r184-20260720 · FDE admin path (via `security fde …`)**

- Build sanity: self-contained backends present (`fe_mount_secure`, `internal-mfa-auth`,
  `--current-file`, FDE `--tty`). **[P]**
- **T1.1** create-passphrase → `provisioned: yes` + `recovery slot: yes` (keyslot 0+1). **[P]**
- **T1.2** mount + forced change: self-contained backend prompts on the tty; a wrong
  passphrase struck FIA_AFL (`remaining=2`); correct one mounted `/data`; the forced-change
  banner fired (chg-reason=reset); "must differ" + password policy (`needs a lowercase`)
  enforced; re-key succeeded — all in one flow, no Go orchestration. **[P]**
- **T1.3** unmount (umount + close, "unmounted and locked") → remount with the NEW
  passphrase mounts directly, **no re-forced-change** (flag cleared, one-shot). **[P]**
- **T1.7** `show status` correct throughout (mounted, pw_retry reset to 3/3 on success). **[P]**
- T2.1 (partial): pw_retry decremented on the wrong passphrase, reset on success; full
  lockout/auto-unlock not yet exercised.

_Pending: FDE change-passphrase standalone, reset/recovery, lockouts; FE (create + mount
via internal-mfa-auth online/offline); appuser sudoers (shoor's front-end)._

# Notes / issues log

_(record anomalies, device serial, image version (`r<n>`), and dates here)_

- 
