---
title: "Dual-DAR FDE/FE — Admin Recovery + appuser — On-Device Test Procedure"
subtitle: "Branch: fde-fe-admin-recovery · Tip commit: 1672484a"
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
3. **appuser integration** — the unprivileged data-owner account drives the
   user-facing FDE/FE ops through the scli `fde-user` / `fe-user` trees
   (scoped sudoers, `SCLI_GUARDED_ONESHOT`), typically from a GUI-spawned pty.
   `security fde/fe` (admin) and `fde-user/fe-user` (appuser) share one Go
   implementation.

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
| 1 | Data FDE — recovery keyslot (admin) | [-] |
| 2 | Data FDE — FIA_AFL lockouts | [-] |
| 3 | Inner FE — recovery conf (admin) | [-] |
| 4 | OTP offline algorithm (FIPS) | [-] |
| 5 | appuser path (NEW) | [-] |
| 6 | Security boundary (sudoers / env / guard) | [-] |
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

- **T0.1** `appuser` account exists, shell `/bin/sh`:
  `getent passwd appuser` → shell field `/bin/sh`.
  Result: `[-]` __________
- **T0.2** Wrappers present, old ones gone:
  `ls /usr/bin/appuser-fde /usr/bin/appuser-fe` present;
  `ls /usr/bin/appuser-mount` → absent.
  Result: `[-]` __________
- **T0.3** sudoers valid + scoped: `visudo -cf /etc/sudoers.d/scli` → parsed OK;
  rule lists the appuser backends + `Defaults env_reset`.
  Result: `[-]` __________
- **T0.4** Backends present: `ls /usr/sbin/fde-data-{mount,unmount,status,chg-reason,change-passphrase}.sh /usr/sbin/gocryptfs-fe.sh /usr/sbin/fe-offline-verify`.
  Result: `[-]` __________

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
  (PIN2 ≥15), RSA PIN, tokencode with the proxy **unreachable**. Expected:
  offline day-file gate passes → `/securefs` mounted → forced change on first
  mount.
  Result: `[-]` __________
- **T3.3 🔑 mount (online OTP)** — same with the MFA proxy reachable. Expected:
  online `/auth` validates, `mount-online` opens the store; offline days
  refreshed.
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

# 5. appuser path (NEW — commit 1672484a)

- **T5.1 login** — log in as `appuser` on the serial console. Expected: a
  `/bin/sh` prompt (not scli).
  Result: `[-]` __________
- **T5.2 🔑 appuser-fde mount** — `appuser-fde mount`, enter the data
  passphrase. Expected: same flow as admin (prompt → mount → forced change if
  owed). `/data` mounted.
  Result: `[-]` __________
- **T5.3 appuser-fde status / unmount** — `appuser-fde status`, `appuser-fde
  unmount`. Expected: work; unmount refuses if FE still mounted.
  Result: `[-]` __________
- **T5.4 🔑 appuser-fde change-passphrase** — Expected: re-keys user slot.
  Result: `[-]` __________
- **T5.5 🔑 appuser-fe mount** — `appuser-fe mount` (PIN2 + RSA OTP). Expected:
  `/securefs` mounted.
  Result: `[-]` __________
- **T5.6 /securefs/app ownership** — `ls -ld /securefs/app` → `appuser:appuser`,
  mode `0700`. As appuser: write + read back a file under `/securefs/app`.
  Result: `[-]` __________
- **T5.7 TSF material protection** — as appuser, attempt (must all FAIL):
  write/rename/unlink under `/securefs` root; touch `/data/anything`;
  rename `/data/.securefs`; rename `/data/.mfa`.
  Result: `[-]` __________
- **T5.8 appuser-fe status / unmount / 🔑 change-passphrase** — Expected: work.
  Result: `[-]` __________

# 6. Security boundary (sudoers / env / guard)

- **T6.1 admin backend denied** — as appuser, run (must be DENIED by sudo):
  `sudo /usr/sbin/fde-data-reset-passphrase.sh`,
  `sudo /usr/sbin/gocryptfs-fe.sh reset`,
  `sudo /usr/sbin/gocryptfs-fe.sh recovery-change`,
  `sudo /usr/sbin/gocryptfs-fe.sh init`.
  Result: `[-]` __________
- **T6.2 allowed backend reachable** — `sudo /usr/sbin/gocryptfs-fe.sh status`
  runs (sudo permits). 
  Result: `[-]` __________
- **T6.3 env_reset** — as appuser:
  `sudo FDE_KEK_LIB=/tmp/evil.sh /usr/sbin/fde-data-status.sh`. Expected: the
  env override is stripped (evil path not used).
  Result: `[-]` __________
- **T6.4 guard boundary** — as appuser:
  `SCLI_GUARDED_ONESHOT=1 scli security fde reset-passphrase`. Expected:
  cmdguard permission-denied (appuser only reaches `fde-user`/`fe-user`).
  Result: `[-]` __________

\newpage

# 7. pty (GUI model)

- **T7.1 🔑 mount inside a pty** — run the appuser mount through a pty, e.g.
  `script -q /dev/null -c 'appuser-fde mount'` (or `python3 -c 'import pty,sys;
  pty.spawn(["appuser-fde","mount"])'`). Expected: `term.ReadPassword` no-echo
  works in the pty; mount succeeds. Confirms the GUI-spawns-a-pty model needs no
  code change.
  Result: `[-]` __________
- **T7.2 🔑 Ctrl-C restore** — press Ctrl-C at the passphrase prompt. Expected:
  tty echo is restored (`restoreTerminalOnSignal` in the guarded-oneshot path);
  the shell is usable afterward.
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

# Notes / issues log

_(record anomalies, device serial, image version (`r<n>`), and dates here)_

- 
