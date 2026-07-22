---
title: "Dual-DAR FDE/FE — Admin Recovery + self-contained backends — On-Device Test Procedure"
subtitle: "branch fde-fe-admin-recovery (bd93066b)"
author: "Privoro / Akita security team"
date: "2026-07-22"
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
   - **FE** `fe-mount.sh` prompts PIN2 + RSA PIN + tokencode on the tty, runs the
     online RSA-OTP **in-process** via `scli … internal-mfa-auth` (the /auth JSON
     loop stays in Go → **no jq**) or the offline day-file gate, then opens.  The
     OTP gate is **bound inside the backend**, so appuser cannot bypass 2FA.
   `security fde/fe` (admin) and the appuser front-end reach the **same** backends.

4. **FE split into one backend per command** (2026-07-22).  `gocryptfs-fe.sh`
   (1425 lines behind a subcommand dispatcher) is **deleted**; the shared core
   lives in `/usr/lib/shiba/fe-lib.sh` and each user-facing command is its own
   `/usr/sbin/fe-*.sh`, mirroring the data-FDE layout.  Because each backend
   prechecks and prompts itself, precheck + input + operation happen in ONE root
   process — so an appuser sudoers entry is a **bare path with no argument
   matching**, and no separate precheck entry is needed.
5. **RSA PIN set at the user's first mount** (2026-07-22).  `create-passphrase`
   no longer touches RSA and needs no network: provisioning is an administrator
   task, while the 4-8 digit RSA PIN is the end user's own secret, established
   server-side at their first `security fe mount` (New-PIN challenge).  Gated by
   the new `mfa.pin-enrolled` flag; the challenge prompts read `/dev/tty`.
6. **Offline day-data upkeep** (2026-07-22).  An online mount tops the window up
   when it falls below the new `mfa.offline-refresh-days`; `mfa show status`
   reports the window that can actually still mount.

**appuser account + the `fde-user` scli tree + the `appuser-mount` /
`appuser-change-passphrase` wrappers are shoor's** (retained — only our own scli
`user`-account work was reverted).  This branch delivers the self-contained
backends those wrappers reach.  Shoor's current front-end is **FDE-only** (mount +
change-passphrase); Phases **5–6** exercise it and require shoor's account/wrappers
in the build.

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
| 0 | Build / install sanity | [P] 07-20 appuser acct + 2-entry sudoers + wrappers present |
| 1 | Data FDE — recovery keyslot (admin) | [P] 07-20 change/reset(mnt+**unmnt**)/recovery-change + keyslots |
| 2 | Data FDE — FIA_AFL lockouts | [P] 07-20 user lockout + **independent** recovery lockout + unlock |
| 3 | Inner FE — recovery conf (admin) | [P] 07-20 change/reset/recovery-change + online mount forced-change |
| 4 | OTP offline algorithm (FIPS) | [P] offline day-data + anti-replay floor + skew ±2 |
| 5 | appuser path | [P] 07-20 appuser-mount + appuser-change-passphrase (FDE-only surface) |
| 6 | Security boundary (sudoers scoping / bypass / env) | [P] 07-20 sudo scope + pw-expiry gate + **anti-escalation** |
| 7 | pty (GUI model) | [-] not run |
| 8 | Dual-DAR teardown + admin regression | [P] 07-20 inner-first teardown order |
| 9 | FE backends — one script per command | [P] 07-22 all 12 backends + preflight + prompts |
| 10 | First-mount RSA PIN enrollment | [P] 07-22 offline create + New-PIN dialog + flag |
| 11 | Offline day-data — cap / threshold / display | [P] 07-22 top-up fires only below threshold |
| 12 | Data FDE — mount restricted to keyslot 1 | [P] 07-22 recovery rejected, user accepted |

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
scp recipes-admin/shiba-config-scripts/files/config-scripts/appuser-mount \
    recipes-admin/shiba-config-scripts/files/config-scripts/appuser-change-passphrase "$TARGET:/usr/bin/"
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
- **T0.2** sudoers valid + matches the reference below (§0.3).
  Result: `[P]` 07-20 — `/etc/sudoers.d/scli-sudoers` grants `appuser` exactly the
  **two FDE backends** (`fde-data-mount.sh`, `fde-data-change-passphrase.sh`).
  `sudo -l` as appuser confirms only those two (root NOPASSWD).
- **T0.3** Backends present: `ls /usr/sbin/fde-data-*.sh /usr/sbin/fe-*.sh /usr/lib/shiba/fe-lib.sh /usr/sbin/fe-offline-verify`;
  `/usr/sbin/gocryptfs-fe.sh` must be **absent** (replaced by the split, §9).
  Result: `[P]` 07-22 — 13 `fe-*.sh` (12 commands + `fe-precheck.sh`), `fe-lib.sh` 0644,
  old dispatcher gone.

## 0.3 appuser sudoers — actual on-device (shoor's) vs design

**Actual** (`/etc/sudoers.d/scli-sudoers`, verified 2026-07-20 shiba-25q3ml):

```
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

admin    ALL=(ALL:ALL) NOPASSWD: ALL
recovery ALL=(ALL:ALL) NOPASSWD: ALL
user     ALL=(ALL:ALL) NOPASSWD: ALL
appuser  ALL=(root) NOPASSWD: /usr/sbin/fde-data-mount.sh, /usr/sbin/fde-data-change-passphrase.sh
```

`appuser` reaches these only through two wrapper scripts (in `/usr/bin`):
`appuser-mount` / `appuser-change-passphrase`, each
`exec env SCLI_GUARDED_ONESHOT=1 /usr/bin/scli fde-user {mount,change-passphrase}`.
The `fde-user` scli tree is **appuser-gated** (`auth.LevelAppuser`); its
`RunMount`/`RunChangePassphrase` are the SAME backend entry points as
`security fde mount`/`change-passphrase`.  So our self-contained backend work is
exactly what lets shoor's appuser be **one sudo entry per command, no bypass**.

**Scope note (design vs actual).** After the FE split (§9) the full design is **8
bare paths** — no subcommand arguments, because each command is its own script:

```
appuser ALL=(root) NOPASSWD: /usr/sbin/fde-data-mount.sh, \
                             /usr/sbin/fde-data-unmount.sh, \
                             /usr/sbin/fde-data-status.sh, \
                             /usr/sbin/fde-data-change-passphrase.sh, \
                             /usr/sbin/fe-mount.sh, \
                             /usr/sbin/fe-change.sh, \
                             /usr/sbin/fe-unmount.sh, \
                             /usr/sbin/fe-status.sh
```

This supersedes the earlier plan of per-subcommand entries
(`gocryptfs-fe.sh mount`, …), which needed sudo argument matching — exact-match
on the whole command line, so adding an argument later would silently break
authorization, while opening the bare dispatcher path would have exposed the
admin subcommands (`init`, `reset`, `recovery-change`).  `fe-precheck.sh` is
**not** in the list: it exists only for `mfa sync`'s FE-state gate (admin).
Shoor's current sudoers still grants **only the two FDE entries** (mount +
change-passphrase); Phase 5/6 below test the actual two.

**Hardening rec (not a blocker):** the current entries omit the `""`
(no-argument) restriction, so appuser may pass args, e.g.
`fde-data-change-passphrase.sh --current-file <path>`.  This is **not** a bypass —
the backend still verifies the supplied current passphrase against keyslot 1
(`cryptsetup --test-passphrase`) — but adding `""` is recommended defense-in-depth.

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

# 5. appuser path (shoor's front-end — FDE mount + change only)

The self-contained backends are ours; the appuser account + the `fde-user` scli
tree + the `appuser-mount`/`appuser-change-passphrase` wrappers are **shoor's**
(retained — only our own scli `user`-account work was reverted).  The current
front-end grants **two** FDE commands (§0.3); FE and unmount/status are not
appuser-exposed yet.  Each command reaches exactly one self-contained backend and
behaves like the admin path.

- **T5.1** `appuser-mount` → `scli fde-user mount` (guarded oneshot) → `RunMount`
  → `sudo fde-data-mount.sh` → `/data` mounted; forced change prompted when owed.
  Result: `[P]` 07-20 — `id`=1004(appuser); wrapper chain mounted `/data`; the
  self-contained backend prompted on the tty and mounted (env self-sufficient under
  `sudo` env_reset, via `detect_tpm_algo`). No forced change owed → clean mount.
- **T5.2 🔑** `appuser-change-passphrase` → `RunChangePassphrase` →
  `sudo fde-data-change-passphrase.sh` → re-key.
  Result: `[P]` 07-20 — current→new→confirm→verify→re-key→"passphrase changed",
  identical to the admin path (T1). (FDE unmount/status are **not** in appuser's
  sudoers → out of scope for the current front-end.)
- **T5.3 🔑** appuser FE mount.
  Result: `[N/A]` — no FE entry in shoor's current sudoers; appuser cannot reach
  FE. (Covered on the admin path, Phase 3.)
- **T5.4** appuser data-area read/write + TSF-material protection under
  `/securefs`.
  Result: `[-]` deferred — part of shoor's `/securefs/app` FE-access work.

# 6. Security boundary (sudoers / env / guard)

- **T6.1 privileged sudo denied** — as appuser, anything outside the two granted
  backends must be denied:
  `sudo -n /usr/sbin/fde-data-unmount.sh`, `sudo -n /bin/sh -c id`,
  `sudo -n cryptsetup luksDump /dev/mmcblk1p10`.
  Result: `[P]` 07-20 — all three → `sudo: a password is required` (not in the
  NOPASSWD list → falls back to password auth, which appuser has none → **denied**).
  No unmount, no root shell, no cryptsetup.
- **T6.2 allowed backend reachable** — the two granted commands run via the
  wrappers.
  Result: `[P]` 07-20 — `appuser-mount` and `appuser-change-passphrase` both reach
  their backend and succeed (T5.1/T5.2).
- **T6.3 interactive scli blocked (pw-expiry gate)** — appuser has **no** interactive
  scli: any un-guarded `scli …` hits a password-expiry PAM gate.
  Result: `[P]` 07-20 — `scli security fde show status` and `scli fde-user mount`
  (no `SCLI_GUARDED_ONESHOT`) both → `Your password has expired. You must change it
  now.` then fail. Only the guarded wrappers bypass this, for their scoped commands.
- **T6.4 🔑 anti-escalation (guard ≠ privilege)** — appuser setting the guard env
  itself must NOT reach admin commands.
  Result: `[P]` 07-20 — `env SCLI_GUARDED_ONESHOT=1 scli security fde show status`
  → `Permission Denied: Command "security fde show status" requires "admin"
  privileges.` The guard only bypasses the pw-expiry gate; the `auth.LevelAppuser`
  check is enforced **independently**. `env SCLI_GUARDED_ONESHOT=1 scli fde-user
  mount` → runs (its own appuser-level command).
- **T6.5 2FA-bypass / admin-subcommand** — `gocryptfs-fe.sh mount-online` and the
  admin FE/reset subcommands.
  Result: `[N/A]` on-device — appuser has **no** FE or reset entry in its sudoers at
  all (§0.3), so none are reachable. Source-verified: the `mount-online` dispatch is
  removed from `gocryptfs-fe.sh` (the OTP gate is bound inside `mount`).
- **T6.6 env_reset** — sudo strips the caller env; the self-contained backend derives
  `FDE_PASSPHRASE_SOURCE` from `detect_tpm_algo`, not the caller.
  Result: `[P]` 07-20 (by behaviour) — `appuser-mount` mounted correctly under sudo
  `env_reset`; an injected `FDE_KEK_LIB=/tmp/evil` would be stripped. (Explicit
  evil-env probe not run.)

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
  Result: `[P]` 07-20 — `fde unmount` while FE mounted → `ERROR: inner FE is mounted
  at /securefs; run 'security fe unmount' first`; then `fe unmount` → `/securefs
  unmounted`; then `fde unmount` → `Data partition unmounted and locked`.
- **T8.2 🔑 admin regression** — confirm the shared-function refactor did not
  change admin behavior.
  Result: `[P]` 07-20 — full `security fde` (mount/unmount/change/reset/recovery-
  change/rotation/lockout/status) and `security fe` (mount/change/reset/recovery-
  change/unmount/status) exercised in Phases 1–3, 8; all behaved as expected.

\newpage

\newpage

# 9. FE backends — one script per command (`fe-*.sh` + `fe-lib.sh`)

The FE dispatcher is gone: `/usr/lib/shiba/fe-lib.sh` holds the shared core and
each command is its own `/usr/sbin/fe-*.sh`.  Every backend runs `fe_precheck`
itself and prompts on the tty, so a failing state is reported **before** the
operator types anything.

- **T9.1** Install layout (see also T0.3): 13 `fe-*.sh`, `fe-lib.sh` present, old
  dispatcher absent.
  Result: `[P]` 07-22 __________
- **T9.2** Preflight before prompting — with the store absent, `security fe mount`
  and `security fe change-passphrase` refuse **with no prompt**.
  Result: `[P]` 07-22 — `Error: FE not set up yet (run 'security fe create-passphrase' first)`
- **T9.3** 🔑 `create-passphrase` — a short value is rejected by the password
  policy and a mismatched confirmation re-asks from the Set step.
  Result: `[P]` 07-22 — `Error: password must be at least 15 characters long`;
  `Error: passphrases do not match; try again`
- **T9.4** 🔑 `change-passphrase` — a wrong current passphrase strikes FIA_AFL.
  Result: `[P]` 07-22 — `Error: incorrect current PIN (remaining=2)`, status `2/3`
- **T9.5** `unlock-pw-retry` clears the counter.  Result: `[P]` 07-22 — 2/3 → 3/3
- **T9.6** 🔑 `reset-passphrase` — `[y/N]` cancels; a wrong recovery passphrase
  strikes the **separate** recovery counter; success flags a forced change.
  Result: `[P]` 07-22 — `Reset cancelled.`;
  `Error: recovery passphrase incorrect (remaining=2)` (user counter untouched)
- **T9.7** 🔑 `recovery-passphrase change` — the new value must differ.
  Result: `[P]` 07-22 — `Error: the new passphrase must differ from the current one`
- **T9.8** `passphrase-rotation show status` / `set interval <n>`.
  Result: `[P]` 07-22 — disabled → 5 mounts (1/5) → disabled
- **T9.9** `unmount` refuses while busy and names the holder process.
  Result: `[P]` 07-22 — `Error: /securefs in use by pid(s): 331(sh) — close them (or 'cd' out) and retry`
- **T9.10** 🔑 Forced change after mount is driven by the backend itself
  (`fe-change.sh --current-file`), so the operator does **not** retype the current
  passphrase.
  Result: `[P]` 07-22 — mount → `A new passphrase must be set …` → Set/Confirm only

\newpage

# 10. First-mount RSA PIN enrollment

`create-passphrase` establishes only the local FE passphrases; the end user sets
their own RSA PIN at their first mount.  Requires the server-side token PIN to be
cleared before T10.2.

- **T10.1** 🔑 `create-passphrase` with the network **physically disconnected** —
  completes with no RSA prompt and no server contact.
  Result: `[P]` 07-22 — `ip -brief addr` showed only `lo`; store created
- **T10.2** 🔑 First mount, RSA PIN left **blank** → the server drives the New-PIN
  dialog (this is the only test that exercises the `/dev/tty` challenge path).
  Result: `[P]` 07-22 — `Enter a new PIN having from 4 to 8 alphanumeric characters:` →
  re-enter → `New tokencode (different from the one entered before):` → mounted
- **T10.3** Enrollment is recorded and the prompt reverts to normal.
  Result: `[P]` 07-22 — `/etc/scli.yml` `pin-enrolled: true`; next mount shows
  `Enter RSA PIN:` with no first-use banner
- **T10.4** Not enrolled **and** server unreachable → refuse before prompting.
  Result: `[-]` __________

\newpage

# 11. Offline day-data — cap, refresh threshold, coverage display

- **T11.1** `mfa show status` reports the window that can still mount, not just
  whether today is covered.
  Result: `[P]` 07-22 — `offline data: 100 days (2026-07-22 to 2026-10-29)`
- **T11.2** Online mount tops up only when the usable window is **below**
  `offline-refresh-days`.
  Result: `[P]` 07-22 — 0 days → refreshed at mount; 100 days ≥ 50 → **no** refresh
  on the next mount
- **T11.3** `offline-refresh-days` validation, both directions.
  Result: `[P]` 07-22 — `150`/`100` rejected (range 1..99); `refresh 20` rejected
  when max is 10; `max 40` rejected when refresh is 50
- **T11.4** Refresh reports what arrived **and** what is stored (the server may
  send fewer days than are already held).
  Result: `[P]` 07-22 — `Offline data refreshed: 14 day(s) received; now 14 days (…)`
- **T11.5** `offline-max-days` truncates a larger server response.
  Result: `[-]` __________ (needs the server to issue more than the cap)

\newpage

# 12. Data FDE — mount restricted to keyslot 1

Keyslot 0 is the admin recovery slot; it must never open the volume.  It is
accepted only by `reset-passphrase` / `recovery-passphrase change`, which re-key
keyslot 1 first.

- **T12.1** 🔑 `security fde mount` with the **recovery** passphrase → refused.
  Result: `[P]` 07-22 — `No key available with this passphrase.` /
  `Error: wrong passphrase or TPM state; LUKS open failed (remaining=2)`
- **T12.2** 🔑 `security fde mount` with the **user** passphrase → mounts, and the
  successful open clears the strike.
  Result: `[P]` 07-22 — mounted at `/data`, `pw_retry left: 3/3`
- **T12.3** Side effect (by design): a recovery passphrase typed at the mount
  prompt consumes a **user** pw_retry attempt.
  Result: `[P]` 07-22 — `remaining=2` after T12.1

# Known limitations — all three CLOSED 2026-07-22

- ~~**New-PIN during mount → offline fallback.**~~ **Fixed.** The FE prompts now
  open `/dev/tty` instead of fd 0 (which is the creds pipe), so a challenge
  reached from `internal-mfa-auth` reaches the operator.  Verified T10.2.  This
  also fixed a latent bug: a server-forced PIN change broke an ordinary mount.
- ~~**Online mount no longer refreshes day-data.**~~ **Fixed.** An online mount
  tops the window up when it falls below `offline-refresh-days`.  Verified T11.2.
- ~~**Dead shell fns.**~~ **Removed** with the split: `fe_mount`,
  `fe_mount_online`, `fe_verify` and `fe_pw_retry_strike` (188 lines) are gone,
  along with the Go helpers that fed them.

# On-device results log

**2026-07-22 · shiba-25q3ml · factory SWU + re-provision · FE backend split, first-mount enrollment, keyslot-1 mount**

_Deployment (§9 T9.1, T0.3):_ 13 `/usr/sbin/fe-*.sh` (12 commands + `fe-precheck.sh`),
`/usr/lib/shiba/fe-lib.sh` 0644, `/usr/sbin/gocryptfs-fe.sh` **absent**. **[P]**

_FE backends — every command exercised (§9):_
- Preflight: unprovisioned `fe mount` / `fe change-passphrase` refused **without
  prompting**; `fe unmount` reported "not mounted". **[P]**
- `create-passphrase`: banner, policy rejection, confirm-mismatch re-prompt, store
  created (`provisioned: yes`, `recovery slot: yes`, `pw_retry 3/3`). **[P]**
- `mount`: top-up fetched the day-window, opened the store, then drove the owed
  forced change itself via `fe-change.sh --current-file` (current passphrase not
  retyped). **[P]**
- `change-passphrase`: wrong current → `remaining=2`, status `2/3`; `unlock-pw-retry`
  → `3/3`. **[P]**
- `reset-passphrase`: `[y/N]` cancel; wrong recovery struck the **separate**
  recovery counter (`remaining=2`) leaving the user counter intact; success set the
  force-change flag, which the next mount honoured. **[P]**
- `recovery-passphrase change`: "must differ" enforced, then re-keyed. **[P]**
- `unmount`: refused while busy naming `331(sh)`; clean after the holder exited. **[P]**
- `passphrase-rotation`: disabled → 5 mounts (1/5) → disabled. **[P]**
- `seal-days` (implicit via the day-data write) and `fe-precheck.sh` (via
  `mfa sync`'s FE gate) both exercised. **[P]**

_First-mount RSA PIN enrollment (§10):_ `create-passphrase` completed with the
network **physically unplugged** (`ip -brief addr` = `lo` only) and asked for no
RSA input; the first mount with a **blank** PIN drove the server's 2-step New-PIN
dialog and mounted; `pin-enrolled: true` was written and the next mount showed the
normal `Enter RSA PIN:`. This is the only path that proves the `/dev/tty` prompt
fix — it could not have worked before. **[P]**

_Offline day-data (§11):_ status showed `100 days (2026-07-22 to 2026-10-29)`;
top-up fired at 0 days and was correctly **skipped** at 100 ≥ 50; range validation
rejected `150`/`100` and both cross-checks (`refresh 20` vs `max 10`, `max 40` vs
`refresh 50`). **[P]**

_Data FDE keyslot restriction (§12):_ the recovery passphrase did **not** open the
volume (`No key available with this passphrase.`), consuming one user attempt
(`remaining=2`); the user passphrase mounted and reset the counter to `3/3`. **[P]**

_Defects found and fixed during this campaign:_ doubled `Error: Error:` prefix on a
policy rejection; `fe-chg-reason.sh` shipped with no callers (removed); `mfa sync`
reported only the fetched count while `status` showed the larger stored window
(now prints both); `(cap)` suffix on the status line needed explaining (dropped).

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

**2026-07-20 · shiba-25q3ml · full campaign (admin `security fde/fe` + appuser)**

_FDE admin (`security fde …`):_
- **change-passphrase** standalone: current→new→confirm→verify→re-key; `luksDump`
  shows keyslot 0 (recovery) + 1 (user) both enrolled, both `Digest ID: 0` (same
  volume key); slot 1 re-keyed in place, slot 0 untouched; remount with the new
  passphrase, no re-forced-change. **[P]**
- **passphrase-rotation** show/set: `interval 2` → effective count reached 2 → next
  mount fired the **aged** forced change ("passphrase has expired"), re-keyed reusing
  the mount's passphrase (no current re-prompt); reset back to disabled. **[P]**
- **reset-passphrase** (recovery-authenticated): `[y/N]`→recovery PP verified
  (keyslot 0)→new default via `luksAddKey` slot 1→force-change NV→next mount fired the
  **reset** forced change ("administrator-set default or reset"). Verified **mounted
  AND unmounted** (lost-passphrase recovery = header+TPM only, no `/data` dependency);
  `luksDump` after: both keyslots intact. **[P]**
- **recovery-passphrase change**: current recovery verified→"must differ"→re-key
  slot 0 ("Recovery passphrase changed"). **[P]**
- **user lockout**: wrong PIN1 ×3 → `remaining 2→1→locked out (~10 min)`; a locked
  mount is refused **before the prompt**; `unlock-pw-retry` → "cleared (user +
  recovery; 3/3)"; correct PIN1 then mounts. **[P]**
- **recovery lockout (independent)**: wrong recovery ×3 → `recovery retry 2→1→locked`;
  `show status` proved independence — `pw_retry 3/3` unchanged, `recovery retry 0/3` +
  `recovery lock: locked`; `unlock-pw-retry` cleared both → `3/3`. **[P]**

_FE admin (`security fe …`, red):_
- **change-passphrase**: consolidated `change` re-wrapped the gocryptfs master key. **[P]**
- **reset-passphrase** (FE recovery conf) + **online mount**: `internal-mfa-auth` →
  "online-validated" → reset forced-change banner → new PIN2 re-wrap. **[P]**
- **recovery-passphrase change**: re-key FE recovery conf ("must differ"). **[P]**
- **lockout**: valid OTP passed but wrong PIN2 → `incorrect FE passphrase
  (remaining=2)` (OTP gate ≠ KEK); `fe unlock-pw-retry` → "cleared (user + recovery)"
  → 3/3. Full 3-strike dynamics = the shared TPM-Clock engine (proved on FDE). **[P]**

_Teardown:_ inner-first enforced — `fde unmount` refused while FE mounted → `fe
unmount` → `fde unmount` (T8.1). **[P]**

_appuser (shoor's front-end, FDE-only):_
- `appuser-mount` / `appuser-change-passphrase` → `scli fde-user …` (guarded oneshot)
  → same self-contained backends → mount + re-key OK (T5.1/T5.2). **[P]**
- Boundary: sudo scoped to the two backends (unmount/root-shell/cryptsetup all
  "password required"); un-guarded scli blocked by pw-expiry; **guard+admin command →
  "requires admin privileges" (no escalation)** (T6). **[P]**

_Prior session:_ FE offline mount (internal-mfa-auth unreachable → `fe-offline-verify`
gate), anti-replay floor (used slot rejected), skew ±2 window, server day-data correct.

_luks-erase (FCS_CKM.4): source-verified only — **skipped on-device** (destructive)._
_pty GUI model (Phase 7): not run._

# Notes / issues log

_(record anomalies, device serial, image version (`r<n>`), and dates here)_

- 
