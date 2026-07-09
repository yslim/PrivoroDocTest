# TPM Resource Map — Handles, NV Indices, Policies

Authoritative inventory of every TPM2 resource the secure-boot stack uses: persistent handles, NV indices, PCR allocation, and the policies bound to sealed secrets. Reflects the current branch (`fe-rsa-otp`).

## Conventions

- **Hash / curve:** `sha384` + `ecc384`, auto-detected per chip (`tpm-algo-lib.sh: detect_tpm_algo`); falls back to `sha256` + `ecc` on a SHA-256-only TPM (e.g. SLB9670). Values below assume SHA-384.
- **A/B banks:** every PCR-sealed per-slot secret is sealed twice, once per firmware bank, because each bank's predicted PCRs differ. Even handle = Bank 0, odd handle = Bank 1.
- **Sealing policy:** every sealed *persistent object* is bound to the compound policy `PolicyNV(device) AND PolicyPCR(sha384:1,4,5,8)` — see [Policies](#policies). NV *indices* are owner-auth and are **not** PCR-bound (so they survive an OTA bank switch in place).

## Persistent handles (`0x81xxxxxx`)

| Bank 0 / Bank 1             | Holds                              | Policy | Scope |
|-----------------------------|------------------------------------|--------|-------|
| `0x81000001`                | TPM primary key (owner, ecc384)    | —      | all   |
| `0x81010001` / `0x81010002` | VPN PKCS#11 PIN                     | NV+PCR | VPN   |
| `0x81010101` / `0x81010102` | IPsec PSK                          | NV+PCR | VPN   |
| `0x81010201` / `0x81010202` | IPsec PPK (post-quantum)           | NV+PCR | VPN   |
| `0x81020000` / `0x81020001` | rootfs LUKS key                    | NV+PCR | all   |
| `0x81020010` / `0x81020011` | overlay LUKS key                   | NV+PCR | all   |
| `0x81020020` / `0x81020021` | data FDE submask_B                 | NV+PCR | red   |
| `0x81020030` / `0x81020031` | FE offline day-data integrity MAC key (HMAC) | NV+PCR | red |
| `0x81020040` / `0x81020041` | data FDE recovery hash (submask_A escrow, admin reset-passphrase) | NV+PCR | red |
| `0x81020050` / `0x81020051` | FE recovery hash (submask_A_FE escrow, admin reset-passphrase) | NV+PCR | red |

Defined in: `tpm-seal-secret.sh` / `tpm-unseal-secret.sh` (PSK/PPK), `vpn-pkcs11-pin.sh` (VPN PIN), the initramfs unlock scripts (rootfs/overlay), `fde-data-provision.sh` (data submask_B), `gocryptfs-fe.sh` (FE day-MAC key, sealed via the shared `fde_reseal_submask_b` and selected per-bank by `daymac_handle`), `fde-data-provision.sh` / `fde-data-change-passphrase.sh` / `fde_rotate_salt` (data recovery hash via `fde_seal_recovery_hash`), `gocryptfs-fe.sh` (FE recovery hash), and `pcr-predict-reseal.sh` (reseal map). The recovery hashes seal `submask_A`/`submask_A_FE` (= the KEK) for admin `reset-passphrase`; they are re-sealed on every `change-passphrase` and auto KEK rotation.

*Scope:* `all` = every device; `red` = red variant only; `VPN` = present once IPsec/VPN is provisioned. The FE day-MAC key exists once MFA offline day-data has been fetched.

## NV indices (`0x01xxxxxx`) — owner hierarchy

| Index        | Variable                      | Purpose                                          | Attributes / auth                  | Scope |
|--------------|-------------------------------|--------------------------------------------------|------------------------------------|-------|
| `0x01500000` | `FDE_NV_INDEX`                | device-bind operand (PolicyNV anchor)            | ownerread / ownerwrite             | all   |
| `0x01500001` | `FDE_PW_COUNTER_NV` (data)    | data-FDE pw_retry monotonic counter (FIA_AFL)    | `nt=counter`                       | red   |
| `0x01500002` | `FDE_PW_BASELINE_NV` (data)   | data-FDE pw_retry baseline                       | PolicyAuthValue(H(submask_A))      | red   |
| `0x01500003` | `FDE_PW_COUNTER_NV` (FE)      | FE pw_retry monotonic counter (FIA_AFL)          | `nt=counter`                       | red   |
| `0x01500004` | `FDE_PW_BASELINE_NV` (FE)     | FE pw_retry baseline                             | PolicyAuthValue(H(submask_A_FE))   | red   |
| `0x01500005` | `FE_LOCKOUT_EXPIRY_NV`        | FE timed-lockout expiry (TPM-Clock ms)           | ownerwrite (u64)                   | red   |
| `0x01500006` | `FE_LASTSLOT_NV`              | FE offline anti-replay floor (last-accepted slot, epoch-min) | policywrite — PolicyAuthValue(H(submask_A_FE)) | red |
| `0x01500013` | `FDE_PWAGE_COUNTER_NV`        | data-FDE passphrase-age counter                  | `nt=counter`                       | red   |
| `0x01500014` | `FDE_PWAGE_BASELINE_NV`       | data-FDE passphrase-age baseline                 | ownerwrite                         | red   |
| `0x01500015` | `FDE_PWAGE_MAX_NV`            | data-FDE passphrase-age interval (default 100)   | ownerwrite                         | red   |
| `0x01500016` | `FDE_PWAGE_COUNTER_NV` (FE)   | FE passphrase-age counter                        | `nt=counter`                       | red   |
| `0x01500017` | `FDE_PWAGE_BASELINE_NV` (FE)  | FE passphrase-age baseline                       | ownerwrite                         | red   |
| `0x01500018` | `FDE_PWAGE_MAX_NV` (FE)       | FE passphrase-age interval (default 100)         | ownerwrite                         | red   |
| `0x01500019` | `FDE_LOCKOUT_EXPIRY_NV` (data)| data-FDE timed-lockout expiry (TPM-Clock ms)     | ownerwrite (u64)                   | red   |
| `0x0150001a` | `FDE_FORCECHG_NV` (data)      | data-FDE temp-passphrase force-change flag (reset) | ownerwrite                       | red   |
| `0x0150001b` | `FDE_FORCECHG_NV` (FE)        | FE temp-passphrase force-change flag (reset)     | ownerwrite                         | red   |
| `0x0150001c` | `FDE_SALTROT_BASELINE_NV` (data) | data-FDE auto-KEK-rotation baseline (mounts)  | ownerwrite                         | red   |
| `0x0150001d` | `FDE_SALTROT_BASELINE_NV` (FE)| FE auto-KEK-rotation baseline (mounts)           | ownerwrite                         | red   |
| `0x0150001e` | `FDE_SALTROT_MAX_NV` (data)   | data-FDE auto-KEK-rotation interval (default 10) | ownerwrite                         | red   |
| `0x0150001f` | `FDE_SALTROT_MAX_NV` (FE)     | FE auto-KEK-rotation interval (default 10)        | ownerwrite                         | red   |

`0x01500007`–`0x01500012` remain **free** (an earlier KEK-rotation block was never allocated there; the implemented auto KEK rotation reuses the pwage mount counters + baselines `0x0150001c/1d` and interval NVs `0x0150001e/1f`).

- **data-partition FDE** (red) uses `0x01500001/02` (retry) + `0x01500013/14/15` (passphrase aging) + `0x01500019` (timed lockout) + `0x0150001a` (force-change) + `0x0150001c/1e` (auto KEK-rotation baseline + interval). Defined in `fde-kek-lib.sh`.
- **inner FE** (`/securefs`, red) uses `0x01500003/04` (retry — `gocryptfs-fe.sh` overrides the shared `FDE_PW_*` defaults so FE has its own counter, separate from data FDE), `0x01500005` (10-min timed lockout), `0x01500006` (offline anti-replay floor), `0x01500016/17/18` (passphrase aging), `0x0150001b` (force-change), `0x0150001d/1f` (auto KEK-rotation baseline + interval). Defined in `gocryptfs-fe.sh`.
- **Auto KEK rotation** (both): every N mounts (default 10, operator-set via `security fde/fe kek-rotation set`, stored in `0x0150001e/1f`) the salt is regenerated so the KEK (`submask_A`/`submask_A_FE`) rotates under the SAME passphrase. `effective = pwage counter − saltrot baseline ≥ interval` triggers it; the baseline resets on each rotation. Crash-safe: FDE via LUKS `luksAddKey`→reseal→`luksRemoveKey`, FE via a `.kdfsalt.new` WAL side-file + mount fallback.
- Counters are monotonic (`nt=counter`); the displayed retry value is `effective = counter − baseline`.

## PCR allocation (measured boot, SHA-384)

| PCR  | Extended by | Measures                    |
|------|-------------|-----------------------------|
| `#1` | TF-A BL2    | FIP — all BL2-loaded images |
| `#4` | U-Boot      | kernel                      |
| `#5` | U-Boot      | DTB                         |
| `#8` | U-Boot      | initramfs                   |

Policy PCR list: **`sha384:1,4,5,8`** (`tpm-algo-lib.sh`). TF-A computes the SHA-384 digest in software (the STM32 HASH block is SHA-256 only) and extends PCR#1 directly from BL2 — `stm32mp1_event_log_metadata` maps every BL2-loaded image to `PCR_1`. U-Boot extends #4/#5/#8 from the FIT-image hook in `boot/image-fit.c`.

## Policies

### Compound sealing policy (all sealed persistent objects)

Built as a trial policy at seal time, enforced at unseal:

1. `tpm2_policynv` — compare NV `0x01500000` (device-bind operand, derived from the device serial via `make_nv_operand`) with `eq`. Binds the secret to **this device**.
2. `tpm2_policypcr` — `sha384:1,4,5,8`. Binds the secret to the **measured-boot state**.

Sealed object attributes: `fixedtpm | fixedparent | adminwithpolicy`, created under the **owner-hierarchy** ecc384 primary using **encrypted + HMAC sessions**. Unsealing requires satisfying both policy terms — a wrong device serial or any PCR mismatch fails the unseal.

### PolicyAuthValue (red only)

These NVs are `policywrite`-gated by an `authValue` derived from the submask (the KEK), so only a caller that holds the correct passphrase can write them:

- pw_retry **baselines** — data FDE `0x01500002` (`H(submask_A)`) and FE `0x01500004` (`H(submask_A_FE)`): only the passphrase-holder can reset the retry counter, so failed attempts increment the monotonic counter (`0x01500001` / `0x01500003`) without being able to clear the lockout.
- FE **anti-replay floor** `0x01500006` (`H(submask_A_FE)`): only the passphrase-holder can advance/lower it, so it cannot be reset to enable offline OTP replay without the FE passphrase. `ownerread` stays open (the offline gate only reads the floor; every write happens with the KEK present — enrollment or a successful mount; the write lazily re-defines to migrate the auth after a passphrase change).

### Owner-auth NV (FE timed lockout)

`0x01500005` (lockout expiry) is a plain owner-auth `u64` NV — **no PolicyPCR, no per-bank copy**. On the 3rd FE failure it stores `TPM_Clock_now + 10 min` (ms); the TPM Clock is monotonic and rollback-proof, so the timer is trustworthy even offline. The FE auto-unlocks once the window elapses (admin `security fe unlock-pw-retry` also clears it). It survives an OTA bank switch unchanged (not PCR-bound) and is cleared only by `clear_tpm.sh` (factory).

The FE **anti-replay floor** (`0x01500006`) and the offline-gate behaviour (current-slot ±1 match, monotonic floor, advance-on-full-unlock — blocks old-code replay + system-clock rollback) are described under [PolicyAuthValue](#policyauthvalue-red-only). Both `0x01500005/06` survive an OTA bank switch in place (not PCR-bound).

> **null owner-auth caveat:** with the current default (TPM owner hierarchy = null-auth), a runtime-root attacker can `undefine`+`redefine` any NV regardless of its write policy — so PolicyAuthValue/ownerwrite distinctions only bite once a TPM owner-auth is set. Today the real barrier against a runtime-root attacker is the FE passphrase (never stored, ≥15 chars), the FDE measured-boot gate, and the day-data HMAC; the NV policies are defence-in-depth + future-proofing for an owner-auth deployment.

## OTA reseal

`pcr-predict-reseal.sh --reseal-extras` re-seals every **PCR-sealed** per-bank persistent object from the current bank to the target bank under the target bank's **predicted** PCRs: the rootfs key (primary `--seal` target) plus the extras overlay (required), VPN-PIN, PSK, PPK, data submask_B, the **FE day-data MAC key** (`reseal_one "mfa-daymac"`), and the **data + FE recovery hashes** (`reseal_one "data-recovery"` / `"fe-recovery"`). The reseal preserves the secret's *value*, so the day-data HMAC and the recovery hashes stay valid after the switch. Red-only secrets soft-skip on grey / before provisioning where the source handle is absent.

The FE retry / lockout / anti-replay **NV indices** (`0x01500003`–`0x01500006`) are owner-auth and **not** PCR-bound, so they need **no** reseal — they carry over the OTA bank switch in place. The TPM Clock backing the lockout is likewise bank-independent.

## Notes

- **FE OTP 2FA (RSA SecurID)** is implemented on this branch. The inner-FE encryption KEK is `PBKDF2(PIN2, plaintext FE salt at /data/.securefs.kdfsalt)` with **no TPM seal of its own** — device + measured-boot binding is inherited from the outer FDE that encrypts `/data` (dual-DAR). The handles `0x81020030/31` (formerly the FE OTP seed, then the dropped FE submask_B) now hold the **offline day-data integrity HMAC key**. FE FIA_AFL (3 attempts / 10-min timed lockout) + offline anti-replay live in NVs `0x01500003`–`0x01500006`.
- **fe-otp seed (`0x81020022/23`)** was removed earlier and is **not** reallocated; the FE day-MAC key reuses `0x81020030/31`, not this range.
- **Grey data-FDE submask_A** is described in the dual-DAR design as a random, TPM-sealed value, but the current code allocates **no persistent handle** for it — data FDE is operator-passphrase (red) today (the `0x8102004x` range is free).
- `0x81C2C92E…` in the TF-A measured-boot patch is **not** a TPM handle — it is a SHA-384/512 round constant in the software hash implementation.
