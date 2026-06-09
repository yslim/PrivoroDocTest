# TPM Resource Map — Handles, NV Indices, Policies

Authoritative inventory of every TPM2 resource the secure-boot stack uses: persistent handles, NV indices, PCR allocation, and the policies bound to sealed secrets. Reflects the current branch.

## Conventions

- **Hash / curve:** `sha384` + `ecc384`, auto-detected per chip (`tpm-algo-lib.sh: detect_tpm_algo`); falls back to `sha256` + `ecc` on a SHA-256-only TPM (e.g. SLB9670). Values below assume SHA-384.
- **A/B banks:** every per-slot secret is sealed twice, once per firmware bank, because each bank's predicted PCRs differ. Even handle = Bank 0, odd handle = Bank 1.
- **Sealing policy:** every sealed object is bound to the compound policy `PolicyNV(device) AND PolicyPCR(sha384:1,4,5,8)` — see [Policies](#policies).

## Persistent handles (`0x81xxxxxx`)

| Bank 0 / Bank 1             | Holds                           | Policy | Scope |
|-----------------------------|---------------------------------|--------|-------|
| `0x81000001`                | TPM primary key (owner, ecc384) | —      | all   |
| `0x81010001` / `0x81010002` | VPN PKCS#11 PIN                 | NV+PCR | VPN   |
| `0x81010101` / `0x81010102` | IPsec PSK                       | NV+PCR | VPN   |
| `0x81010201` / `0x81010202` | IPsec PPK (post-quantum)        | NV+PCR | VPN   |
| `0x81020000` / `0x81020001` | rootfs LUKS key                 | NV+PCR | all   |
| `0x81020010` / `0x81020011` | overlay LUKS key                | NV+PCR | all   |
| `0x81020020` / `0x81020021` | data FDE submask_B              | NV+PCR | red   |
| `0x81020030` / `0x81020031` | FE gocryptfs submask_B          | NV+PCR | red   |

Defined in: `tpm-seal-secret.sh` / `tpm-unseal-secret.sh` (PSK/PPK), `vpn-pkcs11-pin.sh` (VPN PIN), the initramfs unlock scripts (rootfs/overlay), `gocryptfs-init.env` (FE submask_B), `fde-data-provision.sh` (data submask_B), and `pcr-predict-reseal.sh` (reseal map).

*Scope:* `all` = every device; `red` = red variant only; `VPN` = present once IPsec/VPN is provisioned.

## NV indices (`0x01xxxxxx`) — owner hierarchy

| Index        | Variable                | Purpose                               | Attributes / auth             |
|--------------|-------------------------|---------------------------------------|-------------------------------|
| `0x01500000` | `FDE_NV_INDEX`          | device-bind operand (PolicyNV anchor) | ownerread / ownerwrite        |
| `0x01500001` | `FDE_PW_COUNTER_NV`     | pw_retry monotonic counter (FIA_AFL)  | `nt=counter`                  |
| `0x01500002` | `FDE_PW_BASELINE_NV`    | pw_retry baseline                     | PolicyAuthValue(H(submask_A)) |
| `0x01500010` | `FDE_ROT_COUNTER_NV`    | KEK-rotation counter                  | `nt=counter`                  |
| `0x01500011` | `FDE_ROT_BASELINE_NV`   | KEK-rotation baseline                 | ownerwrite                    |
| `0x01500012` | `FDE_ROT_MAX_NV`        | rotation interval (0 ⇒ default 5)     | ownerwrite                    |
| `0x01500013` | `FDE_PWAGE_COUNTER_NV`  | passphrase-age counter                | `nt=counter`                  |
| `0x01500014` | `FDE_PWAGE_BASELINE_NV` | passphrase-age baseline               | ownerwrite                    |
| `0x01500015` | `FDE_PWAGE_MAX_NV`      | passphrase-age interval (default 100) | ownerwrite                    |

`0x01500001`–`0x01500015` govern the **data-partition FDE** (red) retry / rotation / aging clocks. Counters are monotonic (`nt=counter`); the displayed value is `effective = counter − baseline`. Defined in `fde-kek-lib.sh`.

## PCR allocation (measured boot, SHA-384)

| PCR  | Extended by | Measures                    |
|------|-------------|-----------------------------|
| `#1` | TF-A BL2    | FIP — all BL2-loaded images |
| `#4` | U-Boot      | kernel                      |
| `#5` | U-Boot      | DTB                         |
| `#8` | U-Boot      | initramfs                   |

Policy PCR list: **`sha384:1,4,5,8`** (`tpm-algo-lib.sh`). TF-A computes the SHA-384 digest in software (the STM32 HASH block is SHA-256 only) and extends PCR#1 directly from BL2 — `stm32mp1_event_log_metadata` maps every BL2-loaded image to `PCR_1`. U-Boot extends #4/#5/#8 from the FIT-image hook in `boot/image-fit.c`.

## Policies

### Compound sealing policy (all sealed secrets)

Built as a trial policy at seal time, enforced at unseal:

1. `tpm2_policynv` — compare NV `0x01500000` (device-bind operand, derived from the device serial via `make_nv_operand`) with `eq`. Binds the secret to **this device**.
2. `tpm2_policypcr` — `sha384:1,4,5,8`. Binds the secret to the **measured-boot state**.

Sealed object attributes: `fixedtpm | fixedparent | adminwithpolicy`, created under the **owner-hierarchy** ecc384 primary using **encrypted + HMAC sessions**. Unsealing requires satisfying both policy terms — a wrong device serial or any PCR mismatch fails the unseal.

### PolicyAuthValue (FIA_AFL, red only)

The pw_retry **baseline** NV (`0x01500002`) carries `authValue = H(submask_A)`. Only a caller that derives the correct `submask_A` (from the correct passphrase) can reset the retry counter, so failed attempts increment the monotonic counter (`0x01500001`) without being able to clear it.

## OTA reseal

`pcr-predict-reseal.sh --reseal-extras` re-seals every per-bank secret from the current bank to the target bank under the target bank's **predicted** PCRs: the rootfs key (primary `--seal` target) plus the extras overlay, VPN-PIN, PSK, PPK, FE gocryptfs submask_B, and data submask_B. Red-only secrets soft-skip on grey where the source handle is absent.

## Notes

- **fe-otp seed (`0x81020022/23`)** was removed on this branch (FE OTP 2FA dropped; to be redesigned server-side). It is no longer allocated or resealed.
- **Grey data-FDE submask_A** is described in the dual-DAR design as a random, TPM-sealed value, but the current code allocates **no persistent handle** for it — data FDE is operator-passphrase (red) today. No persistent handle is reserved in code for it (the `0x8102004x` range is now free).
- `0x81C2C92E…` in the TF-A measured-boot patch is **not** a TPM handle — it is a SHA-384/512 round constant in the software hash implementation.
