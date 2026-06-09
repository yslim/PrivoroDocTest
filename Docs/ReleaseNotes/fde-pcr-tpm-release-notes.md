# Release Notes — fde-pcr-tpm

**Date:** May 22, 2026
**Base:** upstream/develop
**Branch:** `fde-pcr-tpm` (shiba-meta-secure-boot, shiba-yocto-scripts)

---

## 1. Overview

This release adds TPM-anchored measured boot and TPM-sealed Full Disk Encryption (FDE) to the Akita/Shiba STM32MP15 platform.

The boot chain now measures each stage into the TPM (ST33KTPM2I, SHA-384), and the rootfs / overlay encryption keys are released by the TPM only when the device identity and the measured boot state both match the values captured at provisioning time. Two device variants are supported:

- **grey** — unattended unlock; the key material is sealed entirely to the TPM (device identity + PCR state). No operator interaction at boot.
- **red** — passphrase-gated unlock; the operator passphrase is a required key factor and is never stored on the device.

The encryption key for each protected volume is split into two 64-byte sub-masks:

```
KEK = submask_A  XOR  submask_B            (512-bit AES-256-XTS key)
```

| Sub-mask | grey variant | red variant |
|----------|--------------|-------------|
| `submask_A` | `PBKDF2-HMAC-SHA384(passphrase, salt, 10000)`, derived once at enrollment then **TPM-sealed** | same PBKDF2 derivation, **re-derived from the passphrase at every boot, never stored** |
| `submask_B` | 64 random bytes, **TPM-sealed** per-bank, regenerated on every OTA | same |

This split means a grey device unlocks hands-free, while a red device additionally requires the operator passphrase — and on red the TPM never holds enough material to rebuild the key on its own.

---

## 2. Provisioning Procedure (FDE + TPM PCR Policy)

FDE key material and its TPM PCR policy are **not** present on a freshly flashed device — they are established by enrolling the passphrase and then installing a target variant over OTA. Bring-up follows three steps:

1. **Flash the base variant (USB / DFU).**
   Program the `base` image with STM32CubeProgrammer over USB / DFU. The device boots with the rootfs and overlay **unencrypted** and the TPM **not yet provisioned** with FDE key material — this is the plaintext initialization state.

2. **Enroll the FDE passphrase — `security fde create-passphrase`.**
   From the SCLI, run `security fde create-passphrase`. This derives `submask_A` (`PBKDF2-HMAC-SHA384`, 10000 iterations) from the operator passphrase and caches its hash at `/run/tpm/user_passwd.hash`. This step is **mandatory before OTA**: `update-sw.sh` aborts at its FDE precondition check if the cache is absent.

3. **OTA-update to the desired variant (grey / red).**
   Run swupdate with the target variant image. The update LUKS-formats the rootfs and overlay with `KEK = submask_A XOR submask_B`, generates `submask_B` (64 random bytes), and seals it per-bank — together with `submask_A` on grey — under the device-id + PCR(1,4,5,8) compound policy (§4.1, §4.2). The `submask_A` model (TPM-sealed on grey; passphrase-only on red) follows the **target** variant parsed from the SWU machine name.

After step 3 the device boots the selected variant with FDE active and the keys bound to the measured boot state.

---

## 3. shiba-yocto-scripts

U-Boot device-tree support for the SPI-attached TPM.

| Commit | Description |
|--------|-------------|
| U-Boot DTS: add SPI5 TPM device node and fix ST33KTPM2I pinctrl | Add the SPI5 TPM device node and pinctrl so U-Boot can talk to the TPM. Correct the chip-select pin (PF3 → PF6), SPI clock speed, and pin multiplexing for the ST33KTPM2I part. |

**Impact:**
- U-Boot can now access the TPM over SPI5, enabling firmware-stage PCR measurements.
- Required by the measured-boot changes in `shiba-meta-secure-boot` (§4.1).

---

## 4. shiba-meta-secure-boot

### 4.1 TPM Measured Boot — PCR 1/4/5/8 (SHA-384)

| Commit | Description |
|--------|-------------|
| tpm: measured boot — TF-A PCR#1 FIP, U-Boot FIT PCR#4/5/8, SHA-384 FIT hash | TF-A measures the FIP into PCR#1; U-Boot measures the kernel FIT image (kernel + DTB + initramfs) into PCR#4/5/8. The FIT image hash algorithm is set to SHA-384 to match the TPM PCR bank. |

**PCR allocation (`sha384:1,4,5,8`):**

| PCR | Measured by | Content |
|-----|-------------|---------|
| 1 | TF-A | FIP (FIP-A / FIP-B) |
| 4 | U-Boot | FIT image — boot stage |
| 5 | U-Boot | FIT image — configuration |
| 8 | U-Boot | FIT image — kernel + DTB + initramfs |

The sealed FDE key material is bound to these PCRs, so any unauthorized change to the firmware or kernel image changes the measurements and the TPM refuses to release the key.

### 4.2 Two-Factor KEK Library + Per-Variant Policy

| Commit | Description |
|--------|-------------|
| fde: KEK library, per-variant policy, TPM seal/unseal + rotation/aging scripts | Central FDE KEK library (`fde-kek-lib.sh`) implementing the `submask_A XOR submask_B` key model, TPM seal/unseal with a compound policy, and the periodic KEK-rotation and passphrase-aging counters. Per-variant behavior is driven by `/usr/lib/shiba/fde-policy.conf` (grey vs. red). |

**Compound TPM policy** protecting every sealed object:

```
PolicyNV(device-id NV index)  AND  PolicyPCR(sha384:1,4,5,8)
```

- The device-id NV index holds a hash of the platform serial (`STM32MP15 | SERIAL | <hex>`), binding the key to this physical device.
- The PCR term binds the key to the measured boot state from §4.1.
- Sessions are EK-salted to defend against SPI bus sniffing.

**Rotation / aging counters** use TPM monotonic NV counters (rollback-resistant). The effective count is `counter − baseline`; a rotation is triggered when `effective ≥ max`:

- **KEK rotation** — periodically regenerates `submask_B` and re-seals against current PCRs.
- **Passphrase aging** — forces an operator passphrase change after a configurable number of boots.

### 4.3 FDE Initramfs + Per-Variant Image Installs

| Commit | Description |
|--------|-------------|
| fde: initramfs unlock/rotate/overlay/reencrypt modules; per-variant image installs | Initramfs modules that unseal the KEK and unlock the rootfs at boot, handle pending KEK rotation, format/unlock the writable overlay, and perform DEK re-encryption when requested. Image recipes install the correct module set per variant (grey vs. red). |

**Boot-time flow:**
1. Read `boot_bank` from `/proc/cmdline` to select the active A/B bank handles.
2. Unseal `submask_B` (grey: also `submask_A`; red: derive `submask_A` from the passphrase prompt).
3. Reconstruct `KEK = submask_A XOR submask_B` and unlock the LUKS rootfs.
4. Apply any pending KEK rotation / passphrase-age action.
5. Unlock or format the writable overlay.

### 4.4 SCLI `security fde` Command Tree

| Commit | Description |
|--------|-------------|
| scli: add 'security fde' command tree (create/change-passphrase, rotation, luks-erase/reencrypt) | New SCLI subtree to manage FDE: enroll/rotate the passphrase, view and tune the KEK-rotation and passphrase-rotation intervals, cryptographically erase keyslots, and re-encrypt (rotate the DEK / master key). |

**CLI Commands:**

| Command | Description |
|---------|-------------|
| `security fde create-passphrase` | Enroll the initial FDE passphrase |
| `security fde change-passphrase` | Rotate the FDE passphrase (requires the current passphrase) |
| `security fde kek-rotation show status` | Display the KEK rotation interval and effective boot count |
| `security fde kek-rotation set interval <2..1000>` | Set the KEK rotation interval (boots between rotations) |
| `security fde passphrase-rotation show status` | Display the passphrase rotation interval and effective boot count |
| `security fde passphrase-rotation set interval <2..10000>` | Set the passphrase rotation interval (boots between forced changes) |
| `security fde luks-erase` | Destroy FDE keyslots — cryptographic erase, **IRREVERSIBLE** |
| `security fde luks-reencrypt` | Rotate the DEK (master key) of the rootfs and overlay |

### 4.5 gocryptfs — `/securefs` (red variant only)

| Commit | Description |
|--------|-------------|
| gocryptfs: red-only /securefs (TPM-XOR KEK) | Mount an encrypted `/securefs` (gocryptfs) on the red variant only, keyed by the same TPM-XOR KEK model. |

**Impact:** the red variant gains an additional TPM-sealed encrypted store at `/securefs`; the grey variant is unaffected.

### 4.6 OTA — Per-Bank Re-Seal + Target-Variant Provisioning

| Commit | Description |
|--------|-------------|
| ota: per-bank submask_B reseal + target-variant submask_A provisioning | During OTA, regenerate and re-seal `submask_B` for the inactive A/B bank against the predicted post-update PCR values, and provision `submask_A` according to the **target image variant** (parsed from the SWU machine name), not the running variant. On a red target, any stale sealed `submask_A` handle is evicted. |

**Impact:**
- Fixes a kernel panic on red→grey OTA caused by provisioning `submask_A` for the running variant instead of the target.
- A red OTA target never carries a TPM-sealed `submask_A` (the passphrase remains a mandatory key factor).

### 4.7 VPN PKCS#11 PIN TPM-Sealing

| Commit | Description |
|--------|-------------|
| vpn: PKCS#11 PIN TPM-sealing (compound policy) + pkcs11 helpers | Seal the VPN PKCS#11 token PIN with the TPM under the same device-id + PCR compound policy, plus supporting PKCS#11 helper scripts. The VPN client retrieves the PIN from the TPM at runtime rather than storing it in the clear. |

---

## 5. Migration / Provisioning Notes

- **TPM hardware prerequisite:** the U-Boot SPI5 TPM device-tree node from `shiba-yocto-scripts` (§3) must be present, or firmware-stage PCR measurements will not be taken and FDE unlock will fail.
- **Variant selection** is driven by `/usr/lib/shiba/fde-policy.conf` (installed per variant). grey = unattended TPM unlock; red = passphrase-gated.
- **First boot / enrollment:** the FDE passphrase must be enrolled (`security fde create-passphrase`) before OTA, otherwise the update aborts at the FDE precondition check. See §2 for the full bring-up sequence.
- **OTA across variants:** grey↔grey, red↔red, and base→grey/red are supported. The `submask_A` provisioning model follows the **target** image variant.
