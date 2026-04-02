# PR Title
Fix DDR config for 1GB hardware and reserve OP-TEE secure region

# PR Body

## Summary
- Fix DRAM size to match actual 1GB MT52L256M32D1PF hardware
- Reserve OP-TEE secure DDR region in device trees to prevent TZC panic at boot

## Changes
| File | Description |
|------|-------------|
| `mx/shiba-a7-ddr/optee-os/shiba-peripheral.dtsi` | Reserve OP-TEE secure memory region |
| DDR configuration files | Correct memory size to 1GB |

## Test Plan
- [ ] Boot on 1GB DRAM board — no TZC panic
- [ ] OP-TEE starts normally in secure world
- [ ] Linux sees correct available memory (~1GB minus reserved regions)
- [ ] No regression on existing boards
