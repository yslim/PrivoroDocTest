# PR Title
Set DDR size to 1024MB for 1GB DRAM support

# PR Body

## Summary
- Update machine configuration to reflect 1GB physical DRAM on target hardware

## Changes
| File | Description |
|------|-------------|
| Machine config | DDR size set to 1024MB |

## Test Plan
- [ ] U-Boot reports correct DRAM size (1024MB)
- [ ] Kernel memory info matches expected available memory
- [ ] No regression on existing boards
