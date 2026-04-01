# skb_drop_counter Kernel Module

Out-of-tree kernel module that counts SKB (socket buffer) drop events per reason.
Hooks into the kernel `kfree_skb` tracepoint and increments atomic counters for each drop reason, exposing statistics via debugfs.

---

## How It Works

### 1. Tracepoint Probe

```
kfree_skb tracepoint fires
        |
        v
probe_kfree_skb(skb, location, reason)
        |
        +-- validate reason range (NOT_SPECIFIED ~ MAX)
        +-- NOT_SPECIFIED + excluded function -> skip (normal free)
        +-- NETFILTER_DROP -> skip (already logged by iptables)
        |
        v
atomic_long_inc(&drop_counts[reason])     <- simple counter (always)
detail_record(location, reason)           <- detail counter (always)
```

- Registers `probe_kfree_skb()` on the `kfree_skb` tracepoint
- Uses the `location` argument (caller address) to filter out normal SKB frees from excluded functions when the reason is NOT_SPECIFIED
- Skips `NETFILTER_DROP` since iptables LOG target handles those separately
- Both simple and detail data are collected simultaneously; view mode only changes the output format

### 2. Timer-based Accumulation

```
[periodic timer, default 1s]
        |
        v
for each reason:
   delta = atomic_long_xchg(&drop_counts[i], 0)   <- atomically swap live counter to 0
   cumulative[i] += delta                           <- running total
        |
        v
mod_timer(+interval_ms)                             <- re-arm timer
```

- `atomic_long_xchg` guarantees zero count loss between snapshots
- `cumulative[]` holds the total since module load (or last clear)
- Uses `unsigned long` counters (wraps at 4G on 32-bit ARM)

### 3. Detail Table

```
struct detail_entry {
    unsigned long location;    <- caller address (kfree_skb location)
    unsigned short reason;     <- drop reason enum
    atomic_long_t count;       <- per (location, reason) counter
};

detail_table[256]              <- fixed-size, max 256 unique pairs
```

- Hot path (existing entry): lock-free linear scan + atomic increment
- Cold path (new entry): spinlock-protected insertion
- At display time: `sprint_symbol()` resolves address to function name
- Output sorted by count descending

### 4. Excluded Function Filtering

- Resolves address ranges of functions specified in `exclude_func` using kprobe + `sprint_symbol()`
- Drops with reason `NOT_SPECIFIED` from within those address ranges are excluded from counting
- Excluded functions are resolved BEFORE probe registration to avoid init noise

Default excluded functions:

| Function | Reason |
|----------|--------|
| `r8152_tx_agg_fill` | USB NIC normal TX aggregation free |
| `unix_stream_connect` | Unix domain socket connection (normal skb free) |
| `do_one_broadcast` | Netlink broadcast to absent listeners |

---

## File List

| File | Description |
|------|-------------|
| `recipes-kernel/skb-drop-counter/skb-drop-counter_1.0.bb` | Yocto recipe (LICENSE: CLOSED, inherits: module) |
| `recipes-kernel/skb-drop-counter/files/skb_drop_counter.c` | Kernel module source |
| `recipes-kernel/skb-drop-counter/files/Makefile` | Out-of-tree module build |
| `recipes-core/images-weston/st-image-weston.bbappend` | Includes module in image (`IMAGE_INSTALL:append`) |

---

## Module Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interval_ms` | `1000` | Accumulation period in ms. Can be changed at runtime via sysfs |
| `exclude_func` | `r8152_tx_agg_fill,unix_stream_connect,do_one_broadcast` | Functions to exclude from NOT_SPECIFIED counting (comma-separated, max 8) |

---

## Usage

```bash
# Load (default: 1s interval, simple mode)
modprobe skb_drop_counter

# Load with custom parameters
modprobe skb_drop_counter interval_ms=3000 exclude_func="r8152_tx_agg_fill,unix_stream_connect"

# View drop statistics (simple mode, default)
cat /sys/kernel/debug/skb_drop_counter
# Output:
#   NOT_SPECIFIED                            28
#   IP_INHDR                                 1
#   UNHANDLED_PROTO                          3

# Switch to detail mode (location + reason)
echo detail > /sys/kernel/debug/skb_drop_counter
cat /sys/kernel/debug/skb_drop_counter
# Output:
#   LOCATION                                                REASON                    COUNT
#   --------                                                ------                    -----
#   __netif_receive_skb_core.constprop.0+0x1a0/0x1118       UNHANDLED_PROTO           3
#   ip_rcv+0x48/0x1a0                                       IP_INHDR                  1

# Switch back to simple mode
echo simple > /sys/kernel/debug/skb_drop_counter

# Clear all counters (both simple and detail)
echo clear > /sys/kernel/debug/skb_drop_counter

# Continuous monitoring (1s interval)
while true; do cat /sys/kernel/debug/skb_drop_counter; echo "----------"; sleep 1; done

# View current interval_ms
cat /sys/module/skb_drop_counter/parameters/interval_ms

# Change interval_ms at runtime (e.g. 5 seconds)
echo 5000 > /sys/module/skb_drop_counter/parameters/interval_ms

# Unload
rmmod skb_drop_counter
```

---

## Commands Summary

| Command | Description |
|---------|-------------|
| `echo simple` | Switch to simple view (per-reason cumulative, default) |
| `echo detail` | Switch to detail view (per location+reason, sorted by count) |
| `echo clear` | Clear all counters (simple + detail) |

Note: `simple` and `detail` only change the display format. Both datasets are always collected simultaneously, so switching between views does not lose data.
