#!/bin/bash
#
# Firewall move unit test script
# Usage: scp to device, then run: bash test-firewall-move.sh
#

export SCLI_ONESHOT=1

PASS=0
FAIL=0
SCLI="scli"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_test() {
    echo -e "\n${YELLOW}=== TEST: $1 ===${NC}"
}

log_pass() {
    echo -e "${GREEN}  PASS: $1${NC}"
    PASS=$((PASS + 1))
}

log_fail() {
    echo -e "${RED}  FAIL: $1${NC}"
    FAIL=$((FAIL + 1))
}

# Check if show output contains expected rule order
# Usage: check_order "description" "show_output" "expected_name1" "expected_name2" ...
check_order() {
    local desc="$1"
    local output="$2"
    shift 2

    local prev_pos=0
    local ok=true
    for name in "$@"; do
        local pos
        pos=$(echo "$output" | grep -n "$name" | head -1 | cut -d: -f1)
        if [ -z "$pos" ]; then
            log_fail "$desc — '$name' not found in output"
            ok=false
            break
        fi
        if [ "$pos" -le "$prev_pos" ]; then
            log_fail "$desc — '$name' not in expected order"
            ok=false
            break
        fi
        prev_pos=$pos
    done
    if $ok; then
        log_pass "$desc"
    fi
}

# Check command succeeds
run_ok() {
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        log_pass "$desc"
    else
        log_fail "$desc"
    fi
}

# Check command fails (scli prints "Error:" but exits 0, so check output text)
run_fail() {
    local desc="$1"
    shift
    local out
    out=$("$@" 2>&1)
    if echo "$out" | grep -qi "error"; then
        log_pass "$desc"
    else
        log_fail "$desc (expected failure but succeeded)"
    fi
}

cleanup() {
    $SCLI firewall reset > /dev/null 2>&1 || true
}

# =========================================================================
# Clean start
# =========================================================================
cleanup

# =========================================================================
# TEST 1: access-policy move v4
# =========================================================================
log_test "access-policy move v4"

$SCLI firewall access-policy add inside accept ap-v4-A 10.0.0.0/24 192.168.1.0/24
$SCLI firewall access-policy add inside drop ap-v4-B 172.16.0.0/16 192.168.1.0/24
$SCLI firewall access-policy add inside accept ap-v4-C 10.10.0.0/16 192.168.2.0/24

# Verify initial order
output=$($SCLI firewall show access-policy inside 2>&1)
check_order "initial order A,B,C" "$output" "ap-v4-A" "ap-v4-B" "ap-v4-C"

# Move 3 to 1
run_ok "move v4 3 to 1" $SCLI firewall access-policy move inside v4 3 1

# Verify new order: C, A, B
output=$($SCLI firewall show access-policy inside 2>&1)
check_order "after move: C,A,B" "$output" "ap-v4-C" "ap-v4-A" "ap-v4-B"

# Move 2 to 3
run_ok "move v4 2 to 3" $SCLI firewall access-policy move inside v4 2 3

# Verify new order: C, B, A
output=$($SCLI firewall show access-policy inside 2>&1)
check_order "after move: C,B,A" "$output" "ap-v4-C" "ap-v4-B" "ap-v4-A"

# Move same position (no-op)
run_ok "move v4 same position (no-op)" $SCLI firewall access-policy move inside v4 2 2

cleanup

# =========================================================================
# TEST 2: access-policy move v6
# =========================================================================
log_test "access-policy move v6"

$SCLI firewall access-policy add inside accept ap-v6-A 2001:db8:1::/48 fd00:1::/64
$SCLI firewall access-policy add inside drop ap-v6-B 2001:db8:2::/48 fd00:2::/64
$SCLI firewall access-policy add inside accept ap-v6-C 2001:db8:3::/48 fd00:3::/64

# Verify initial order
output=$($SCLI firewall show access-policy inside 2>&1)
check_order "initial v6 order A,B,C" "$output" "ap-v6-A" "ap-v6-B" "ap-v6-C"

# Move 3 to 1
run_ok "move v6 3 to 1" $SCLI firewall access-policy move inside v6 3 1

# Verify new order: C, A, B
output=$($SCLI firewall show access-policy inside 2>&1)
check_order "after v6 move: C,A,B" "$output" "ap-v6-C" "ap-v6-A" "ap-v6-B"

cleanup

# =========================================================================
# TEST 3: access-policy move v4+v6 mixed
# =========================================================================
log_test "access-policy move v4+v6 mixed"

$SCLI firewall access-policy add inside accept mix-v4-A 10.0.0.0/24 192.168.1.0/24
$SCLI firewall access-policy add inside drop mix-v4-B 172.16.0.0/16 10.0.0.0/8
$SCLI firewall access-policy add inside accept mix-v6-A 2001:db8::/32 fd00::/64
$SCLI firewall access-policy add inside drop mix-v6-B fc00::/7 fd00::/64

# Verify v4 and v6 sections exist
output=$($SCLI firewall show access-policy inside 2>&1)
check_order "v4 section: mix-v4-A, mix-v4-B" "$output" "mix-v4-A" "mix-v4-B"

# Move v4 only — v6 should be unaffected
run_ok "move v4 2 to 1" $SCLI firewall access-policy move inside v4 2 1

output=$($SCLI firewall show access-policy inside 2>&1)
check_order "v4 after move: mix-v4-B, mix-v4-A" "$output" "mix-v4-B" "mix-v4-A"

# Move v6 only — v4 should be unaffected
run_ok "move v6 2 to 1" $SCLI firewall access-policy move inside v6 2 1

output=$($SCLI firewall show access-policy inside 2>&1)
check_order "v6 after move: mix-v6-B, mix-v6-A" "$output" "mix-v6-B" "mix-v6-A"

# v4 move on v6-only rules should fail (v4 has no rules)
cleanup
$SCLI firewall access-policy add inside accept v6only-A 2001:db8:1::/48 fd00:1::/64
$SCLI firewall access-policy add inside accept v6only-B 2001:db8:2::/48 fd00:2::/64
run_fail "move v4 on empty v4 (no v4 rules)" $SCLI firewall access-policy move inside v4 1 2

cleanup

# =========================================================================
# TEST 4: access-policy cross-stack rule-name uniqueness
# =========================================================================
log_test "access-policy cross-stack rule-name uniqueness"

$SCLI firewall access-policy add inside accept dup-test 10.0.0.0/24 192.168.1.0/24
run_fail "reject duplicate name in v6" $SCLI firewall access-policy add inside accept dup-test 2001:db8::/32 fd00::/64

cleanup

# =========================================================================
# TEST 5: access-policy move out of range
# =========================================================================
log_test "access-policy move out of range"

$SCLI firewall access-policy add inside accept range-A 10.0.0.0/24 192.168.1.0/24
$SCLI firewall access-policy add inside drop range-B 172.16.0.0/16 192.168.1.0/24

run_fail "move from=0 (out of range)" $SCLI firewall access-policy move inside v4 0 1
run_fail "move from=3 (out of range)" $SCLI firewall access-policy move inside v4 3 1
run_fail "move to=0 (out of range)" $SCLI firewall access-policy move inside v4 1 0
run_fail "move to=3 (out of range)" $SCLI firewall access-policy move inside v4 1 3

cleanup

# =========================================================================
# TEST 6: access-policy outside
# =========================================================================
log_test "access-policy move outside"

$SCLI firewall access-policy add outside accept out-A 10.0.0.0/24 192.168.1.0/24
$SCLI firewall access-policy add outside drop out-B 172.16.0.0/16 192.168.1.0/24

run_ok "move outside v4 2 to 1" $SCLI firewall access-policy move outside v4 2 1

output=$($SCLI firewall show access-policy outside 2>&1)
check_order "outside after move: out-B, out-A" "$output" "out-B" "out-A"

cleanup

# =========================================================================
# TEST 7: ICMPv4 move
# =========================================================================
log_test "ICMPv4 move"

$SCLI firewall icmp4 add input accept echo-request outside 0.0.0.0/0 icmp-A
$SCLI firewall icmp4 add input accept echo-reply outside 0.0.0.0/0 icmp-B
$SCLI firewall icmp4 add input drop echo-request outside 10.0.0.0/8 icmp-C

output=$($SCLI firewall show icmp4 input outside 2>&1)
check_order "icmp4 initial: A,B,C" "$output" "icmp-A" "icmp-B" "icmp-C"

run_ok "icmp4 move 3 to 1" $SCLI firewall icmp4 move input outside 3 1

output=$($SCLI firewall show icmp4 input outside 2>&1)
check_order "icmp4 after move: C,A,B" "$output" "icmp-C" "icmp-A" "icmp-B"

cleanup

# =========================================================================
# TEST 8: ICMPv6 move
# =========================================================================
log_test "ICMPv6 move"

$SCLI firewall icmp6 add input accept echo-request outside ::/0 icmp6-A
$SCLI firewall icmp6 add input accept echo-reply outside ::/0 icmp6-B
$SCLI firewall icmp6 add input drop echo-request outside 2001:db8::/32 icmp6-C

output=$($SCLI firewall show icmp6 input outside 2>&1)
check_order "icmp6 initial: A,B,C" "$output" "icmp6-A" "icmp6-B" "icmp6-C"

run_ok "icmp6 move 3 to 1" $SCLI firewall icmp6 move input outside 3 1

output=$($SCLI firewall show icmp6 input outside 2>&1)
check_order "icmp6 after move: C,A,B" "$output" "icmp6-C" "icmp6-A" "icmp6-B"

cleanup

# =========================================================================
# TEST 9: ICMPv4 forward zone move
# =========================================================================
log_test "ICMPv4 move forward/inside"

$SCLI firewall icmp4 add forward accept echo-request inside 10.0.0.0/8 fwd-A
$SCLI firewall icmp4 add forward drop echo-request inside 172.16.0.0/12 fwd-B

run_ok "icmp4 move forward inside 2 to 1" $SCLI firewall icmp4 move forward inside 2 1

output=$($SCLI firewall show icmp4 forward inside 2>&1)
check_order "fwd inside after move: B,A" "$output" "fwd-B" "fwd-A"

cleanup

# =========================================================================
# TEST 10: NAT masquerade move
# =========================================================================
log_test "NAT masquerade move"

$SCLI firewall nat masquerade add nat-A 10.0.0.0/24 0.0.0.0/0
$SCLI firewall nat masquerade add nat-B 172.16.0.0/16 0.0.0.0/0
$SCLI firewall nat masquerade add nat-C 192.168.0.0/16 0.0.0.0/0

output=$($SCLI firewall show nat masquerade 2>&1)
check_order "nat masq initial: A,B,C" "$output" "nat-A" "nat-B" "nat-C"

run_ok "nat masq move 3 to 1" $SCLI firewall nat masquerade move 3 1

output=$($SCLI firewall show nat masquerade 2>&1)
check_order "nat masq after move: C,A,B" "$output" "nat-C" "nat-A" "nat-B"

run_ok "nat masq move 2 to 3" $SCLI firewall nat masquerade move 2 3

output=$($SCLI firewall show nat masquerade 2>&1)
check_order "nat masq after move: C,B,A" "$output" "nat-C" "nat-B" "nat-A"

cleanup

# =========================================================================
# TEST 11: NAT snat move
# =========================================================================
log_test "NAT snat move"

$SCLI firewall nat snat add snat-A 10.0.0.0/24 0.0.0.0/0 -p tcp --to-source 192.168.1.1:5000
$SCLI firewall nat snat add snat-B 172.16.0.0/16 0.0.0.0/0 -p tcp --to-source 192.168.1.2:5001

output=$($SCLI firewall show nat snat 2>&1)
check_order "nat snat initial: A,B" "$output" "snat-A" "snat-B"

run_ok "nat snat move 2 to 1" $SCLI firewall nat snat move 2 1

output=$($SCLI firewall show nat snat 2>&1)
check_order "nat snat after move: B,A" "$output" "snat-B" "snat-A"

cleanup

# =========================================================================
# TEST 12: NAT dnat move
# =========================================================================
log_test "NAT dnat move"

$SCLI firewall nat dnat add dnat-A 0.0.0.0/0 192.168.1.0/24 -p tcp --dport 80 --to-destination 10.0.0.1:8080
$SCLI firewall nat dnat add dnat-B 0.0.0.0/0 192.168.1.0/24 -p tcp --dport 443 --to-destination 10.0.0.1:8443

output=$($SCLI firewall show nat dnat 2>&1)
check_order "nat dnat initial: A,B" "$output" "dnat-A" "dnat-B"

run_ok "nat dnat move 2 to 1" $SCLI firewall nat dnat move 2 1

output=$($SCLI firewall show nat dnat 2>&1)
check_order "nat dnat after move: B,A" "$output" "dnat-B" "dnat-A"

cleanup

# =========================================================================
# TEST 13: save and verify in kernel (access-policy)
# =========================================================================
log_test "save and verify in kernel"

$SCLI firewall access-policy add inside accept kern-A 10.0.0.0/24 192.168.1.0/24
$SCLI firewall access-policy add inside drop kern-B 172.16.0.0/16 192.168.1.0/24
$SCLI firewall access-policy add inside accept kern-C 10.10.0.0/16 192.168.2.0/24

$SCLI firewall access-policy move inside v4 3 1

# Save with auto-confirm
echo "y" | $SCLI firewall save

# Verify kernel rule order
kernel_output=$(sudo iptables -L AKITA_FW_INSIDE_FILTER -v -n 2>&1)
check_order "kernel v4 order: kern-C, kern-A, kern-B" "$kernel_output" "kern-C" "kern-A" "kern-B"

# Delete and save to clean up
$SCLI firewall access-policy del inside kern-A
$SCLI firewall access-policy del inside kern-B
$SCLI firewall access-policy del inside kern-C
echo "y" | $SCLI firewall save

# =========================================================================
# Summary
# =========================================================================
echo ""
echo "==========================================="
echo -e "  ${GREEN}PASSED: $PASS${NC}"
echo -e "  ${RED}FAILED: $FAIL${NC}"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
