#!/usr/bin/env bash
# =============================================================================
# Firewall CLI Integration Test Suite for shiba-scli
#
# Runs on a real Linux device with iptables.
# Single commands use one-shot mode, while live save flows run inside one
# admin session so staging and save stay in the same CLI context.
#
# Usage:
#   bash tests/test_firewall.sh                  # uses 'scli' from $PATH
#   bash tests/test_firewall.sh -v               # verbose (show command + output)
#   bash tests/test_firewall.sh --verbose         # same as -v
#   bash tests/test_firewall.sh --live            # enable save tests (modifies iptables!)
#   bash tests/test_firewall.sh -v --live         # verbose + live
#   SCLI_BIN=/path/to/scli bash tests/test_firewall.sh
#
# Prerequisites:
#   - Linux device with iptables
#   - /etc/iptables_rules/ directory structure (yocto templates applied)
#   - Passwordless sudo (or run as root)
#   - scli binary built and accessible
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Load common test framework
# ---------------------------------------------------------------------------
source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Firewall-specific configuration
# ---------------------------------------------------------------------------
STAGE_ROOT="/tmp/akita-staging/firewall"

cleanup_staging() {
    rm -rf "$STAGE_ROOT" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Live-test helpers (used when --live is passed)
# ---------------------------------------------------------------------------

# assert_iptables_chain_contains <description> <chain> <needle>
#   Runs 'sudo iptables -L <chain> -n' and asserts needle is present.
assert_iptables_chain_contains() {
    local desc="$1" chain="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo iptables -L "$chain" -n 2>&1) || exit_code=$?

    if echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected chain %s to contain: %s\n" "$chain" "$needle"
    fi
    verbose_log "iptables -L $chain -n (grep $needle)" "$output" "$exit_code"
}

# assert_iptables_chain_not_contains <description> <chain> <needle>
assert_iptables_chain_not_contains() {
    local desc="$1" chain="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo iptables -L "$chain" -n 2>&1) || exit_code=$?

    if ! echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected chain %s NOT to contain: %s\n" "$chain" "$needle"
    fi
    verbose_log "iptables -L $chain -n (grep -v $needle)" "$output" "$exit_code"
}

# assert_ip6tables_chain_contains <description> <chain> <needle>
assert_ip6tables_chain_contains() {
    local desc="$1" chain="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo ip6tables -L "$chain" -n 2>&1) || exit_code=$?

    if echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected chain %s (v6) to contain: %s\n" "$chain" "$needle"
    fi
    verbose_log "ip6tables -L $chain -n (grep $needle)" "$output" "$exit_code"
}

# assert_ip6tables_chain_not_contains <description> <chain> <needle>
assert_ip6tables_chain_not_contains() {
    local desc="$1" chain="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo ip6tables -L "$chain" -n 2>&1) || exit_code=$?

    if ! echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected chain %s (v6) NOT to contain: %s\n" "$chain" "$needle"
    fi
    verbose_log "ip6tables -L $chain -n (grep -v $needle)" "$output" "$exit_code"
}

# assert_iptables_nat_chain_contains <description> <chain> <needle>
assert_iptables_nat_chain_contains() {
    local desc="$1" chain="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo iptables -t nat -L "$chain" -n 2>&1) || exit_code=$?

    if echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected nat chain %s to contain: %s\n" "$chain" "$needle"
    fi
    verbose_log "iptables -t nat -L $chain -n (grep $needle)" "$output" "$exit_code"
}

# assert_iptables_nat_chain_not_contains <description> <chain> <needle>
assert_iptables_nat_chain_not_contains() {
    local desc="$1" chain="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo iptables -t nat -L "$chain" -n 2>&1) || exit_code=$?

    if ! echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected nat chain %s NOT to contain: %s\n" "$chain" "$needle"
    fi
    verbose_log "iptables -t nat -L $chain -n (grep -v $needle)" "$output" "$exit_code"
}

# assert_xfrm_contains <description> <needle>
assert_xfrm_contains() {
    local desc="$1" needle="$2"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo ip xfrm policy 2>&1) || exit_code=$?

    if echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected 'ip xfrm policy' to contain: %s\n" "$needle"
    fi
    verbose_log "ip xfrm policy (grep $needle)" "$output" "$exit_code"
}

# assert_xfrm_not_contains <description> <needle>
assert_xfrm_not_contains() {
    local desc="$1" needle="$2"
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(sudo ip xfrm policy 2>&1) || exit_code=$?

    if ! echo "$output" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected 'ip xfrm policy' NOT to contain: %s\n" "$needle"
    fi
    verbose_log "ip xfrm policy (grep -v $needle)" "$output" "$exit_code"
}

# =============================================================================
# TEST SECTIONS
# =============================================================================

# ---------------------------------------------------------------------------
# 1. Show commands (read-only, always safe)
# ---------------------------------------------------------------------------
test_show_commands() {
    section "SHOW COMMANDS (read-only)"

    assert_output_contains "show icmp4 input outside" \
        "Firewall ICMPv4 Rules (input/outside)" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input inside" \
        "Firewall ICMPv4 Rules (input/inside)" \
        firewall show icmp4 input inside

    assert_output_contains "show icmp4 input vti" \
        "Firewall ICMPv4 Rules (input/vti)" \
        firewall show icmp4 input vti

    assert_output_contains "show icmp4 forward outside" \
        "Firewall ICMPv4 Rules (forward/outside)" \
        firewall show icmp4 forward outside

    assert_output_contains "show icmp4 forward inside" \
        "Firewall ICMPv4 Rules (forward/inside)" \
        firewall show icmp4 forward inside

    assert_output_contains "show icmp4 forward vti" \
        "Firewall ICMPv4 Rules (forward/vti)" \
        firewall show icmp4 forward vti

    assert_output_contains "show icmp6 input outside" \
        "Firewall ICMPv6 Rules (input/outside)" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input inside" \
        "Firewall ICMPv6 Rules (input/inside)" \
        firewall show icmp6 input inside

    assert_output_contains "show icmp6 input vti" \
        "Firewall ICMPv6 Rules (input/vti)" \
        firewall show icmp6 input vti

    assert_output_contains "show icmp6 forward outside" \
        "Firewall ICMPv6 Rules (forward/outside)" \
        firewall show icmp6 forward outside

    assert_output_contains "show icmp6 forward inside" \
        "Firewall ICMPv6 Rules (forward/inside)" \
        firewall show icmp6 forward inside

    assert_output_contains "show icmp6 forward vti" \
        "Firewall ICMPv6 Rules (forward/vti)" \
        firewall show icmp6 forward vti

    assert_output_contains "show access-policy inside" \
        "Access Policy Rules (inside)" \
        firewall show access-policy inside

    assert_output_contains "show access-policy outside" \
        "Access Policy Rules (outside)" \
        firewall show access-policy outside

    assert_output_contains "show vpn-policy in deny" \
        "VPN Policy Rules (in/deny)" \
        firewall show vpn-policy in deny

    assert_output_contains "show vpn-policy in bypass" \
        "VPN Policy Rules (in/bypass)" \
        firewall show vpn-policy in bypass

    assert_output_contains "show vpn-policy in allow" \
        "VPN Policy Rules (in/allow)" \
        firewall show vpn-policy in allow

    assert_output_contains "show vpn-policy out deny" \
        "VPN Policy Rules (out/deny)" \
        firewall show vpn-policy out deny

    assert_output_contains "show vpn-policy out bypass" \
        "VPN Policy Rules (out/bypass)" \
        firewall show vpn-policy out bypass

    assert_output_contains "show vpn-policy out allow" \
        "VPN Policy Rules (out/allow)" \
        firewall show vpn-policy out allow

    assert_output_contains "show nat masquerade" \
        "NAT Masquerade Rules" \
        firewall show nat masquerade

    assert_output_contains "show nat snat" \
        "NAT SNAT Rules" \
        firewall show nat snat

    assert_output_contains "show nat dnat" \
        "NAT DNAT Rules" \
        firewall show nat dnat
}

# ---------------------------------------------------------------------------
# 2. ICMPv4 lifecycle
# ---------------------------------------------------------------------------
test_icmp4_lifecycle() {
    section "ICMPv4 RULES LIFECYCLE"
    cleanup_staging

    # --- Add (core types) ---
    assert_success "icmp4 add echo-request outside" \
        'Staged new ICMPv4 rule "test-icmp-out"' \
        firewall icmp4 add input accept echo-request outside 10.0.0.0/8 test-icmp-out

    assert_success "icmp4 add echo-reply inside" \
        'Staged new ICMPv4 rule "test-icmp-in"' \
        firewall icmp4 add input accept echo-reply inside 192.168.0.0/16 test-icmp-in

    assert_success "icmp4 add unreachable vti" \
        'Staged new ICMPv4 rule "test-icmp-vti"' \
        firewall icmp4 add input accept unreachable vti 172.16.0.0/12 test-icmp-vti

    assert_success "icmp4 add any outside" \
        'Staged new ICMPv4 rule "test-icmp-any"' \
        firewall icmp4 add input accept any outside 10.1.0.0/16 test-icmp-any

    assert_success "icmp4 add time-exceeded outside" \
        'Staged new ICMPv4 rule "test-icmp-te"' \
        firewall icmp4 add input accept time-exceeded outside 10.2.0.0/16 test-icmp-te

    # --- Add (extended IPv4 types) ---
    assert_success "icmp4 add timestamp-request outside" \
        'Staged new ICMPv4 rule "test-icmp-ts-req"' \
        firewall icmp4 add input accept timestamp-request outside 10.3.0.0/16 test-icmp-ts-req

    assert_success "icmp4 add timestamp-reply outside" \
        'Staged new ICMPv4 rule "test-icmp-ts-rep"' \
        firewall icmp4 add input accept timestamp-reply outside 10.4.0.0/16 test-icmp-ts-rep

    assert_success "icmp4 add parameter-problem outside" \
        'Staged new ICMPv4 rule "test-icmp-pp"' \
        firewall icmp4 add input accept parameter-problem outside 10.5.0.0/16 test-icmp-pp

    assert_success "icmp4 add source-quench outside" \
        'Staged new ICMPv4 rule "test-icmp-sq"' \
        firewall icmp4 add input accept source-quench outside 10.6.0.0/16 test-icmp-sq

    assert_success "icmp4 add redirect outside" \
        'Staged new ICMPv4 rule "test-icmp-redir"' \
        firewall icmp4 add input accept redirect outside 10.7.0.0/16 test-icmp-redir

    assert_success "icmp4 add router-advertisement outside" \
        'Staged new ICMPv4 rule "test-icmp-ra"' \
        firewall icmp4 add input accept router-advertisement outside 10.8.0.0/16 test-icmp-ra

    assert_success "icmp4 add router-solicitation outside" \
        'Staged new ICMPv4 rule "test-icmp-rs"' \
        firewall icmp4 add input accept router-solicitation outside 10.9.0.0/16 test-icmp-rs

    assert_success "icmp4 add mask-request outside" \
        'Staged new ICMPv4 rule "test-icmp-mreq"' \
        firewall icmp4 add input accept mask-request outside 10.10.0.0/16 test-icmp-mreq

    assert_success "icmp4 add mask-reply outside" \
        'Staged new ICMPv4 rule "test-icmp-mrep"' \
        firewall icmp4 add input accept mask-reply outside 10.11.0.0/16 test-icmp-mrep

    # --- Add (drop action) ---
    assert_success "icmp4 add drop echo-request outside" \
        'Staged new ICMPv4 rule "test-icmp-drop"' \
        firewall icmp4 add input drop echo-request outside 10.12.0.0/16 test-icmp-drop

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show icmp4 input outside -> test-icmp-out" \
        "test-icmp-out" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-any" \
        "test-icmp-any" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-te" \
        "test-icmp-te" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-ts-req" \
        "test-icmp-ts-req" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-ts-rep" \
        "test-icmp-ts-rep" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-pp" \
        "test-icmp-pp" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-sq" \
        "test-icmp-sq" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-redir" \
        "test-icmp-redir" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-ra" \
        "test-icmp-ra" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-rs" \
        "test-icmp-rs" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-mreq" \
        "test-icmp-mreq" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-icmp-mrep" \
        "test-icmp-mrep" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input inside -> test-icmp-in" \
        "test-icmp-in" \
        firewall show icmp4 input inside

    assert_output_contains "show icmp4 input vti -> test-icmp-vti" \
        "test-icmp-vti" \
        firewall show icmp4 input vti

    # --- Duplicate add ---
    assert_error "icmp4 add duplicate" \
        "already exists" \
        firewall icmp4 add input accept echo-request outside 10.0.0.0/8 test-icmp-out

    # --- Delete + show verification ---
    assert_success "icmp4 del test-icmp-out" \
        'Staged deletion of input ICMPv4 rule "test-icmp-out"' \
        firewall icmp4 del input test-icmp-out

    assert_output_not_contains "show icmp4 input outside after del test-icmp-out" \
        "test-icmp-out" \
        firewall show icmp4 input outside

    assert_success "icmp4 del test-icmp-in" \
        'Staged deletion of input ICMPv4 rule "test-icmp-in"' \
        firewall icmp4 del input test-icmp-in

    assert_output_not_contains "show icmp4 input inside after del test-icmp-in" \
        "test-icmp-in" \
        firewall show icmp4 input inside

    assert_success "icmp4 del test-icmp-vti" \
        'Staged deletion of input ICMPv4 rule "test-icmp-vti"' \
        firewall icmp4 del input test-icmp-vti

    assert_output_not_contains "show icmp4 input vti after del test-icmp-vti" \
        "test-icmp-vti" \
        firewall show icmp4 input vti

    assert_success "icmp4 del test-icmp-any" \
        'Staged deletion of input ICMPv4 rule "test-icmp-any"' \
        firewall icmp4 del input test-icmp-any

    assert_output_not_contains "show icmp4 input outside after del test-icmp-any" \
        "test-icmp-any" \
        firewall show icmp4 input outside

    assert_success "icmp4 del test-icmp-te" \
        'Staged deletion of input ICMPv4 rule "test-icmp-te"' \
        firewall icmp4 del input test-icmp-te

    assert_output_not_contains "show icmp4 input outside after del test-icmp-te" \
        "test-icmp-te" \
        firewall show icmp4 input outside

    assert_success "icmp4 del test-icmp-ts-req" \
        'Staged deletion of input ICMPv4 rule "test-icmp-ts-req"' \
        firewall icmp4 del input test-icmp-ts-req

    assert_success "icmp4 del test-icmp-ts-rep" \
        'Staged deletion of input ICMPv4 rule "test-icmp-ts-rep"' \
        firewall icmp4 del input test-icmp-ts-rep

    assert_success "icmp4 del test-icmp-pp" \
        'Staged deletion of input ICMPv4 rule "test-icmp-pp"' \
        firewall icmp4 del input test-icmp-pp

    assert_success "icmp4 del test-icmp-sq" \
        'Staged deletion of input ICMPv4 rule "test-icmp-sq"' \
        firewall icmp4 del input test-icmp-sq

    assert_success "icmp4 del test-icmp-redir" \
        'Staged deletion of input ICMPv4 rule "test-icmp-redir"' \
        firewall icmp4 del input test-icmp-redir

    assert_success "icmp4 del test-icmp-ra" \
        'Staged deletion of input ICMPv4 rule "test-icmp-ra"' \
        firewall icmp4 del input test-icmp-ra

    assert_success "icmp4 del test-icmp-rs" \
        'Staged deletion of input ICMPv4 rule "test-icmp-rs"' \
        firewall icmp4 del input test-icmp-rs

    assert_success "icmp4 del test-icmp-mreq" \
        'Staged deletion of input ICMPv4 rule "test-icmp-mreq"' \
        firewall icmp4 del input test-icmp-mreq

    assert_success "icmp4 del test-icmp-mrep" \
        'Staged deletion of input ICMPv4 rule "test-icmp-mrep"' \
        firewall icmp4 del input test-icmp-mrep

    assert_success "icmp4 del test-icmp-drop" \
        'Staged deletion of input ICMPv4 rule "test-icmp-drop"' \
        firewall icmp4 del input test-icmp-drop

    # --- Delete nonexistent ---
    assert_error "icmp4 del nonexistent" \
        "no matching rule" \
        firewall icmp4 del input nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 2b. ICMPv6 lifecycle
# ---------------------------------------------------------------------------
test_icmp6_lifecycle() {
    section "ICMPv6 RULES LIFECYCLE"
    cleanup_staging

    # --- Add (V6-only types) ---
    assert_success "icmp6 add packet-too-big outside" \
        'Staged new ICMPv6 rule "test-icmp6-ptb"' \
        firewall icmp6 add input accept packet-too-big outside fd00::/64 test-icmp6-ptb

    assert_success "icmp6 add neighbor-solicitation outside" \
        'Staged new ICMPv6 rule "test-icmp6-ns"' \
        firewall icmp6 add input accept neighbor-solicitation outside fd00::/64 test-icmp6-ns

    assert_success "icmp6 add neighbor-advertisement outside" \
        'Staged new ICMPv6 rule "test-icmp6-na"' \
        firewall icmp6 add input accept neighbor-advertisement outside fd00::/64 test-icmp6-na

    assert_success "icmp6 add ml-query outside" \
        'Staged new ICMPv6 rule "test-icmp6-mlq"' \
        firewall icmp6 add input accept ml-query outside fd00::/64 test-icmp6-mlq

    assert_success "icmp6 add ml-report outside" \
        'Staged new ICMPv6 rule "test-icmp6-mlr"' \
        firewall icmp6 add input accept ml-report outside fd00::/64 test-icmp6-mlr

    assert_success "icmp6 add ml-done outside" \
        'Staged new ICMPv6 rule "test-icmp6-mld"' \
        firewall icmp6 add input accept ml-done outside fd00::/64 test-icmp6-mld

    # --- Add (common types with IPv6 addresses) ---
    assert_success "icmp6 add echo-request outside" \
        'Staged new ICMPv6 rule "test-icmp6-echo"' \
        firewall icmp6 add input accept echo-request outside 2001:db8::/32 test-icmp6-echo

    assert_success "icmp6 add destination-unreachable inside" \
        'Staged new ICMPv6 rule "test-icmp6-du"' \
        firewall icmp6 add input accept destination-unreachable inside fd00::/64 test-icmp6-du

    assert_success "icmp6 add parameter-problem vti" \
        'Staged new ICMPv6 rule "test-icmp6-pp"' \
        firewall icmp6 add input accept parameter-problem vti fd00::/64 test-icmp6-pp

    assert_success "icmp6 add router-solicitation outside" \
        'Staged new ICMPv6 rule "test-icmp6-rs"' \
        firewall icmp6 add input accept router-solicitation outside fd00::/64 test-icmp6-rs

    assert_success "icmp6 add router-advertisement outside" \
        'Staged new ICMPv6 rule "test-icmp6-ra"' \
        firewall icmp6 add input accept router-advertisement outside fd00::/64 test-icmp6-ra

    assert_success "icmp6 add redirect outside" \
        'Staged new ICMPv6 rule "test-icmp6-redir"' \
        firewall icmp6 add input accept redirect outside fd00::/64 test-icmp6-redir

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show icmp6 input outside -> test-icmp6-ptb" \
        "test-icmp6-ptb" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-ns" \
        "test-icmp6-ns" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-na" \
        "test-icmp6-na" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-mlq" \
        "test-icmp6-mlq" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-mlr" \
        "test-icmp6-mlr" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-mld" \
        "test-icmp6-mld" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-echo" \
        "test-icmp6-echo" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-rs" \
        "test-icmp6-rs" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-ra" \
        "test-icmp6-ra" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input outside -> test-icmp6-redir" \
        "test-icmp6-redir" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input inside -> test-icmp6-du" \
        "test-icmp6-du" \
        firewall show icmp6 input inside

    assert_output_contains "show icmp6 input vti -> test-icmp6-pp" \
        "test-icmp6-pp" \
        firewall show icmp6 input vti

    # --- Duplicate add ---
    assert_error "icmp6 add duplicate" \
        "already exists" \
        firewall icmp6 add input accept packet-too-big outside fd00::/64 test-icmp6-ptb

    # --- Delete + show verification ---
    assert_success "icmp6 del test-icmp6-ptb" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-ptb"' \
        firewall icmp6 del input test-icmp6-ptb

    assert_output_not_contains "show icmp6 input outside after del test-icmp6-ptb" \
        "test-icmp6-ptb" \
        firewall show icmp6 input outside

    assert_success "icmp6 del test-icmp6-ns" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-ns"' \
        firewall icmp6 del input test-icmp6-ns

    assert_success "icmp6 del test-icmp6-na" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-na"' \
        firewall icmp6 del input test-icmp6-na

    assert_success "icmp6 del test-icmp6-mlq" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-mlq"' \
        firewall icmp6 del input test-icmp6-mlq

    assert_success "icmp6 del test-icmp6-mlr" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-mlr"' \
        firewall icmp6 del input test-icmp6-mlr

    assert_success "icmp6 del test-icmp6-mld" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-mld"' \
        firewall icmp6 del input test-icmp6-mld

    assert_success "icmp6 del test-icmp6-echo" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-echo"' \
        firewall icmp6 del input test-icmp6-echo

    assert_success "icmp6 del test-icmp6-du" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-du"' \
        firewall icmp6 del input test-icmp6-du

    assert_success "icmp6 del test-icmp6-pp" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-pp"' \
        firewall icmp6 del input test-icmp6-pp

    assert_success "icmp6 del test-icmp6-rs" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-rs"' \
        firewall icmp6 del input test-icmp6-rs

    assert_success "icmp6 del test-icmp6-ra" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-ra"' \
        firewall icmp6 del input test-icmp6-ra

    assert_success "icmp6 del test-icmp6-redir" \
        'Staged deletion of input ICMPv6 rule "test-icmp6-redir"' \
        firewall icmp6 del input test-icmp6-redir

    # --- Delete nonexistent ---
    assert_error "icmp6 del nonexistent" \
        "no matching rule" \
        firewall icmp6 del input nonexistent-v6-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 2c. ICMPv4 FORWARD lifecycle
# ---------------------------------------------------------------------------
test_icmp4_fwd_lifecycle() {
    section "ICMPv4 FORWARD RULES LIFECYCLE"
    cleanup_staging

    # --- Add (forward + accept) ---
    assert_success "icmp4 add forward accept echo-request outside" \
        'Staged new ICMPv4 rule "test-fwd-echo"' \
        firewall icmp4 add forward accept echo-request outside 10.0.0.0/8 test-fwd-echo

    assert_success "icmp4 add forward drop echo-request inside" \
        'Staged new ICMPv4 rule "test-fwd-drop"' \
        firewall icmp4 add forward drop echo-request inside 192.168.0.0/16 test-fwd-drop

    assert_success "icmp4 add forward accept unreachable vti" \
        'Staged new ICMPv4 rule "test-fwd-vti"' \
        firewall icmp4 add forward accept unreachable vti 172.16.0.0/12 test-fwd-vti

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show icmp4 forward outside -> test-fwd-echo" \
        "test-fwd-echo" \
        firewall show icmp4 forward outside

    assert_output_contains "show icmp4 forward inside -> test-fwd-drop" \
        "test-fwd-drop" \
        firewall show icmp4 forward inside

    assert_output_contains "show icmp4 forward vti -> test-fwd-vti" \
        "test-fwd-vti" \
        firewall show icmp4 forward vti

    # --- Duplicate add ---
    assert_error "icmp4 add forward duplicate" \
        "already exists" \
        firewall icmp4 add forward accept echo-request outside 10.0.0.0/8 test-fwd-echo

    # --- Delete + show verification ---
    assert_success "icmp4 del forward test-fwd-echo" \
        'Staged deletion of forward ICMPv4 rule "test-fwd-echo"' \
        firewall icmp4 del forward test-fwd-echo

    assert_output_not_contains "show icmp4 forward outside after del test-fwd-echo" \
        "test-fwd-echo" \
        firewall show icmp4 forward outside

    assert_success "icmp4 del forward test-fwd-drop" \
        'Staged deletion of forward ICMPv4 rule "test-fwd-drop"' \
        firewall icmp4 del forward test-fwd-drop

    assert_output_not_contains "show icmp4 forward inside after del test-fwd-drop" \
        "test-fwd-drop" \
        firewall show icmp4 forward inside

    assert_success "icmp4 del forward test-fwd-vti" \
        'Staged deletion of forward ICMPv4 rule "test-fwd-vti"' \
        firewall icmp4 del forward test-fwd-vti

    assert_output_not_contains "show icmp4 forward vti after del test-fwd-vti" \
        "test-fwd-vti" \
        firewall show icmp4 forward vti

    # --- Delete nonexistent ---
    assert_error "icmp4 del forward nonexistent" \
        "no matching rule" \
        firewall icmp4 del forward nonexistent-fwd-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 2d. ICMPv6 FORWARD lifecycle
# ---------------------------------------------------------------------------
test_icmp6_fwd_lifecycle() {
    section "ICMPv6 FORWARD RULES LIFECYCLE"
    cleanup_staging

    # --- Add (forward) ---
    assert_success "icmp6 add forward accept echo-request outside" \
        'Staged new ICMPv6 rule "test-fwd6-echo"' \
        firewall icmp6 add forward accept echo-request outside fd00::/64 test-fwd6-echo

    assert_success "icmp6 add forward drop destination-unreachable inside" \
        'Staged new ICMPv6 rule "test-fwd6-drop"' \
        firewall icmp6 add forward drop destination-unreachable inside 2001:db8::/32 test-fwd6-drop

    assert_success "icmp6 add forward accept packet-too-big vti" \
        'Staged new ICMPv6 rule "test-fwd6-vti"' \
        firewall icmp6 add forward accept packet-too-big vti fd00::/64 test-fwd6-vti

    # --- Show ---
    assert_output_contains "show icmp6 forward outside -> test-fwd6-echo" \
        "test-fwd6-echo" \
        firewall show icmp6 forward outside

    assert_output_contains "show icmp6 forward inside -> test-fwd6-drop" \
        "test-fwd6-drop" \
        firewall show icmp6 forward inside

    assert_output_contains "show icmp6 forward vti -> test-fwd6-vti" \
        "test-fwd6-vti" \
        firewall show icmp6 forward vti

    # --- Delete ---
    assert_success "icmp6 del forward test-fwd6-echo" \
        'Staged deletion of forward ICMPv6 rule "test-fwd6-echo"' \
        firewall icmp6 del forward test-fwd6-echo

    assert_success "icmp6 del forward test-fwd6-drop" \
        'Staged deletion of forward ICMPv6 rule "test-fwd6-drop"' \
        firewall icmp6 del forward test-fwd6-drop

    assert_success "icmp6 del forward test-fwd6-vti" \
        'Staged deletion of forward ICMPv6 rule "test-fwd6-vti"' \
        firewall icmp6 del forward test-fwd6-vti

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 2e. ICMPv4 type-code (numeric) input
# ---------------------------------------------------------------------------
test_icmp4_type_code() {
    section "ICMPv4 TYPE-CODE (numeric)"
    cleanup_staging

    # --- Add with type only (e.g. type 3 = destination-unreachable) ---
    assert_success "icmp4 type-code add type-only (3)" \
        'Staged new ICMPv4 rule "test-tc-type3"' \
        firewall icmp4 add input accept type-code 3 outside 10.0.0.0/8 test-tc-type3

    # --- Add with type/code (e.g. 3/4 = fragmentation-needed) ---
    assert_success "icmp4 type-code add 3/4 (frag-needed)" \
        'Staged new ICMPv4 rule "test-tc-frag"' \
        firewall icmp4 add input accept type-code 3/4 outside 10.1.0.0/16 test-tc-frag

    # --- Add with type/code (e.g. 11/0 = ttl-zero-during-transit) ---
    assert_success "icmp4 type-code add 11/0 (ttl-exceeded)" \
        'Staged new ICMPv4 rule "test-tc-ttl"' \
        firewall icmp4 add input drop type-code 11/0 inside 192.168.0.0/16 test-tc-ttl

    # --- Add with type/code (e.g. 3/10 = host-precedence-violation) ---
    assert_success "icmp4 type-code add 3/10" \
        'Staged new ICMPv4 rule "test-tc-310"' \
        firewall icmp4 add forward drop type-code 3/10 inside 10.10.0.0/16 test-tc-310

    # --- Show (verify staged rules appear) ---
    assert_output_contains "show icmp4 input outside -> test-tc-type3" \
        "test-tc-type3" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-tc-frag" \
        "test-tc-frag" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input inside -> test-tc-ttl" \
        "test-tc-ttl" \
        firewall show icmp4 input inside

    assert_output_contains "show icmp4 forward inside -> test-tc-310" \
        "test-tc-310" \
        firewall show icmp4 forward inside

    # --- Delete ---
    assert_success "icmp4 del test-tc-type3" \
        'Staged deletion of input ICMPv4 rule "test-tc-type3"' \
        firewall icmp4 del input test-tc-type3

    assert_success "icmp4 del test-tc-frag" \
        'Staged deletion of input ICMPv4 rule "test-tc-frag"' \
        firewall icmp4 del input test-tc-frag

    assert_success "icmp4 del test-tc-ttl" \
        'Staged deletion of input ICMPv4 rule "test-tc-ttl"' \
        firewall icmp4 del input test-tc-ttl

    assert_success "icmp4 del test-tc-310" \
        'Staged deletion of forward ICMPv4 rule "test-tc-310"' \
        firewall icmp4 del forward test-tc-310

    # --- Invalid type-code ---
    assert_error "icmp4 type-code invalid (256)" \
        "invalid ICMP type" \
        firewall icmp4 add input accept type-code 256 outside 10.0.0.0/8 test-tc-err

    assert_error "icmp4 type-code invalid (abc)" \
        "invalid ICMP type" \
        firewall icmp4 add input accept type-code abc outside 10.0.0.0/8 test-tc-err

    assert_error "icmp4 type-code invalid code (3/256)" \
        "invalid ICMP code" \
        firewall icmp4 add input accept type-code 3/256 outside 10.0.0.0/8 test-tc-err

    # --- Invalid zone in type-code ---
    assert_error "icmp4 type-code invalid zone" \
        "invalid zone" \
        firewall icmp4 add input accept type-code 3 badzone 10.0.0.0/8 test-tc-err

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 2f. ICMPv6 type-code (numeric) input
# ---------------------------------------------------------------------------
test_icmp6_type_code() {
    section "ICMPv6 TYPE-CODE (numeric)"
    cleanup_staging

    # --- Add with type only (e.g. type 128 = echo-request) ---
    assert_success "icmp6 type-code add type-only (128)" \
        'Staged new ICMPv6 rule "test-tc6-echo"' \
        firewall icmp6 add input accept type-code 128 outside fd00::/64 test-tc6-echo

    # --- Add with type/code (e.g. 1/3 = address-unreachable) ---
    assert_success "icmp6 type-code add 1/3 (addr-unreachable)" \
        'Staged new ICMPv6 rule "test-tc6-addr"' \
        firewall icmp6 add input drop type-code 1/3 inside 2001:db8::/32 test-tc6-addr

    # --- Add forward ---
    assert_success "icmp6 type-code add forward 2 (pkt-too-big)" \
        'Staged new ICMPv6 rule "test-tc6-ptb"' \
        firewall icmp6 add forward accept type-code 2 outside fd00::/64 test-tc6-ptb

    # --- Show ---
    assert_output_contains "show icmp6 input outside -> test-tc6-echo" \
        "test-tc6-echo" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp6 input inside -> test-tc6-addr" \
        "test-tc6-addr" \
        firewall show icmp6 input inside

    assert_output_contains "show icmp6 forward outside -> test-tc6-ptb" \
        "test-tc6-ptb" \
        firewall show icmp6 forward outside

    # --- Delete ---
    assert_success "icmp6 del test-tc6-echo" \
        'Staged deletion of input ICMPv6 rule "test-tc6-echo"' \
        firewall icmp6 del input test-tc6-echo

    assert_success "icmp6 del test-tc6-addr" \
        'Staged deletion of input ICMPv6 rule "test-tc6-addr"' \
        firewall icmp6 del input test-tc6-addr

    assert_success "icmp6 del test-tc6-ptb" \
        'Staged deletion of forward ICMPv6 rule "test-tc6-ptb"' \
        firewall icmp6 del forward test-tc6-ptb

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 2g. ICMP --logging flag (NIAP FAU_GEN.1)
# ---------------------------------------------------------------------------
test_icmp_logging() {
    section "ICMP --logging FLAG"
    cleanup_staging

    # --- ICMPv4 with --logging (accept → AKITA_LOG_ACCEPT) ---
    assert_success "icmp4 add echo-request outside --logging" \
        'Staged new ICMPv4 rule "test-log-accept"' \
        firewall icmp4 add input accept echo-request outside 10.0.0.0/8 test-log-accept --logging

    # --- ICMPv4 with --logging (drop → AKITA_LOG_DROP) ---
    assert_success "icmp4 add drop echo-request outside --logging" \
        'Staged new ICMPv4 rule "test-log-drop"' \
        firewall icmp4 add input drop echo-request outside 10.1.0.0/16 test-log-drop --logging

    # --- ICMPv6 with --logging ---
    assert_success "icmp6 add echo-request outside --logging" \
        'Staged new ICMPv6 rule "test-log6-accept"' \
        firewall icmp6 add input accept echo-request outside fd00::/64 test-log6-accept --logging

    # --- ICMPv4 type-code with --logging ---
    assert_success "icmp4 type-code 3/4 --logging" \
        'Staged new ICMPv4 rule "test-log-tc"' \
        firewall icmp4 add input drop type-code 3/4 outside 10.2.0.0/16 test-log-tc --logging

    # --- Show (verify staged) ---
    assert_output_contains "show icmp4 input outside -> test-log-accept" \
        "test-log-accept" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp4 input outside -> test-log-drop" \
        "test-log-drop" \
        firewall show icmp4 input outside

    assert_output_contains "show icmp6 input outside -> test-log6-accept" \
        "test-log6-accept" \
        firewall show icmp6 input outside

    assert_output_contains "show icmp4 input outside -> test-log-tc" \
        "test-log-tc" \
        firewall show icmp4 input outside

    # --- Delete ---
    assert_success "icmp4 del test-log-accept" \
        'Staged deletion of input ICMPv4 rule "test-log-accept"' \
        firewall icmp4 del input test-log-accept

    assert_success "icmp4 del test-log-drop" \
        'Staged deletion of input ICMPv4 rule "test-log-drop"' \
        firewall icmp4 del input test-log-drop

    assert_success "icmp6 del test-log6-accept" \
        'Staged deletion of input ICMPv6 rule "test-log6-accept"' \
        firewall icmp6 del input test-log6-accept

    assert_success "icmp4 del test-log-tc" \
        'Staged deletion of input ICMPv4 rule "test-log-tc"' \
        firewall icmp4 del input test-log-tc

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 3. Inside-filter lifecycle
# ---------------------------------------------------------------------------
test_inside_filter_lifecycle() {
    section "ACCESS-POLICY ADD/DEL INSIDE RULES LIFECYCLE"
    cleanup_staging

    # --- Add with various flags ---
    assert_success "access-policy add inside accept with ports" \
        'Staged new inside access-policy rule "test-if-accept"' \
        firewall access-policy add inside accept test-if-accept 192.168.1.0/24 10.0.0.0/8 \
        -p tcp --sport 1024 --dport 80

    assert_success "access-policy add inside drop with not-src" \
        'Staged new inside access-policy rule "test-if-drop"' \
        firewall access-policy add inside drop test-if-drop 10.0.0.0/8 192.168.0.0/16 \
        -p udp --not-src

    assert_success "access-policy add inside accept with logging" \
        'Staged new inside access-policy rule "test-if-log"' \
        firewall access-policy add inside accept test-if-log 10.1.0.0/16 192.168.0.0/16 \
        -p tcp --dport 443 --logging

    assert_success "access-policy add inside accept with not-dst" \
        'Staged new inside access-policy rule "test-if-notdst"' \
        firewall access-policy add inside accept test-if-notdst 10.0.0.0/8 192.168.0.0/16 \
        --not-dst

    assert_success "access-policy add inside accept IPv6" \
        'Staged new inside access-policy rule "test-if-v6"' \
        firewall access-policy add inside accept test-if-v6 fd00::/64 2001:db8::/32 \
        -p tcp --dport 80

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show access-policy inside -> test-if-accept" \
        "test-if-accept" \
        firewall show access-policy inside

    assert_output_contains "show access-policy inside -> test-if-drop" \
        "test-if-drop" \
        firewall show access-policy inside

    assert_output_contains "show access-policy inside -> test-if-log" \
        "test-if-log" \
        firewall show access-policy inside

    assert_output_contains "show access-policy inside -> test-if-notdst" \
        "test-if-notdst" \
        firewall show access-policy inside

    assert_output_contains "show access-policy inside -> test-if-v6" \
        "test-if-v6" \
        firewall show access-policy inside

    # --- Duplicate ---
    assert_error "access-policy add inside duplicate" \
        "already exists" \
        firewall access-policy add inside accept test-if-accept 10.0.0.0/8 10.0.0.0/8

    # --- Delete + show verification ---
    assert_success "access-policy del inside accept" \
        'Staged deletion of inside access-policy rule "test-if-accept"' \
        firewall access-policy del inside test-if-accept

    assert_output_not_contains "show access-policy inside after del test-if-accept" \
        "test-if-accept" \
        firewall show access-policy inside

    assert_success "access-policy del inside drop" \
        'Staged deletion of inside access-policy rule "test-if-drop"' \
        firewall access-policy del inside test-if-drop

    assert_output_not_contains "show access-policy inside after del test-if-drop" \
        "test-if-drop" \
        firewall show access-policy inside

    assert_success "access-policy del inside log" \
        'Staged deletion of inside access-policy rule "test-if-log"' \
        firewall access-policy del inside test-if-log

    assert_output_not_contains "show access-policy inside after del test-if-log" \
        "test-if-log" \
        firewall show access-policy inside

    assert_success "access-policy del inside notdst" \
        'Staged deletion of inside access-policy rule "test-if-notdst"' \
        firewall access-policy del inside test-if-notdst

    assert_output_not_contains "show access-policy inside after del test-if-notdst" \
        "test-if-notdst" \
        firewall show access-policy inside

    assert_success "access-policy del inside v6" \
        'Staged deletion of inside access-policy rule "test-if-v6"' \
        firewall access-policy del inside test-if-v6

    assert_output_not_contains "show access-policy inside after del test-if-v6" \
        "test-if-v6" \
        firewall show access-policy inside

    # --- Delete nonexistent ---
    assert_error "access-policy del inside nonexistent" \
        "no matching rule" \
        firewall access-policy del inside nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 4. Outside-filter lifecycle
# ---------------------------------------------------------------------------
test_outside_filter_lifecycle() {
    section "ACCESS-POLICY ADD/DEL OUTSIDE RULES LIFECYCLE"
    cleanup_staging

    assert_success "access-policy add outside accept" \
        'Staged new outside access-policy rule "test-of-accept"' \
        firewall access-policy add outside accept test-of-accept 0.0.0.0/0 192.168.1.100 \
        -p tcp --dport 443

    assert_success "access-policy add outside drop" \
        'Staged new outside access-policy rule "test-of-drop"' \
        firewall access-policy add outside drop test-of-drop 10.0.0.0/8 192.168.0.0/16 \
        -p udp

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show access-policy outside -> test-of-accept" \
        "test-of-accept" \
        firewall show access-policy outside

    assert_output_contains "show access-policy outside -> test-of-drop" \
        "test-of-drop" \
        firewall show access-policy outside

    # --- Duplicate ---
    assert_error "access-policy add outside duplicate" \
        "already exists" \
        firewall access-policy add outside accept test-of-accept 10.0.0.0/8 10.0.0.0/8

    # --- Delete + show verification ---
    assert_success "access-policy del outside accept" \
        'Staged deletion of outside access-policy rule "test-of-accept"' \
        firewall access-policy del outside test-of-accept

    assert_output_not_contains "show access-policy outside after del test-of-accept" \
        "test-of-accept" \
        firewall show access-policy outside

    assert_success "access-policy del outside drop" \
        'Staged deletion of outside access-policy rule "test-of-drop"' \
        firewall access-policy del outside test-of-drop

    assert_output_not_contains "show access-policy outside after del test-of-drop" \
        "test-of-drop" \
        firewall show access-policy outside

    # --- Delete nonexistent ---
    assert_error "access-policy del outside nonexistent" \
        "no matching rule" \
        firewall access-policy del outside nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 5. VPN-in lifecycle
# ---------------------------------------------------------------------------
test_vpn_in_lifecycle() {
    section "VPN-POLICY ADD/DEL IN RULES LIFECYCLE"
    cleanup_staging

    # --- Add deny ---
    assert_success "vpn-policy add in deny" \
        'Staged new vpn-policy in rule "test-vpn-in-deny" (action=deny)' \
        firewall vpn-policy add in deny test-vpn-in-deny 172.16.0.0/12 0.0.0.0/0 \
        -p tcp --dport 22

    # --- Add allow ---
    assert_success "vpn-policy add in allow" \
        'Staged new vpn-policy in rule "test-vpn-in-allow" (action=allow)' \
        firewall vpn-policy add in allow test-vpn-in-allow 172.16.0.0/12 0.0.0.0/0 \
        -p tcp --dport 443

    # --- Add bypass (may require XFRM scripts) ---
    local bypass_output bypass_exit=0
    bypass_output=$(scli_run firewall vpn-policy add in bypass test-vpn-in-bypass 172.16.0.0/12 0.0.0.0/0 -p tcp --dport 80) || bypass_exit=$?

    if echo "$bypass_output" | grep -qF 'Staged new vpn-policy in rule'; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn-policy add in bypass\n"
    elif echo "$bypass_output" | grep -qi "no such file\|not found\|xfrm"; then
        skip_test "vpn-policy add in bypass" "XFRM scripts not available"
    else
        TOTAL=$((TOTAL + 1)); FAIL=$((FAIL + 1)); FAILURES+=("vpn-policy add in bypass")
        printf "  ${RED}FAIL${NC}  vpn-policy add in bypass\n"
        printf "        output: %s\n" "$bypass_output"
    fi

    # --- Add with logging ---
    assert_success "vpn-policy add in deny with logging" \
        'Staged new vpn-policy in rule "test-vpn-in-log" (action=deny)' \
        firewall vpn-policy add in deny test-vpn-in-log 10.0.0.0/8 0.0.0.0/0 \
        -p udp --dport 53 --logging

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show vpn-policy in deny -> test-vpn-in-deny" \
        "test-vpn-in-deny" \
        firewall show vpn-policy in deny

    assert_output_contains "show vpn-policy in allow -> test-vpn-in-allow" \
        "test-vpn-in-allow" \
        firewall show vpn-policy in allow

    if echo "$bypass_output" | grep -qF 'Staged new vpn-policy in rule'; then
        assert_output_contains "show vpn-policy in bypass -> test-vpn-in-bypass" \
            "test-vpn-in-bypass" \
            firewall show vpn-policy in bypass
    fi

    assert_output_contains "show vpn-policy in deny -> test-vpn-in-log" \
        "test-vpn-in-log" \
        firewall show vpn-policy in deny

    # --- Duplicate ---
    assert_error "vpn-policy add in deny duplicate" \
        "already exists" \
        firewall vpn-policy add in deny test-vpn-in-deny 10.0.0.0/8 0.0.0.0/0

    # --- Delete + show verification ---
    assert_success "vpn-policy del in deny" \
        'Staged deletion of vpn-policy in rule "test-vpn-in-deny"' \
        firewall vpn-policy del in deny test-vpn-in-deny

    assert_output_not_contains "show vpn-policy in deny after del test-vpn-in-deny" \
        "test-vpn-in-deny" \
        firewall show vpn-policy in deny

    assert_success "vpn-policy del in allow" \
        'Staged deletion of vpn-policy in rule "test-vpn-in-allow"' \
        firewall vpn-policy del in allow test-vpn-in-allow

    assert_output_not_contains "show vpn-policy in allow after del test-vpn-in-allow" \
        "test-vpn-in-allow" \
        firewall show vpn-policy in allow

    # Clean up bypass only if it was added
    if echo "$bypass_output" | grep -qF 'Staged new vpn-policy in rule'; then
        assert_success "vpn-policy del in bypass" \
            'Staged deletion of vpn-policy in rule "test-vpn-in-bypass"' \
            firewall vpn-policy del in bypass test-vpn-in-bypass

        assert_output_not_contains "show vpn-policy in bypass after del test-vpn-in-bypass" \
            "test-vpn-in-bypass" \
            firewall show vpn-policy in bypass
    fi

    assert_success "vpn-policy del in deny-log" \
        'Staged deletion of vpn-policy in rule "test-vpn-in-log"' \
        firewall vpn-policy del in deny test-vpn-in-log

    assert_output_not_contains "show vpn-policy in deny after del test-vpn-in-log" \
        "test-vpn-in-log" \
        firewall show vpn-policy in deny

    # --- Delete nonexistent ---
    assert_error "vpn-policy del in deny nonexistent" \
        "no matching rule" \
        firewall vpn-policy del in deny nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 6. VPN-out lifecycle
# ---------------------------------------------------------------------------
test_vpn_out_lifecycle() {
    section "VPN-POLICY ADD/DEL OUT RULES LIFECYCLE"
    cleanup_staging

    # --- Add deny ---
    assert_success "vpn-policy add out deny" \
        'Staged new vpn-policy out rule "test-vpn-out-deny" (action=deny)' \
        firewall vpn-policy add out deny test-vpn-out-deny 192.168.0.0/16 0.0.0.0/0 \
        -p tcp --dport 22

    # --- Add allow ---
    assert_success "vpn-policy add out allow" \
        'Staged new vpn-policy out rule "test-vpn-out-allow" (action=allow)' \
        firewall vpn-policy add out allow test-vpn-out-allow 192.168.0.0/16 0.0.0.0/0 \
        -p tcp --dport 443

    # --- Add bypass (may require XFRM scripts) ---
    local bypass_output bypass_exit=0
    bypass_output=$(scli_run firewall vpn-policy add out bypass test-vpn-out-bypass 192.168.0.0/16 0.0.0.0/0 -p tcp --dport 80) || bypass_exit=$?

    if echo "$bypass_output" | grep -qF 'Staged new vpn-policy out rule'; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn-policy add out bypass\n"
    elif echo "$bypass_output" | grep -qi "no such file\|not found\|xfrm"; then
        skip_test "vpn-policy add out bypass" "XFRM scripts not available"
    else
        TOTAL=$((TOTAL + 1)); FAIL=$((FAIL + 1)); FAILURES+=("vpn-policy add out bypass")
        printf "  ${RED}FAIL${NC}  vpn-policy add out bypass\n"
        printf "        output: %s\n" "$bypass_output"
    fi

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show vpn-policy out deny -> test-vpn-out-deny" \
        "test-vpn-out-deny" \
        firewall show vpn-policy out deny

    assert_output_contains "show vpn-policy out allow -> test-vpn-out-allow" \
        "test-vpn-out-allow" \
        firewall show vpn-policy out allow

    if echo "$bypass_output" | grep -qF 'Staged new vpn-policy out rule'; then
        assert_output_contains "show vpn-policy out bypass -> test-vpn-out-bypass" \
            "test-vpn-out-bypass" \
            firewall show vpn-policy out bypass
    fi

    # --- Duplicate ---
    assert_error "vpn-policy add out deny duplicate" \
        "already exists" \
        firewall vpn-policy add out deny test-vpn-out-deny 10.0.0.0/8 0.0.0.0/0

    # --- Delete + show verification ---
    assert_success "vpn-policy del out deny" \
        'Staged deletion of vpn-policy out rule "test-vpn-out-deny"' \
        firewall vpn-policy del out deny test-vpn-out-deny

    assert_output_not_contains "show vpn-policy out deny after del test-vpn-out-deny" \
        "test-vpn-out-deny" \
        firewall show vpn-policy out deny

    assert_success "vpn-policy del out allow" \
        'Staged deletion of vpn-policy out rule "test-vpn-out-allow"' \
        firewall vpn-policy del out allow test-vpn-out-allow

    assert_output_not_contains "show vpn-policy out allow after del test-vpn-out-allow" \
        "test-vpn-out-allow" \
        firewall show vpn-policy out allow

    if echo "$bypass_output" | grep -qF 'Staged new vpn-policy out rule'; then
        assert_success "vpn-policy del out bypass" \
            'Staged deletion of vpn-policy out rule "test-vpn-out-bypass"' \
            firewall vpn-policy del out bypass test-vpn-out-bypass

        assert_output_not_contains "show vpn-policy out bypass after del test-vpn-out-bypass" \
            "test-vpn-out-bypass" \
            firewall show vpn-policy out bypass
    fi

    # --- Delete nonexistent ---
    assert_error "vpn-policy del out deny nonexistent" \
        "no matching rule" \
        firewall vpn-policy del out deny nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 7. NAT masquerade lifecycle
# ---------------------------------------------------------------------------
test_nat_masquerade_lifecycle() {
    section "NAT MASQUERADE LIFECYCLE"
    cleanup_staging

    # --- Add ---
    assert_success "nat masquerade add" \
        'Staged new NAT masquerade rule "test-masq-base"' \
        firewall nat masquerade add test-masq-base 192.168.1.0/24 0.0.0.0/0

    assert_success "nat masquerade add with proto and not-dst" \
        'Staged new NAT masquerade rule "test-masq-tcp"' \
        firewall nat masquerade add test-masq-tcp 10.0.0.0/8 192.168.0.0/16 \
        -p tcp --not-dst

    assert_success "nat masquerade add with logging" \
        'Staged new NAT masquerade rule "test-masq-log"' \
        firewall nat masquerade add test-masq-log 10.1.0.0/16 0.0.0.0/0 \
        --logging

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show nat masquerade -> test-masq-base" \
        "test-masq-base" \
        firewall show nat masquerade

    assert_output_contains "show nat masquerade -> test-masq-tcp" \
        "test-masq-tcp" \
        firewall show nat masquerade

    assert_output_contains "show nat masquerade -> test-masq-log" \
        "test-masq-log" \
        firewall show nat masquerade

    # --- Duplicate ---
    assert_error "nat masquerade add duplicate" \
        "already exists" \
        firewall nat masquerade add test-masq-base 10.0.0.0/8 0.0.0.0/0

    # --- Delete + show verification ---
    assert_success "nat masquerade del" \
        'Staged deletion of NAT masquerade rule "test-masq-base"' \
        firewall nat masquerade del test-masq-base

    assert_output_not_contains "show nat masquerade after del test-masq-base" \
        "test-masq-base" \
        firewall show nat masquerade

    assert_success "nat masquerade del tcp" \
        'Staged deletion of NAT masquerade rule "test-masq-tcp"' \
        firewall nat masquerade del test-masq-tcp

    assert_output_not_contains "show nat masquerade after del test-masq-tcp" \
        "test-masq-tcp" \
        firewall show nat masquerade

    assert_success "nat masquerade del log" \
        'Staged deletion of NAT masquerade rule "test-masq-log"' \
        firewall nat masquerade del test-masq-log

    assert_output_not_contains "show nat masquerade after del test-masq-log" \
        "test-masq-log" \
        firewall show nat masquerade

    # --- Delete nonexistent ---
    assert_error "nat masquerade del nonexistent" \
        "no matching rule" \
        firewall nat masquerade del nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 8. NAT SNAT lifecycle
# ---------------------------------------------------------------------------
test_nat_snat_lifecycle() {
    section "NAT SNAT LIFECYCLE"
    cleanup_staging

    # --- Add (--to-source required) ---
    assert_success "nat snat add with ports" \
        'Staged new NAT SNAT rule "test-snat-base"' \
        firewall nat snat add test-snat-base 192.168.1.0/24 0.0.0.0/0 \
        --to-source 203.0.113.1:8080 -p tcp --dport 80

    assert_success "nat snat add minimal" \
        'Staged new NAT SNAT rule "test-snat-min"' \
        firewall nat snat add test-snat-min 10.0.0.0/8 0.0.0.0/0 \
        --to-source 203.0.113.2:443

    assert_success "nat snat add with sport" \
        'Staged new NAT SNAT rule "test-snat-sp"' \
        firewall nat snat add test-snat-sp 10.0.0.0/8 0.0.0.0/0 \
        --to-source 203.0.113.3:9090 -p tcp --sport 1024 --dport 80

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show nat snat -> test-snat-base" \
        "test-snat-base" \
        firewall show nat snat

    assert_output_contains "show nat snat -> test-snat-min" \
        "test-snat-min" \
        firewall show nat snat

    assert_output_contains "show nat snat -> test-snat-sp" \
        "test-snat-sp" \
        firewall show nat snat

    # --- Duplicate ---
    assert_error "nat snat add duplicate" \
        "already exists" \
        firewall nat snat add test-snat-base 10.0.0.0/8 0.0.0.0/0 \
        --to-source 1.2.3.4:80

    # --- Missing --to-source ---
    assert_error "nat snat add missing --to-source" \
        "required" \
        firewall nat snat add test-snat-err 10.0.0.0/8 0.0.0.0/0

    # --- Delete + show verification ---
    assert_success "nat snat del" \
        'Staged deletion of NAT SNAT rule "test-snat-base"' \
        firewall nat snat del test-snat-base

    assert_output_not_contains "show nat snat after del test-snat-base" \
        "test-snat-base" \
        firewall show nat snat

    assert_success "nat snat del min" \
        'Staged deletion of NAT SNAT rule "test-snat-min"' \
        firewall nat snat del test-snat-min

    assert_output_not_contains "show nat snat after del test-snat-min" \
        "test-snat-min" \
        firewall show nat snat

    assert_success "nat snat del sp" \
        'Staged deletion of NAT SNAT rule "test-snat-sp"' \
        firewall nat snat del test-snat-sp

    assert_output_not_contains "show nat snat after del test-snat-sp" \
        "test-snat-sp" \
        firewall show nat snat

    # --- Delete nonexistent ---
    assert_error "nat snat del nonexistent" \
        "no matching rule" \
        firewall nat snat del nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 9. NAT DNAT lifecycle
# ---------------------------------------------------------------------------
test_nat_dnat_lifecycle() {
    section "NAT DNAT LIFECYCLE"
    cleanup_staging

    # --- Add (--to-destination required) ---
    assert_success "nat dnat add with ports" \
        'Staged new NAT DNAT rule "test-dnat-base"' \
        firewall nat dnat add test-dnat-base 0.0.0.0/0 203.0.113.1 \
        --to-destination 192.168.1.100:80 -p tcp --dport 80

    assert_success "nat dnat add minimal" \
        'Staged new NAT DNAT rule "test-dnat-min"' \
        firewall nat dnat add test-dnat-min 0.0.0.0/0 203.0.113.2 \
        --to-destination 192.168.1.200:443

    assert_success "nat dnat add with sport" \
        'Staged new NAT DNAT rule "test-dnat-sp"' \
        firewall nat dnat add test-dnat-sp 10.0.0.0/8 203.0.113.3 \
        --to-destination 192.168.1.50:8080 -p tcp --sport 1024 --dport 8080

    # --- Show (verify ALL staged rules appear) ---
    assert_output_contains "show nat dnat -> test-dnat-base" \
        "test-dnat-base" \
        firewall show nat dnat

    assert_output_contains "show nat dnat -> test-dnat-min" \
        "test-dnat-min" \
        firewall show nat dnat

    assert_output_contains "show nat dnat -> test-dnat-sp" \
        "test-dnat-sp" \
        firewall show nat dnat

    # --- Duplicate ---
    assert_error "nat dnat add duplicate" \
        "already exists" \
        firewall nat dnat add test-dnat-base 10.0.0.0/8 10.0.0.0/8 \
        --to-destination 1.2.3.4:80

    # --- Missing --to-destination ---
    assert_error "nat dnat add missing --to-destination" \
        "required" \
        firewall nat dnat add test-dnat-err 10.0.0.0/8 10.0.0.0/8

    # --- Delete + show verification ---
    assert_success "nat dnat del" \
        'Staged deletion of NAT DNAT rule "test-dnat-base"' \
        firewall nat dnat del test-dnat-base

    assert_output_not_contains "show nat dnat after del test-dnat-base" \
        "test-dnat-base" \
        firewall show nat dnat

    assert_success "nat dnat del min" \
        'Staged deletion of NAT DNAT rule "test-dnat-min"' \
        firewall nat dnat del test-dnat-min

    assert_output_not_contains "show nat dnat after del test-dnat-min" \
        "test-dnat-min" \
        firewall show nat dnat

    assert_success "nat dnat del sp" \
        'Staged deletion of NAT DNAT rule "test-dnat-sp"' \
        firewall nat dnat del test-dnat-sp

    assert_output_not_contains "show nat dnat after del test-dnat-sp" \
        "test-dnat-sp" \
        firewall show nat dnat

    # --- Delete nonexistent ---
    assert_error "nat dnat del nonexistent" \
        "no matching rule" \
        firewall nat dnat del nonexistent-rule-xyz

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 10. Reset command
# ---------------------------------------------------------------------------
test_reset_command() {
    section "RESET COMMAND"

    # Reset with no staging
    cleanup_staging
    assert_output_contains "reset with no staging" \
        "No staged changes to discard" \
        firewall reset

    # Create some staging, then reset
    scli_run firewall icmp4 add input accept echo-request outside 10.0.0.0/8 test-reset-rule >/dev/null 2>&1 || true

    assert_output_contains "reset with staging" \
        "Staged firewall changes discarded" \
        firewall reset

    # Verify staging directory is gone
    assert_dir_not_exists "staging dir removed after reset" "$STAGE_ROOT"

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 11. Validation errors (cross-cutting)
# ---------------------------------------------------------------------------
test_validation_errors() {
    section "VALIDATION ERRORS"
    cleanup_staging

    # --- Invalid IP/CIDR ---
    assert_error "invalid source IP" \
        "invalid" \
        firewall access-policy add inside accept test-val-err not-an-ip 10.0.0.0/8

    assert_error "invalid dest CIDR" \
        "invalid" \
        firewall access-policy add inside accept test-val-err 10.0.0.0/8 999.999.999.999

    # --- Invalid protocol ---
    assert_error "invalid protocol" \
        "invalid" \
        firewall access-policy add inside accept test-val-err 10.0.0.0/8 10.0.0.0/8 \
        -p bogus-proto

    # --- Invalid port ---
    assert_error "port out of range (99999)" \
        "" \
        firewall access-policy add inside accept test-val-err 10.0.0.0/8 10.0.0.0/8 \
        -p tcp --dport 99999

    assert_error "port zero" \
        "" \
        firewall access-policy add inside accept test-val-err 10.0.0.0/8 10.0.0.0/8 \
        -p tcp --dport 0

    assert_error "non-numeric port" \
        "" \
        firewall access-policy add inside accept test-val-err 10.0.0.0/8 10.0.0.0/8 \
        -p tcp --dport abc

    # --- Invalid rule name ---
    local long_name
    long_name=$(python3 -c "print('A'*65)" 2>/dev/null || printf 'A%.0s' $(seq 1 65))
    assert_error "rule name too long (65 chars)" \
        "invalid rule-name" \
        firewall access-policy add inside accept "$long_name" 10.0.0.0/8 10.0.0.0/8

    # --- Unknown filter action (not accept/drop) — cobra shows usage, not error ---
    assert_output_contains "unknown filter action (reject) shows usage" \
        "Available Commands" \
        firewall access-policy add inside reject test-val-err 10.0.0.0/8 10.0.0.0/8

    # --- Missing positional args ---
    assert_error "filter add missing args" \
        "" \
        firewall access-policy add inside accept only-one-arg

    # --- SNAT missing --to-source (via MarkFlagRequired) ---
    assert_error "snat missing --to-source" \
        "required" \
        firewall nat snat add test-val-err 10.0.0.0/8 0.0.0.0/0

    # --- DNAT missing --to-destination (via MarkFlagRequired) ---
    assert_error "dnat missing --to-destination" \
        "required" \
        firewall nat dnat add test-val-err 10.0.0.0/8 0.0.0.0/0

    # --- Invalid ICMPv4 type (unknown subcommand — cobra shows usage, exit 0) ---
    assert_output_contains "invalid icmp4 type shows usage" \
        "Available Commands" \
        firewall icmp4 add input accept bogus-type outside 10.0.0.0/8 test-val-err

    # --- Invalid zone (unknown subcommand under icmp type) — cobra shows usage ---
    assert_output_contains "invalid icmp4 zone shows usage" \
        "Available Commands" \
        firewall icmp4 add input accept echo-request badzone 10.0.0.0/8 test-val-err

    # --- Invalid ICMPv6 type (unknown subcommand — cobra shows usage, exit 0) ---
    assert_output_contains "invalid icmp6 type shows usage" \
        "Available Commands" \
        firewall icmp6 add input accept bogus-v6-type outside fd00::/64 test-val-err

    # --- ICMPv4 type-code validation ---
    assert_error "icmp4 type-code out of range" \
        "invalid ICMP type" \
        firewall icmp4 add input accept type-code 300 outside 10.0.0.0/8 test-val-err

    assert_error "icmp4 type-code non-numeric" \
        "invalid ICMP type" \
        firewall icmp4 add input accept type-code xyz outside 10.0.0.0/8 test-val-err

    cleanup_staging
}

# ---------------------------------------------------------------------------
# 12. Save guard (do NOT actually apply)
# ---------------------------------------------------------------------------
test_save_guard() {
    section "SAVE COMMAND (guard only - no actual apply)"
    cleanup_staging

    assert_output_contains "save with no staging" \
        "No changes to save" \
        firewall save

    # NOTE: We intentionally do NOT test 'firewall save' with staged rules.
    # It would modify live iptables on the device.  Use --live for that.
}

# ---------------------------------------------------------------------------
# 12b. Save + kernel verification (LIVE mode only)
# ---------------------------------------------------------------------------
test_save_and_verify() {
    section "SAVE + KERNEL VERIFICATION (live)"
    cleanup_staging

    # ===== PHASE 1: Stage rules across all categories =====
    local bypass_added=false
    local stage_cmds=(
        "firewall icmp4 add input accept echo-request outside 10.99.0.0/16 tsav-icmp-v4"
        "firewall icmp6 add input accept echo-request outside fd99::/64 tsav-icmp-v6"
        "firewall icmp4 add input accept type-code 3/4 outside 10.99.10.0/24 tsav-icmp-tc"
        "firewall icmp4 add input drop echo-request outside 10.99.11.0/24 tsav-icmp-log --logging"
        "firewall access-policy add inside accept tsav-ap-in 10.99.1.0/24 10.99.2.0/24 -p tcp --dport 8080"
        "firewall access-policy add outside accept tsav-ap-out 0.0.0.0/0 10.99.3.0/24 -p tcp --dport 443"
        "firewall vpn-policy add in deny tsav-vpn-in-deny 10.99.4.0/24 0.0.0.0/0 -p tcp --dport 22"
        "firewall vpn-policy add out deny tsav-vpn-out-deny 10.99.5.0/24 0.0.0.0/0 -p udp --dport 53"
        "firewall vpn-policy add in bypass tsav-vpn-in-bypass 10.99.6.0/24 0.0.0.0/0 -p tcp --dport 80"
        "firewall nat masquerade add tsav-masq 10.99.7.0/24 0.0.0.0/0"
        "firewall nat snat add tsav-snat 10.99.8.0/24 0.0.0.0/0 --to-source 203.0.113.99:9090 -p tcp --dport 80"
        "firewall nat dnat add tsav-dnat 0.0.0.0/0 203.0.113.98 --to-destination 10.99.9.100:8080 -p tcp --dport 8080"
        "firewall save"
        "Y"
    )
    capture_scli_session "${stage_cmds[@]}"
    assert_captured_session_success "save session: apply staged rules"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    # -- ICMPv4 (outside) --
    assert_text_contains "save: stage icmp4 echo-request outside" \
        'Staged new ICMPv4 rule "tsav-icmp-v4"' \
        "$SCLI_SESSION_OUTPUT"

    # -- ICMPv6 (outside) --
    assert_text_contains "save: stage icmp6 echo-request outside" \
        'Staged new ICMPv6 rule "tsav-icmp-v6"' \
        "$SCLI_SESSION_OUTPUT"

    # -- ICMPv4 type-code --
    assert_text_contains "save: stage icmp4 type-code 3/4" \
        'Staged new ICMPv4 rule "tsav-icmp-tc"' \
        "$SCLI_SESSION_OUTPUT"

    # -- ICMPv4 --logging --
    assert_text_contains "save: stage icmp4 echo-request drop --logging" \
        'Staged new ICMPv4 rule "tsav-icmp-log"' \
        "$SCLI_SESSION_OUTPUT"

    # -- Access-policy inside (IPv4) --
    assert_text_contains "save: stage access-policy inside" \
        'Staged new inside access-policy rule "tsav-ap-in"' \
        "$SCLI_SESSION_OUTPUT"

    # -- Access-policy outside (IPv4) --
    assert_text_contains "save: stage access-policy outside" \
        'Staged new outside access-policy rule "tsav-ap-out"' \
        "$SCLI_SESSION_OUTPUT"

    # -- VPN in deny (IPv4) --
    assert_text_contains "save: stage vpn-policy in deny" \
        'Staged new vpn-policy in rule "tsav-vpn-in-deny" (action=deny)' \
        "$SCLI_SESSION_OUTPUT"

    # -- VPN out deny (IPv4) --
    assert_text_contains "save: stage vpn-policy out deny" \
        'Staged new vpn-policy out rule "tsav-vpn-out-deny" (action=deny)' \
        "$SCLI_SESSION_OUTPUT"

    # -- VPN in bypass (may require XFRM scripts — skip gracefully) --
    if printf '%s\n' "$SCLI_SESSION_OUTPUT" | grep -qF 'Staged new vpn-policy in rule "tsav-vpn-in-bypass"'; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  save: stage vpn-policy in bypass\n"
        bypass_added=true
    elif printf '%s\n' "$SCLI_SESSION_OUTPUT" | grep -qi "no such file\|not found\|xfrm"; then
        skip_test "save: stage vpn-policy in bypass" "XFRM scripts not available"
    else
        TOTAL=$((TOTAL + 1)); FAIL=$((FAIL + 1)); FAILURES+=("save: stage vpn-policy in bypass")
        printf "  ${RED}FAIL${NC}  save: stage vpn-policy in bypass\n"
        printf "        output: %s\n" "$SCLI_SESSION_OUTPUT"
    fi

    # -- NAT masquerade --
    assert_text_contains "save: stage nat masquerade" \
        'Staged new NAT masquerade rule "tsav-masq"' \
        "$SCLI_SESSION_OUTPUT"

    # -- NAT SNAT --
    assert_text_contains "save: stage nat snat" \
        'Staged new NAT SNAT rule "tsav-snat"' \
        "$SCLI_SESSION_OUTPUT"

    # -- NAT DNAT --
    assert_text_contains "save: stage nat dnat" \
        'Staged new NAT DNAT rule "tsav-dnat"' \
        "$SCLI_SESSION_OUTPUT"

    # ===== PHASE 2: Save and confirm =====
    assert_text_contains "save: apply all staged rules" \
        "confirmed and saved" \
        "$SCLI_SESSION_OUTPUT"

    # ===== PHASE 3: Verify rules exist in kernel =====
    # Using 'iptables -L <chain> -n' to confirm rules landed in the correct chain.

    # -- IPv4 filter: ICMPv4 --
    assert_iptables_chain_contains "kernel v4: AKITA_ICMP_INPUT_OUTSIDE has tsav-icmp-v4" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-v4"

    # -- IPv4 filter: ICMPv4 type-code 3/4 --
    assert_iptables_chain_contains "kernel v4: AKITA_ICMP_INPUT_OUTSIDE has tsav-icmp-tc" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-tc"

    # -- IPv4 filter: ICMPv4 with logging (should use AKITA_LOG_DROP) --
    assert_iptables_chain_contains "kernel v4: AKITA_ICMP_INPUT_OUTSIDE has tsav-icmp-log" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-log"

    # -- IPv6 filter: ICMPv6 --
    assert_ip6tables_chain_contains "kernel v6: AKITA_ICMP_INPUT_OUTSIDE has tsav-icmp-v6" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-v6"

    # -- IPv4 filter: access-policy --
    assert_iptables_chain_contains "kernel v4: AKITA_FW_INSIDE_FILTER has tsav-ap-in" \
        "AKITA_FW_INSIDE_FILTER" "tsav-ap-in"

    assert_iptables_chain_contains "kernel v4: AKITA_FW_OUTSIDE_FILTER has tsav-ap-out" \
        "AKITA_FW_OUTSIDE_FILTER" "tsav-ap-out"

    # -- IPv4 filter: VPN deny --
    assert_iptables_chain_contains "kernel v4: AKITA_VPN_IN_DENY has tsav-vpn-in-deny" \
        "AKITA_VPN_IN_DENY" "tsav-vpn-in-deny"

    assert_iptables_chain_contains "kernel v4: AKITA_VPN_OUT_DENY has tsav-vpn-out-deny" \
        "AKITA_VPN_OUT_DENY" "tsav-vpn-out-deny"

    # -- IPv4 filter: VPN bypass --
    if $bypass_added; then
        assert_iptables_chain_contains "kernel v4: AKITA_VPN_IN_BYPASS has tsav-vpn-in-bypass" \
            "AKITA_VPN_IN_BYPASS" "tsav-vpn-in-bypass"
        # -- XFRM policy --
        assert_xfrm_contains "kernel: xfrm policy has 10.99.6.0/24" \
            "10.99.6.0/24"
    fi

    # -- NAT table --
    assert_iptables_nat_chain_contains "kernel nat: AKITA_MASQUERADE has tsav-masq" \
        "AKITA_MASQUERADE" "tsav-masq"

    assert_iptables_nat_chain_contains "kernel nat: AKITA_SNAT has tsav-snat" \
        "AKITA_SNAT" "tsav-snat"

    assert_iptables_nat_chain_contains "kernel nat: AKITA_DNAT has tsav-dnat" \
        "AKITA_DNAT" "tsav-dnat"

    # ===== PHASE 4: Delete all rules (staging) =====

    local delete_cmds=(
        "firewall icmp4 del input tsav-icmp-v4"
        "firewall icmp6 del input tsav-icmp-v6"
        "firewall icmp4 del input tsav-icmp-tc"
        "firewall icmp4 del input tsav-icmp-log"
        "firewall access-policy del inside tsav-ap-in"
        "firewall access-policy del outside tsav-ap-out"
        "firewall vpn-policy del in deny tsav-vpn-in-deny"
        "firewall vpn-policy del out deny tsav-vpn-out-deny"
        "firewall nat masquerade del tsav-masq"
        "firewall nat snat del tsav-snat"
        "firewall nat dnat del tsav-dnat"
    )
    if $bypass_added; then
        delete_cmds+=("firewall vpn-policy del in bypass tsav-vpn-in-bypass")
    fi
    delete_cmds+=("firewall save" "Y")
    capture_scli_session "${delete_cmds[@]}"
    assert_captured_session_success "save session: apply deletions"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    assert_text_contains "save: del icmp4 tsav-icmp-v4" \
        'Staged deletion of input ICMPv4 rule "tsav-icmp-v4"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del icmp6 tsav-icmp-v6" \
        'Staged deletion of input ICMPv6 rule "tsav-icmp-v6"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del icmp4 tsav-icmp-tc" \
        'Staged deletion of input ICMPv4 rule "tsav-icmp-tc"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del icmp4 tsav-icmp-log" \
        'Staged deletion of input ICMPv4 rule "tsav-icmp-log"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del access-policy inside tsav-ap-in" \
        'Staged deletion of inside access-policy rule "tsav-ap-in"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del access-policy outside tsav-ap-out" \
        'Staged deletion of outside access-policy rule "tsav-ap-out"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del vpn-policy in deny tsav-vpn-in-deny" \
        'Staged deletion of vpn-policy in rule "tsav-vpn-in-deny"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del vpn-policy out deny tsav-vpn-out-deny" \
        'Staged deletion of vpn-policy out rule "tsav-vpn-out-deny"' \
        "$SCLI_SESSION_OUTPUT"
    if $bypass_added; then
        assert_text_contains "save: del vpn-policy in bypass tsav-vpn-in-bypass" \
            'Staged deletion of vpn-policy in rule "tsav-vpn-in-bypass"' \
            "$SCLI_SESSION_OUTPUT"
    fi
    assert_text_contains "save: del nat masquerade tsav-masq" \
        'Staged deletion of NAT masquerade rule "tsav-masq"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del nat snat tsav-snat" \
        'Staged deletion of NAT SNAT rule "tsav-snat"' \
        "$SCLI_SESSION_OUTPUT"
    assert_text_contains "save: del nat dnat tsav-dnat" \
        'Staged deletion of NAT DNAT rule "tsav-dnat"' \
        "$SCLI_SESSION_OUTPUT"

    # ===== PHASE 5: Save again (apply deletions) =====
    assert_text_contains "save: apply all deletions" \
        "confirmed and saved" \
        "$SCLI_SESSION_OUTPUT"

    # ===== PHASE 6: Verify rules removed from kernel =====

    assert_iptables_chain_not_contains "kernel v4: AKITA_ICMP_INPUT_OUTSIDE no tsav-icmp-v4" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-v4"

    assert_iptables_chain_not_contains "kernel v4: AKITA_ICMP_INPUT_OUTSIDE no tsav-icmp-tc" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-tc"

    assert_iptables_chain_not_contains "kernel v4: AKITA_ICMP_INPUT_OUTSIDE no tsav-icmp-log" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-log"

    assert_ip6tables_chain_not_contains "kernel v6: AKITA_ICMP_INPUT_OUTSIDE no tsav-icmp-v6" \
        "AKITA_ICMP_INPUT_OUTSIDE" "tsav-icmp-v6"

    assert_iptables_chain_not_contains "kernel v4: AKITA_FW_INSIDE_FILTER no tsav-ap-in" \
        "AKITA_FW_INSIDE_FILTER" "tsav-ap-in"

    assert_iptables_chain_not_contains "kernel v4: AKITA_FW_OUTSIDE_FILTER no tsav-ap-out" \
        "AKITA_FW_OUTSIDE_FILTER" "tsav-ap-out"

    assert_iptables_chain_not_contains "kernel v4: AKITA_VPN_IN_DENY no tsav-vpn-in-deny" \
        "AKITA_VPN_IN_DENY" "tsav-vpn-in-deny"

    assert_iptables_chain_not_contains "kernel v4: AKITA_VPN_OUT_DENY no tsav-vpn-out-deny" \
        "AKITA_VPN_OUT_DENY" "tsav-vpn-out-deny"

    if $bypass_added; then
        assert_iptables_chain_not_contains "kernel v4: AKITA_VPN_IN_BYPASS no tsav-vpn-in-bypass" \
            "AKITA_VPN_IN_BYPASS" "tsav-vpn-in-bypass"
        assert_xfrm_not_contains "kernel: xfrm no 10.99.6.0/24" \
            "10.99.6.0/24"
    fi

    assert_iptables_nat_chain_not_contains "kernel nat: AKITA_MASQUERADE no tsav-masq" \
        "AKITA_MASQUERADE" "tsav-masq"

    assert_iptables_nat_chain_not_contains "kernel nat: AKITA_SNAT no tsav-snat" \
        "AKITA_SNAT" "tsav-snat"

    assert_iptables_nat_chain_not_contains "kernel nat: AKITA_DNAT no tsav-dnat" \
        "AKITA_DNAT" "tsav-dnat"

    # ===== PHASE 7: Cleanup =====
    cleanup_staging
}

# ---------------------------------------------------------------------------
# 12c. Save + rollback verification (LIVE mode only)
# ---------------------------------------------------------------------------
test_save_rollback() {
    section "SAVE + ROLLBACK VERIFICATION (live)"
    cleanup_staging

    # ===== PHASE 1: Stage rules across multiple categories =====
    local bypass_added=false
    local stage_cmds=(
        "firewall icmp4 add input accept echo-request outside 10.98.0.0/16 trol-icmp-v4"
        "firewall icmp6 add input accept echo-request outside fd98::/64 trol-icmp-v6"
        "firewall icmp4 add input drop type-code 3/4 outside 10.98.1.0/24 trol-icmp-tc"
        "firewall icmp4 add input accept echo-request outside 10.98.2.0/24 trol-icmp-log --logging"
        "firewall access-policy add inside accept trol-ap-in 10.98.3.0/24 10.98.4.0/24 -p tcp --dport 8080"
        "firewall access-policy add outside accept trol-ap-out 0.0.0.0/0 10.98.5.0/24 -p tcp --dport 443"
        "firewall vpn-policy add in deny trol-vpn-in-deny 10.98.6.0/24 0.0.0.0/0 -p tcp --dport 22"
        "firewall vpn-policy add out deny trol-vpn-out-deny 10.98.7.0/24 0.0.0.0/0 -p udp --dport 53"
        "firewall vpn-policy add in bypass trol-vpn-in-bypass 10.98.8.0/24 0.0.0.0/0 -p tcp --dport 80"
        "firewall nat masquerade add trol-masq 10.98.9.0/24 0.0.0.0/0"
        "firewall nat snat add trol-snat 10.98.10.0/24 0.0.0.0/0 --to-source 203.0.113.98:9090 -p tcp --dport 80"
        "firewall nat dnat add trol-dnat 0.0.0.0/0 203.0.113.97 --to-destination 10.98.11.100:8080 -p tcp --dport 8080"
        "firewall save"
        "N"
    )
    capture_scli_session "${stage_cmds[@]}"
    assert_captured_session_success "rollback session: stage + save + N"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    # ===== PHASE 2: Verify rollback message =====
    assert_text_contains "rollback: rolled back message" \
        "Rolled back firewall changes" \
        "$SCLI_SESSION_OUTPUT"

    # Check if bypass was actually staged (XFRM may not be available)
    if printf '%s\n' "$SCLI_SESSION_OUTPUT" | grep -qF 'Staged new vpn-policy in rule "trol-vpn-in-bypass"'; then
        bypass_added=true
    fi

    # ===== PHASE 3: Verify rules are NOT in kernel after rollback =====

    # -- ICMPv4 --
    assert_iptables_chain_not_contains "rollback: AKITA_ICMP_INPUT_OUTSIDE no trol-icmp-v4" \
        "AKITA_ICMP_INPUT_OUTSIDE" "trol-icmp-v4"

    assert_iptables_chain_not_contains "rollback: AKITA_ICMP_INPUT_OUTSIDE no trol-icmp-tc" \
        "AKITA_ICMP_INPUT_OUTSIDE" "trol-icmp-tc"

    assert_iptables_chain_not_contains "rollback: AKITA_ICMP_INPUT_OUTSIDE no trol-icmp-log" \
        "AKITA_ICMP_INPUT_OUTSIDE" "trol-icmp-log"

    # -- ICMPv6 --
    assert_ip6tables_chain_not_contains "rollback: AKITA_ICMP_INPUT_OUTSIDE no trol-icmp-v6 (v6)" \
        "AKITA_ICMP_INPUT_OUTSIDE" "trol-icmp-v6"

    # -- Access policy --
    assert_iptables_chain_not_contains "rollback: AKITA_FW_INSIDE_FILTER no trol-ap-in" \
        "AKITA_FW_INSIDE_FILTER" "trol-ap-in"

    assert_iptables_chain_not_contains "rollback: AKITA_FW_OUTSIDE_FILTER no trol-ap-out" \
        "AKITA_FW_OUTSIDE_FILTER" "trol-ap-out"

    # -- VPN deny --
    assert_iptables_chain_not_contains "rollback: AKITA_VPN_IN_DENY no trol-vpn-in-deny" \
        "AKITA_VPN_IN_DENY" "trol-vpn-in-deny"

    assert_iptables_chain_not_contains "rollback: AKITA_VPN_OUT_DENY no trol-vpn-out-deny" \
        "AKITA_VPN_OUT_DENY" "trol-vpn-out-deny"

    # -- VPN bypass + XFRM --
    if $bypass_added; then
        assert_iptables_chain_not_contains "rollback: AKITA_VPN_IN_BYPASS no trol-vpn-in-bypass" \
            "AKITA_VPN_IN_BYPASS" "trol-vpn-in-bypass"

        assert_xfrm_not_contains "rollback: xfrm no 10.98.8.0/24" \
            "10.98.8.0/24"
    fi

    # -- NAT --
    assert_iptables_nat_chain_not_contains "rollback: AKITA_MASQUERADE no trol-masq" \
        "AKITA_MASQUERADE" "trol-masq"

    assert_iptables_nat_chain_not_contains "rollback: AKITA_SNAT no trol-snat" \
        "AKITA_SNAT" "trol-snat"

    assert_iptables_nat_chain_not_contains "rollback: AKITA_DNAT no trol-dnat" \
        "AKITA_DNAT" "trol-dnat"

    # ===== PHASE 4: Cleanup =====
    cleanup_staging
}

# ---------------------------------------------------------------------------
# 13. IPSET commands
# ---------------------------------------------------------------------------
test_ipset_commands() {
    section "IPSET COMMANDS"

    # Check if ipset is available
    if ! command -v ipset &>/dev/null; then
        skip_test "ipset show" "ipset command not available"
        skip_test "ipset add/del" "ipset command not available"
        return
    fi

    # --- Show (read-only, always safe) ---
    assert_output_contains "ipset show" \
        "" \
        firewall ipset show || skip_test "ipset show" "ipset show failed"

    # --- Add + show + del + show (restore original state) ---
    local add_output add_exit=0
    add_output=$(scli_run firewall ipset add obj-dns-v4 8.8.8.8) || add_exit=$?

    if echo "$add_output" | grep -qi "error\|not found\|unknown\|no such"; then
        skip_test "ipset add obj-dns-v4 8.8.8.8" "ipset obj-dns-v4 not available"
        skip_test "ipset show after add" "skipped due to add failure"
        skip_test "ipset del obj-dns-v4 8.8.8.8" "skipped due to add failure"
        skip_test "ipset show after del" "skipped due to add failure"
    else
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ipset add obj-dns-v4 8.8.8.8\n"

        # Verify via show
        assert_output_contains "ipset show obj-dns-v4 -> 8.8.8.8 after add" \
            "8.8.8.8" \
            firewall ipset show obj-dns-v4

        # Delete (restore)
        assert_success "ipset del obj-dns-v4 8.8.8.8" \
            "" \
            firewall ipset del obj-dns-v4 8.8.8.8

        # Verify removal via show
        assert_output_not_contains "ipset show obj-dns-v4 -> 8.8.8.8 after del" \
            "8.8.8.8" \
            firewall ipset show obj-dns-v4
    fi

    # --- Invalid ipset name ---
    assert_error "ipset add invalid name" \
        "" \
        firewall ipset add not-managed-ipset 1.2.3.4
}

# ---------------------------------------------------------------------------
# 14. Anti-spoof commands
# ---------------------------------------------------------------------------
test_anti_spoof_commands() {
    section "ANTI-SPOOF COMMANDS"

    local spoof_script="/usr/sbin/ipset-object-init.d/set_anti-spoof-object.sh"

    if [ ! -f "$spoof_script" ]; then
        skip_test "anti-spoof private enable" "script $spoof_script not found"
        skip_test "anti-spoof private disable" "script $spoof_script not found"
        return
    fi

    if [ ! -f "/etc/anti-spoof.conf" ]; then
        skip_test "anti-spoof private enable" "/etc/anti-spoof.conf not found"
        skip_test "anti-spoof private disable" "/etc/anti-spoof.conf not found"
        return
    fi

    # Enable
    assert_success "anti-spoof private enable" \
        "Anti-spoof private ranges enabled" \
        firewall anti-spoof private enable

    # Disable (restore)
    assert_success "anti-spoof private disable" \
        "Anti-spoof private ranges disabled" \
        firewall anti-spoof private disable
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_common_args "$@"
    print_header "Firewall"

    # Clean any leftover staging
    cleanup_staging

    # Run all test sections
    test_show_commands
    test_icmp4_lifecycle
    test_icmp6_lifecycle
    test_icmp4_fwd_lifecycle
    test_icmp6_fwd_lifecycle
    test_icmp4_type_code
    test_icmp6_type_code
    test_icmp_logging
    test_inside_filter_lifecycle
    test_outside_filter_lifecycle
    test_vpn_in_lifecycle
    test_vpn_out_lifecycle
    test_nat_masquerade_lifecycle
    test_nat_snat_lifecycle
    test_nat_dnat_lifecycle
    test_reset_command
    test_validation_errors
    test_save_guard

    # Live save tests (only when --live is passed)
    if $LIVE; then
        test_save_and_verify
        test_save_rollback
    else
        section "SAVE + KERNEL VERIFICATION (skipped, use --live)"
        section "SAVE + ROLLBACK VERIFICATION (skipped, use --live)"
    fi

    test_ipset_commands
    test_anti_spoof_commands

    # Final cleanup
    cleanup_staging

    print_summary
}

main "$@"
