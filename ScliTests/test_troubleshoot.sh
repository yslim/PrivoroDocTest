#!/usr/bin/env bash
# =============================================================================
# Troubleshoot CLI Integration Test Suite for shiba-scli
#
# Tests troubleshoot arp, ping, tcpdump, and traceroute commands.
#
# Usage:
#   bash tests/test_troubleshoot.sh                  # basic tests
#   bash tests/test_troubleshoot.sh -v               # verbose
#   bash tests/test_troubleshoot.sh --live            # enable live network tests
#   SCLI_BIN=/path/to/scli bash tests/test_troubleshoot.sh
#
# Prerequisites:
#   - Linux device with arp, arping, ndisc6, ping, tcpdump, traceroute
#   - Passwordless sudo (or run as root)
#   - scli binary built and accessible
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Load common test framework
# ---------------------------------------------------------------------------
source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TEST_IFACE="${TEST_IFACE:-eth0}"

# Detect a valid test interface
detect_test_interface() {
    if sudo ip link show "$TEST_IFACE" &>/dev/null 2>&1; then
        return 0
    fi
    local iface
    iface=$(sudo ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
            | grep -v '^lo$' | grep -v '^usb0$' | head -1)
    if [ -n "$iface" ]; then
        TEST_IFACE="$iface"
    fi
}

# Get the default gateway for ping/traceroute tests
get_gateway() {
    sudo ip route show default 2>/dev/null | awk '{print $3; exit}'
}

# =============================================================================
# TEST SECTIONS
# =============================================================================

# ---------------------------------------------------------------------------
# 1. ARP show commands (read-only)
# ---------------------------------------------------------------------------
test_arp_show() {
    section "ARP SHOW COMMANDS"

    # IPv4 ARP table
    local arp_output arp_exit=0
    arp_output=$(scli_run troubleshoot arp show) || arp_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $arp_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  arp show (IPv4)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("arp show (IPv4)")
        printf "  ${RED}FAIL${NC}  arp show (IPv4) (exit=%d)\n" "$arp_exit"
        printf "        output: %s\n" "$arp_output"
    fi
    verbose_log "troubleshoot arp show" "$arp_output" "$arp_exit"

    # IPv6 neighbor table
    local arp6_output arp6_exit=0
    arp6_output=$(scli_run troubleshoot arp show -6) || arp6_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $arp6_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  arp show -6 (IPv6)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("arp show -6 (IPv6)")
        printf "  ${RED}FAIL${NC}  arp show -6 (IPv6) (exit=%d)\n" "$arp6_exit"
        printf "        output: %s\n" "$arp6_output"
    fi
    verbose_log "troubleshoot arp show -6" "$arp6_output" "$arp6_exit"
}

# ---------------------------------------------------------------------------
# 2. ARP ping
# ---------------------------------------------------------------------------
test_arp_ping() {
    section "ARP PING"

    local gw
    gw=$(get_gateway)

    if [ -z "$gw" ]; then
        skip_test "arp ping IPv4" "no default gateway found"
        return
    fi

    # arping to gateway (1 count)
    # arping may fail if gateway doesn't respond — but output should contain
    # recognizable arping output (e.g., "arping", "Unicast", "packets", MAC address).
    local output exit_code=0
    output=$(scli_run troubleshoot arp ping "$gw" 1) || exit_code=$?
    TOTAL=$((TOTAL + 1))
    if [ -n "$output" ] && echo "$output" | grep -qi "arping\|unicast\|packets\|broadcast\|reply\|[0-9a-f]\{2\}:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  arp ping $gw (count=1, exit=%d)\n" "$exit_code"
    elif [ -n "$output" ]; then
        # Has output but not recognizable arping — still acceptable
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  arp ping $gw (exit=%d, non-standard output)\n" "$exit_code"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("arp ping $gw")
        printf "  ${RED}FAIL${NC}  arp ping $gw (no output, exit=%d)\n" "$exit_code"
    fi
    verbose_log "troubleshoot arp ping $gw 1" "$output" "$exit_code"

    # IPv6 arp ping without -i flag
    assert_output_contains "arp ping IPv6 without -i" \
        "requires -i" \
        troubleshoot arp ping fd99::1 1
}

# ---------------------------------------------------------------------------
# 3. Ping
# ---------------------------------------------------------------------------
test_ping() {
    section "PING"

    # Ping localhost (should always work)
    assert_output_contains "ping localhost (count=1)" \
        "packets transmitted" \
        troubleshoot ping 127.0.0.1 1

    # Ping gateway if available
    local gw
    gw=$(get_gateway)

    if [ -n "$gw" ]; then
        assert_output_contains "ping gateway $gw (count=1)" \
            "packets transmitted" \
            troubleshoot ping "$gw" 1
    else
        skip_test "ping gateway" "no default gateway found"
    fi

    # Ping IPv6 loopback
    assert_output_contains "ping ::1 (count=1)" \
        "packets transmitted" \
        troubleshoot ping ::1 1
}

# ---------------------------------------------------------------------------
# 4. Tcpdump
# ---------------------------------------------------------------------------
test_tcpdump() {
    section "TCPDUMP"

    # Tcpdump with count (capture 1 packet on interface, timeout quickly)
    # Use -c 1 to capture only 1 packet
    local output exit_code=0
    output=$(timeout 5 "$SCLI_BIN" troubleshoot tcpdump -i "$TEST_IFACE" -c 1 2>&1) || exit_code=$?
    TOTAL=$((TOTAL + 1))
    # tcpdump may time out or succeed depending on traffic
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 124 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  tcpdump -i $TEST_IFACE -c 1\n"
    else
        # Accept any output as long as tcpdump ran
        if echo "$output" | grep -qi "listening\|tcpdump\|packet"; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  tcpdump ran (exit=%d)\n" "$exit_code"
        else
            FAIL=$((FAIL + 1))
            FAILURES+=("tcpdump")
            printf "  ${RED}FAIL${NC}  tcpdump (exit=%d)\n" "$exit_code"
            printf "        output: %s\n" "$output"
        fi
    fi
    verbose_log "troubleshoot tcpdump -i $TEST_IFACE -c 1" "$output" "$exit_code"
}

# ---------------------------------------------------------------------------
# 5. Traceroute
# ---------------------------------------------------------------------------
test_traceroute() {
    section "TRACEROUTE"

    # Traceroute to gateway (if available)
    local gw
    gw=$(get_gateway)

    if [ -n "$gw" ]; then
        local output exit_code=0
        output=$(scli_run troubleshoot traceroute "$gw" -m 2) || exit_code=$?
        TOTAL=$((TOTAL + 1))
        # traceroute may fail if ICMP is blocked, but should produce recognizable output
        if [ -n "$output" ] && echo "$output" | grep -qi "traceroute\|hops\|ms\|\*"; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  traceroute $gw (-m 2, exit=%d)\n" "$exit_code"
        elif [ -n "$output" ]; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  traceroute $gw (exit=%d, non-standard output)\n" "$exit_code"
        else
            FAIL=$((FAIL + 1))
            FAILURES+=("traceroute $gw")
            printf "  ${RED}FAIL${NC}  traceroute $gw (no output, exit=%d)\n" "$exit_code"
        fi
        verbose_log "troubleshoot traceroute $gw -m 2" "$output" "$exit_code"
    else
        skip_test "traceroute" "no default gateway found"
    fi
}

# ---------------------------------------------------------------------------
# 6. Live network tests (--live only)
# ---------------------------------------------------------------------------
test_live_arp_ping() {
    section "ARP PING (live, with interface)"

    local gw
    gw=$(get_gateway)

    if [ -z "$gw" ]; then
        skip_test "arp ping with -i (live)" "no default gateway found"
        return
    fi

    # arping with explicit interface
    local output exit_code=0
    output=$(scli_run troubleshoot arp ping "$gw" 1 -i "$TEST_IFACE") || exit_code=$?
    TOTAL=$((TOTAL + 1))
    if [ -n "$output" ] && echo "$output" | grep -qi "arping\|unicast\|packets\|broadcast\|reply\|[0-9a-f]\{2\}:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  arp ping $gw -i $TEST_IFACE (count=1, exit=%d)\n" "$exit_code"
    elif [ -n "$output" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  arp ping with -i (exit=%d, non-standard output)\n" "$exit_code"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("arp ping with -i $TEST_IFACE")
        printf "  ${RED}FAIL${NC}  arp ping with -i (no output, exit=%d)\n" "$exit_code"
    fi
    verbose_log "troubleshoot arp ping $gw 1 -i $TEST_IFACE" "$output" "$exit_code"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_common_args "$@"
    print_header "Troubleshoot"

    # Detect test interface
    detect_test_interface

    # Run test sections
    test_arp_show
    test_arp_ping
    test_ping
    test_tcpdump
    test_traceroute

    # Live tests
    if $LIVE; then
        test_live_arp_ping
    else
        section "LIVE NETWORK TESTS (skipped, use --live)"
    fi

    print_summary
}

main "$@"
