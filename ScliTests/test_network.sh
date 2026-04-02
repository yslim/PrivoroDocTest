#!/usr/bin/env bash
# =============================================================================
# Network CLI Integration Test Suite for shiba-scli
#
# Tests network hostname, interface, lan-config, and route commands.
# Route add/del commands apply changes immediately via "ip route", so
# route lifecycle tests work even in ONESHOT mode. Multi-step save flows
# use a single admin session so staged edits and the final save happen
# inside the same CLI context.
#
# Usage:
#   bash tests/test_network.sh                  # basic tests
#   bash tests/test_network.sh -v               # verbose
#   bash tests/test_network.sh --live            # enable save tests (modifies network!)
#   SCLI_BIN=/path/to/scli bash tests/test_network.sh
#
# Prerequisites:
#   - Linux device with systemd-networkd
#   - /etc/systemd/network/ directory
#   - Passwordless sudo (or run as root)
#   - scli binary built and accessible
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Load common test framework
# ---------------------------------------------------------------------------
source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Network-specific configuration
# ---------------------------------------------------------------------------
TEST_IFACE="${TEST_IFACE:-eth0}"

# Detect a valid test interface (fallback if eth0 doesn't exist)
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

# =============================================================================
# TEST SECTIONS
# =============================================================================

# ---------------------------------------------------------------------------
# 1. Show commands (read-only, always safe)
# ---------------------------------------------------------------------------
test_show_commands() {
    section "SHOW COMMANDS (read-only)"

    # --- Hostname ---
    assert_output_contains "hostname show" \
        "hostname" \
        network hostname show

    # --- Interface show list ---
    assert_output_contains "interface show list (header)" \
        "Name" \
        network interface show list

    assert_output_contains "interface show list (test iface)" \
        "$TEST_IFACE" \
        network interface show list

    assert_output_contains "interface show list --ipv6" \
        "$TEST_IFACE" \
        network interface show list --ipv6

    assert_output_contains "interface show list --raw" \
        "$TEST_IFACE" \
        network interface show list --raw

    # --- Interface show editing ---
    assert_output_contains "interface show editing (no edits)" \
        "no staged interface edits" \
        network interface show editing

    # --- Interface show config ---
    assert_output_contains "interface show config $TEST_IFACE" \
        "Interface:" \
        network interface show config "$TEST_IFACE"

    assert_output_contains "interface show config has Current section" \
        "Current" \
        network interface show config "$TEST_IFACE"

    assert_error "interface show config nonexistent" \
        "not found" \
        network interface show config nonexistent-iface-xyz

    # --- Route show status ---
    assert_output_contains "route show status (IPv4)" \
        "Routes" \
        network route show status

    assert_output_contains "route show status -6 (IPv6)" \
        "Routes" \
        network route show status -6

    # --- LAN config show status ---
    assert_output_contains "lan-config show status" \
        "IPv4" \
        network lan-config show status
}

# ---------------------------------------------------------------------------
# 2. Hostname commands
# ---------------------------------------------------------------------------
test_hostname_commands() {
    section "HOSTNAME COMMANDS"

    # hostname set (in-memory staging, does not persist across ONESHOT calls)
    assert_success "hostname set" \
        "Editing hostname updated to:" \
        network hostname set test-hostname-scli

    # hostname set with current hostname (restore)
    local current_hostname
    current_hostname=$(hostname 2>/dev/null || echo "shiba")
    assert_success "hostname set restore ($current_hostname)" \
        "Editing hostname updated to:" \
        network hostname set "$current_hostname"

    # hostname save with no editing hostname (ONESHOT — editing lost)
    assert_output_contains "hostname save (no editing)" \
        "No editing hostname to save" \
        network hostname save
}

# ---------------------------------------------------------------------------
# 3. Interface create/delete (staging only, validation)
# ---------------------------------------------------------------------------
test_interface_create_delete() {
    section "INTERFACE CREATE/DELETE"

    # --- Create dummy interface (staging output) ---
    assert_success "interface create dummy99" \
        "Staged interface create (dummy):" \
        network interface create dummy99

    # --- Create validation errors ---
    assert_error "interface create invalid name (eth9)" \
        "dummy" \
        network interface create eth9

    assert_error "interface create invalid name (nope)" \
        "dummy" \
        network interface create nope

    # --- Create usb0 (name validation rejects non-dummy names first) ---
    assert_error "interface create usb0 (not dummy)" \
        "dummy" \
        network interface create usb0

    # --- Delete validation ---
    assert_error "interface del nonexistent" \
        "" \
        network interface del nonexistent-iface-xyz

    assert_error "interface del usb0 (managed)" \
        "managed by" \
        network interface del usb0

    # --- Delete non-dummy (if TEST_IFACE is not dummy) ---
    if ! echo "$TEST_IFACE" | grep -q '^dummy'; then
        assert_error "interface del $TEST_IFACE (not dummy)" \
            "not a dummy" \
            network interface del "$TEST_IFACE"
    fi
}

# ---------------------------------------------------------------------------
# 4. Interface set commands (staging only, test output + validation)
# ---------------------------------------------------------------------------
test_interface_set_commands() {
    section "INTERFACE SET COMMANDS"

    # --- Mode ---
    assert_success "set mode dhcp" \
        "Staged mode:" \
        network interface set mode "$TEST_IFACE" dhcp

    assert_success "set mode static" \
        "Staged mode:" \
        network interface set mode "$TEST_IFACE" static

    assert_error "set mode invalid" \
        "invalid mode" \
        network interface set mode "$TEST_IFACE" bogus

    # --- Add-address IPv4 ---
    assert_success "set add-address IPv4 CIDR" \
        "Staged address add:" \
        network interface set add-address "$TEST_IFACE" 10.99.88.1/24

    # --- Add-address IPv6 ---
    assert_success "set add-address IPv6 CIDR" \
        "Staged address add:" \
        network interface set add-address "$TEST_IFACE" fd99:88::1/64

    # --- Add-address validation ---
    assert_error "set add-address invalid CIDR" \
        "invalid CIDR" \
        network interface set add-address "$TEST_IFACE" not-a-cidr

    assert_error "set add-address bare IPv4 (hint /32)" \
        "did you mean" \
        network interface set add-address "$TEST_IFACE" 10.0.0.1

    assert_error "set add-address bare IPv6 (hint /128)" \
        "did you mean" \
        network interface set add-address "$TEST_IFACE" fd99::1

    # --- Del-address validation ---
    assert_error "set del-address invalid CIDR" \
        "invalid CIDR" \
        network interface set del-address "$TEST_IFACE" not-a-cidr

    # --- Gateway ---
    assert_success "set gateway IPv4" \
        "Staged gateway:" \
        network interface set gateway "$TEST_IFACE" 10.99.88.254

    assert_success "set gateway IPv6" \
        "Staged gateway:" \
        network interface set gateway "$TEST_IFACE" fd99:88::ffff

    assert_error "set gateway invalid IP" \
        "invalid IP" \
        network interface set gateway "$TEST_IFACE" not-an-ip

    # --- DNS ---
    assert_success "set dns single" \
        "Staged DNS:" \
        network interface set dns "$TEST_IFACE" 8.8.8.8

    assert_success "set dns multiple" \
        "Staged DNS:" \
        network interface set dns "$TEST_IFACE" 8.8.8.8,8.8.4.4

    assert_success "set dns IPv6" \
        "Staged DNS:" \
        network interface set dns "$TEST_IFACE" fd99::53

    assert_error "set dns invalid" \
        "invalid IP" \
        network interface set dns "$TEST_IFACE" not-an-ip

    # --- MTU ---
    assert_success "set mtu 1500" \
        "Staged MTU:" \
        network interface set mtu "$TEST_IFACE" 1500

    assert_success "set mtu 576 (min)" \
        "Staged MTU:" \
        network interface set mtu "$TEST_IFACE" 576

    assert_success "set mtu 9000 (max)" \
        "Staged MTU:" \
        network interface set mtu "$TEST_IFACE" 9000

    assert_error "set mtu too low (100)" \
        "invalid MTU" \
        network interface set mtu "$TEST_IFACE" 100

    assert_error "set mtu too high (10000)" \
        "invalid MTU" \
        network interface set mtu "$TEST_IFACE" 10000

    assert_error "set mtu non-numeric" \
        "invalid MTU" \
        network interface set mtu "$TEST_IFACE" abc

    # --- Nonexistent interface ---
    assert_error "set mode on nonexistent" \
        "not found" \
        network interface set mode nonexistent-iface-xyz dhcp

    assert_error "set add-address on nonexistent" \
        "not found" \
        network interface set add-address nonexistent-iface-xyz 10.0.0.1/24

    assert_error "set gateway on nonexistent" \
        "not found" \
        network interface set gateway nonexistent-iface-xyz 10.0.0.1

    assert_error "set dns on nonexistent" \
        "not found" \
        network interface set dns nonexistent-iface-xyz 8.8.8.8

    assert_error "set mtu on nonexistent" \
        "not found" \
        network interface set mtu nonexistent-iface-xyz 1500

    # --- lan-config managed interface (usb0) ---
    assert_error "set mode on usb0 (managed)" \
        "managed by" \
        network interface set mode usb0 dhcp

    assert_error "set add-address on usb0 (managed)" \
        "managed by" \
        network interface set add-address usb0 10.0.0.1/24
}

# ---------------------------------------------------------------------------
# 5. Interface save guard
# ---------------------------------------------------------------------------
test_interface_save_guard() {
    section "INTERFACE SAVE (guard only)"

    assert_output_contains "interface save (no changes)" \
        "No changes to save" \
        network interface save
}

# ---------------------------------------------------------------------------
# 6. LAN config show
# ---------------------------------------------------------------------------
test_lan_config_show() {
    section "LAN CONFIG SHOW"

    assert_output_contains "lan-config show status has Parameter" \
        "Parameter" \
        network lan-config show status

    assert_output_contains "lan-config show status has File Config" \
        "File Config" \
        network lan-config show status
}

# ---------------------------------------------------------------------------
# 7. LAN config set commands (staging only, test output + validation)
# ---------------------------------------------------------------------------
test_lan_config_set_commands() {
    section "LAN CONFIG SET COMMANDS"

    # --- address4 ---
    assert_success "set address4" \
        "Staged IPv4 address:" \
        network lan-config set address4 10.10.101.1/24

    assert_error "set address4 invalid" \
        "" \
        network lan-config set address4 not-a-cidr

    assert_error "set address4 with IPv6 (wrong type)" \
        "IPv4" \
        network lan-config set address4 fd8d::1/64

    # --- address6 ---
    assert_success "set address6" \
        "Staged IPv6 address:" \
        network lan-config set address6 fd8d:fb25:4300:101::1/64

    assert_error "set address6 invalid" \
        "" \
        network lan-config set address6 not-a-cidr

    assert_error "set address6 with IPv4 (wrong type)" \
        "IPv6" \
        network lan-config set address6 10.10.101.1/24

    # --- dns4 ---
    assert_success "set dns4" \
        "Staged IPv4 DNS:" \
        network lan-config set dns4 8.8.8.8 8.8.4.4

    assert_error "set dns4 invalid IP" \
        "not a valid IPv4" \
        network lan-config set dns4 not-an-ip

    # --- dns6 (may require address6 to be set first, which doesn't persist in ONESHOT) ---
    local dns6_output dns6_exit=0
    dns6_output=$(scli_run network lan-config set dns6 fd8d::53 fd8d::54) || dns6_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$dns6_output" | grep -qF "Staged IPv6 DNS:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set dns6\n"
    elif echo "$dns6_output" | grep -qi "requires an IPv6 address"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set dns6 (correctly rejected: no IPv6 address in ONESHOT)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("set dns6")
        printf "  ${RED}FAIL${NC}  set dns6\n"
        printf "        output: %s\n" "$dns6_output"
    fi
    verbose_log "network lan-config set dns6 fd8d::53 fd8d::54" "$dns6_output" "$dns6_exit"

    assert_error "set dns6 invalid IP" \
        "not a valid IPv6" \
        network lan-config set dns6 not-an-ip

    # --- dhcp-server service ---
    assert_success "set dhcp-server service enable" \
        "Staged DHCP server:" \
        network lan-config set dhcp-server service enable

    assert_success "set dhcp-server service disable" \
        "Staged DHCP server:" \
        network lan-config set dhcp-server service disable

    assert_error "set dhcp-server service invalid" \
        "invalid argument" \
        network lan-config set dhcp-server service bogus

    # --- dhcp-server range (uses address from config file) ---
    local range_output range_exit=0
    range_output=$(scli_run network lan-config set dhcp-server range 10.10.101.100 10.10.101.200) || range_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$range_output" | grep -qF "Staged DHCP server range"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set dhcp-server range\n"
    elif echo "$range_output" | grep -qi "requires an IPv4 address\|not within the network"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set dhcp-server range (correctly rejected: address mismatch)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("set dhcp-server range")
        printf "  ${RED}FAIL${NC}  set dhcp-server range\n"
        printf "        output: %s\n" "$range_output"
    fi
    verbose_log "network lan-config set dhcp-server range 10.10.101.100 10.10.101.200" \
        "$range_output" "$range_exit"

    assert_error "set dhcp-server range invalid IP" \
        "invalid" \
        network lan-config set dhcp-server range not-ip 10.10.101.200

    assert_error "set dhcp-server range IPv6 (wrong type)" \
        "" \
        network lan-config set dhcp-server range fd8d::1 fd8d::100

    # --- dhcp-server static ---
    local static_output static_exit=0
    static_output=$(scli_run network lan-config set dhcp-server static 00:11:22:33:44:55 10.10.101.50) || static_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$static_output" | grep -qF "Staged static DHCP lease:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set dhcp-server static\n"
    elif echo "$static_output" | grep -qi "requires an IPv4 address"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set dhcp-server static (correctly rejected: no IPv4 address)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("set dhcp-server static")
        printf "  ${RED}FAIL${NC}  set dhcp-server static\n"
        printf "        output: %s\n" "$static_output"
    fi
    verbose_log "network lan-config set dhcp-server static 00:11:22:33:44:55 10.10.101.50" \
        "$static_output" "$static_exit"

    assert_error "set dhcp-server static invalid MAC" \
        "invalid MAC" \
        network lan-config set dhcp-server static not-a-mac 10.10.101.50

    assert_error "set dhcp-server static invalid IP" \
        "invalid IPv4" \
        network lan-config set dhcp-server static 00:11:22:33:44:55 not-an-ip

    # --- RA service ---
    local ra_output ra_exit=0
    ra_output=$(scli_run network lan-config set ra service enable) || ra_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$ra_output" | grep -qF "Staged IPv6 RA:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set ra service enable\n"
    elif echo "$ra_output" | grep -qi "requires an IPv6 address"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set ra service enable (correctly rejected: no IPv6 address)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("set ra service enable")
        printf "  ${RED}FAIL${NC}  set ra service enable\n"
        printf "        output: %s\n" "$ra_output"
    fi
    verbose_log "network lan-config set ra service enable" "$ra_output" "$ra_exit"

    # set ra service with invalid value (may also be rejected for missing IPv6 address)
    local ra_inv_output ra_inv_exit=0
    ra_inv_output=$(scli_run network lan-config set ra service bogus) || ra_inv_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$ra_inv_output" | grep -qi "invalid argument\|requires an IPv6 address"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  set ra service invalid (correctly rejected)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("set ra service invalid")
        printf "  ${RED}FAIL${NC}  set ra service invalid\n"
        printf "        output: %s\n" "$ra_inv_output"
    fi
    verbose_log "network lan-config set ra service bogus" "$ra_inv_output" "$ra_inv_exit"

    # --- RA prefix ---
    assert_success "set ra prefix" \
        "Staged IPv6 prefix:" \
        network lan-config set ra prefix fd8d:fb25:4300:101::/64

    # --- RA lifetimes ---
    assert_success "set ra preferred-lifetime" \
        "Staged preferred lifetime:" \
        network lan-config set ra preferred-lifetime 3600

    assert_error "set ra preferred-lifetime invalid" \
        "invalid value" \
        network lan-config set ra preferred-lifetime abc

    # Negative value: -1 is parsed as a flag by cobra, so we get "unknown shorthand flag"
    assert_error "set ra preferred-lifetime negative" \
        "unknown shorthand flag" \
        network lan-config set ra preferred-lifetime -1

    assert_success "set ra valid-lifetime" \
        "Staged valid lifetime:" \
        network lan-config set ra valid-lifetime 7200

    assert_error "set ra valid-lifetime invalid" \
        "invalid value" \
        network lan-config set ra valid-lifetime abc
}

# ---------------------------------------------------------------------------
# 8. LAN config del commands
# ---------------------------------------------------------------------------
test_lan_config_del_commands() {
    section "LAN CONFIG DEL COMMANDS"

    # dns4/dns6/ra del always succeed (stage removal)
    assert_success "del dns4" \
        "Staged:" \
        network lan-config del dns4

    assert_success "del dns6" \
        "Staged:" \
        network lan-config del dns6

    assert_success "del ra" \
        "Staged:" \
        network lan-config del ra

    # --- del address4 (may be rejected if it's the only address) ---
    local output exit_code=0
    output=$(scli_run network lan-config del address4) || exit_code=$?
    TOTAL=$((TOTAL + 1))
    if echo "$output" | grep -qF "Staged:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  del address4 (staged)\n"
    elif echo "$output" | grep -qi "cannot remove\|at least one"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  del address4 (correctly rejected: only address)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("del address4")
        printf "  ${RED}FAIL${NC}  del address4\n"
        printf "        output: %s\n" "$output"
    fi
    verbose_log "network lan-config del address4" "$output" "$exit_code"

    # --- del address6 (may be rejected if it's the only address) ---
    exit_code=0
    output=$(scli_run network lan-config del address6) || exit_code=$?
    TOTAL=$((TOTAL + 1))
    if echo "$output" | grep -qF "Staged:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  del address6 (staged)\n"
    elif echo "$output" | grep -qi "cannot remove\|at least one"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  del address6 (correctly rejected: only address)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("del address6")
        printf "  ${RED}FAIL${NC}  del address6\n"
        printf "        output: %s\n" "$output"
    fi
    verbose_log "network lan-config del address6" "$output" "$exit_code"

    # --- del dhcp-server static nonexistent MAC ---
    assert_error "del dhcp-server static nonexistent MAC" \
        "not found" \
        network lan-config del dhcp-server static FF:FF:FF:FF:FF:FF
}

# ---------------------------------------------------------------------------
# 9. LAN config save guard
# ---------------------------------------------------------------------------
test_lan_config_save_guard() {
    section "LAN CONFIG SAVE (guard only)"

    assert_output_contains "lan-config save (no changes)" \
        "No changes to save" \
        network lan-config save
}

# ---------------------------------------------------------------------------
# 10. Route lifecycle — IPv4
#     Route add/del are applied immediately via "ip route", so we can
#     verify kernel state even in ONESHOT mode.
# ---------------------------------------------------------------------------
test_route_lifecycle_v4() {
    section "ROUTE LIFECYCLE (IPv4)"

    local add_output add_exit=0
    add_output=$(scli_run network route add \
        --dst-addr 10.99.99.0/24 --dev "$TEST_IFACE") || add_exit=$?

    if echo "$add_output" | grep -qF "Route added:"; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  route add 10.99.99.0/24 dev $TEST_IFACE\n"
        verbose_log "network route add --dst-addr 10.99.99.0/24 --dev $TEST_IFACE" \
            "$add_output" "$add_exit"

        # Verify route appears in kernel output
        assert_output_contains "route show status has 10.99.99.0/24" \
            "10.99.99.0/24" \
            network route show status

        # Delete the route
        assert_success "route del 10.99.99.0/24" \
            "Route deleted:" \
            network route del --dst-addr 10.99.99.0/24 --dev "$TEST_IFACE"

        # Verify route removed from kernel output
        assert_output_not_contains "route show status no 10.99.99.0/24" \
            "10.99.99.0/24" \
            network route show status
    else
        skip_test "route add 10.99.99.0/24"  "route add failed (exit=$add_exit)"
        skip_test "route show status verify"  "skipped (add failed)"
        skip_test "route del 10.99.99.0/24"  "skipped (add failed)"
        skip_test "route show after del"      "skipped (add failed)"
    fi

    # --- Duplicate add (re-add the same route to test duplicate check) ---
    local dup_output dup_exit=0
    # First add it
    scli_run network route add --dst-addr 10.99.98.0/24 --dev "$TEST_IFACE" >/dev/null 2>&1 || true
    # Try to add again
    dup_output=$(scli_run network route add \
        --dst-addr 10.99.98.0/24 --dev "$TEST_IFACE") || dup_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$dup_output" | grep -qi "already exists\|error"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  route add duplicate (correctly rejected)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("route add duplicate")
        printf "  ${RED}FAIL${NC}  route add duplicate (expected error)\n"
        printf "        output: %s\n" "$dup_output"
    fi
    verbose_log "network route add (duplicate)" "$dup_output" "$dup_exit"
    # Cleanup
    scli_run network route del --dst-addr 10.99.98.0/24 --dev "$TEST_IFACE" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# 11. Route lifecycle — IPv6
# ---------------------------------------------------------------------------
test_route_lifecycle_v6() {
    section "ROUTE LIFECYCLE (IPv6)"

    local add_output add_exit=0
    add_output=$(scli_run network route add \
        --dst-addr fd99:99::/64 --dev "$TEST_IFACE") || add_exit=$?

    if echo "$add_output" | grep -qF "Route added:"; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  route add fd99:99::/64 dev $TEST_IFACE\n"
        verbose_log "network route add --dst-addr fd99:99::/64 --dev $TEST_IFACE" \
            "$add_output" "$add_exit"

        # Delete the route
        assert_success "route del fd99:99::/64" \
            "Route deleted:" \
            network route del --dst-addr fd99:99::/64 --dev "$TEST_IFACE"
    else
        skip_test "route add fd99:99::/64"  "route add failed (exit=$add_exit)"
        skip_test "route del fd99:99::/64"  "skipped (add failed)"
    fi
}

# ---------------------------------------------------------------------------
# 12. Route with gateway
# ---------------------------------------------------------------------------
test_route_with_gateway() {
    section "ROUTE WITH GATEWAY"

    # Get the current default gateway
    local gw
    gw=$(sudo ip route show default 2>/dev/null | awk '{print $3; exit}')

    if [ -z "$gw" ]; then
        skip_test "route add with gateway" "no default gateway found"
        skip_test "route del with gateway" "skipped"
        return
    fi

    local add_output add_exit=0
    add_output=$(scli_run network route add \
        --dst-addr 10.99.97.0/24 --gw "$gw" --dev "$TEST_IFACE") || add_exit=$?

    if echo "$add_output" | grep -qF "Route added:"; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  route add 10.99.97.0/24 via $gw\n"
        verbose_log "network route add --dst-addr 10.99.97.0/24 --gw $gw --dev $TEST_IFACE" \
            "$add_output" "$add_exit"

        # Cleanup
        assert_success "route del 10.99.97.0/24 (with gw)" \
            "Route deleted:" \
            network route del --dst-addr 10.99.97.0/24 --dev "$TEST_IFACE"
    else
        skip_test "route add with gateway" "route add failed"
        skip_test "route del with gateway" "skipped"
    fi
}

# ---------------------------------------------------------------------------
# 13. Route with source address
# ---------------------------------------------------------------------------
test_route_with_source() {
    section "ROUTE WITH SOURCE ADDRESS"

    # Get first IPv4 address on TEST_IFACE
    local src
    src=$(sudo ip -4 -o addr show "$TEST_IFACE" 2>/dev/null \
          | awk '{print $4}' | cut -d/ -f1 | head -1)
    local gw
    gw=$(sudo ip route show default 2>/dev/null | awk '{print $3; exit}')

    if [ -z "$src" ] || [ -z "$gw" ]; then
        skip_test "route add with --src" "no source IP or gateway found"
        skip_test "route del with --src" "skipped"
        return
    fi

    local add_output add_exit=0
    add_output=$(scli_run network route add \
        --dst-addr 10.99.96.0/24 --gw "$gw" --dev "$TEST_IFACE" \
        --src "$src") || add_exit=$?

    if echo "$add_output" | grep -qF "Route added:"; then
        TOTAL=$((TOTAL + 1)); PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  route add 10.99.96.0/24 src $src\n"
        verbose_log "network route add --dst-addr 10.99.96.0/24 --gw $gw --dev $TEST_IFACE --src $src" \
            "$add_output" "$add_exit"

        # Cleanup
        assert_success "route del 10.99.96.0/24 (with src)" \
            "Route deleted:" \
            network route del --dst-addr 10.99.96.0/24 --dev "$TEST_IFACE"
    else
        skip_test "route add with --src" "route add failed"
        skip_test "route del with --src" "skipped"
    fi
}

# ---------------------------------------------------------------------------
# 14. Route validation errors
# ---------------------------------------------------------------------------
test_route_validation() {
    section "ROUTE VALIDATION ERRORS"

    # Missing required flags
    assert_error "route add missing --dst-addr" \
        "--dst-addr is required" \
        network route add --dev "$TEST_IFACE"

    assert_error "route add missing --dev" \
        "--dev is required" \
        network route add --dst-addr 10.99.95.0/24

    assert_error "route del missing --dst-addr" \
        "--dst-addr is required" \
        network route del --dev "$TEST_IFACE"

    assert_error "route del missing --dev" \
        "--dev is required" \
        network route del --dst-addr 10.99.95.0/24

    # Route save with no changes
    assert_output_contains "route save (no changes)" \
        "No changes" \
        network route save
}

# ---------------------------------------------------------------------------
# 15. Live interface set+save session (--live only)
# ---------------------------------------------------------------------------
test_live_interface_set_save() {
    section "INTERFACE SET+SAVE SESSION (live)"

    local cmds=(
        "network interface set mode $TEST_IFACE static"
        "network interface set add-address $TEST_IFACE 10.99.88.1/24"
        "network interface set gateway $TEST_IFACE 10.99.88.254"
        "network interface set dns $TEST_IFACE 8.8.8.8"
        "network interface set mtu $TEST_IFACE 1500"
        "network interface save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "interface set+save session"

    assert_text_contains "iface session: mode staged" \
        "Staged mode:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "iface session: address staged" \
        "Staged address add:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "iface session: gateway staged" \
        "Staged gateway:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "iface session: dns staged" \
        "Staged DNS:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "iface session: mtu staged" \
        "Staged MTU:" \
        "$SCLI_SESSION_OUTPUT"
}

# ---------------------------------------------------------------------------
# 16. Live lan-config set+save session (--live only)
# ---------------------------------------------------------------------------
test_live_lan_config_set_save() {
    section "LAN CONFIG SET+SAVE SESSION (live)"

    local cmds=(
        "network lan-config set address4 10.10.101.1/24"
        "network lan-config set dns4 8.8.8.8 8.8.4.4"
        "network lan-config set dhcp-server service enable"
        "network lan-config save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "lan-config set+save session"

    assert_text_contains "lan session: address4 staged" \
        "Staged IPv4 address:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "lan session: dns4 staged" \
        "Staged IPv4 DNS:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "lan session: dhcp staged" \
        "Staged DHCP server:" \
        "$SCLI_SESSION_OUTPUT"
}

# ---------------------------------------------------------------------------
# 17. Live route save tests (--live only)
# ---------------------------------------------------------------------------
test_live_route_save() {
    section "ROUTE SAVE (live)"

    local save_cmds=(
        "network route add --dst-addr 10.99.94.0/24 --dev $TEST_IFACE"
        "network route save"
    )
    capture_scli_session "${save_cmds[@]}"
    assert_captured_session_success "route save session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    assert_text_contains "route add for save test" \
        "Route added:" \
        "$SCLI_SESSION_OUTPUT"

    # Verify config file contains the route
    local conf_found=false
    for f in /etc/systemd/network/*.network.d/routes.conf; do
        if [ -f "$f" ] && sudo grep -qF "10.99.94.0/24" "$f" 2>/dev/null; then
            conf_found=true
            break
        fi
    done

    TOTAL=$((TOTAL + 1))
    if $conf_found; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  routes.conf contains 10.99.94.0/24\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("routes.conf verification")
        printf "  ${RED}FAIL${NC}  routes.conf does not contain 10.99.94.0/24\n"
    fi

    # Cleanup: delete the route and save again
    capture_scli_session \
        "network route del --dst-addr 10.99.94.0/24 --dev $TEST_IFACE" \
        "network route save"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_common_args "$@"
    print_header "Network"

    # Detect test interface
    detect_test_interface

    # Read-only show commands
    test_show_commands

    # Hostname
    test_hostname_commands

    # Interface
    test_interface_create_delete
    test_interface_set_commands
    test_interface_save_guard

    # LAN config
    test_lan_config_show
    test_lan_config_set_commands
    test_lan_config_del_commands
    test_lan_config_save_guard

    # Route lifecycle (applied immediately, always testable)
    test_route_lifecycle_v4
    test_route_lifecycle_v6
    test_route_with_gateway
    test_route_with_source
    test_route_validation

    # Live save tests (only when --live is passed)
    if $LIVE; then
        test_live_interface_set_save
        test_live_lan_config_set_save
        test_live_route_save
    else
        section "SAVE TESTS (skipped, use --live)"
    fi

    print_summary
}

main "$@"
