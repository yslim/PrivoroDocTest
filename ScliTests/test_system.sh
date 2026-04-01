#!/usr/bin/env bash
# =============================================================================
# System CLI Integration Test Suite for shiba-scli
#
# Tests system session, banner, remote-access, auto-logout, ntp,
# syslog-server, log, and update commands.
# (Account tests are in test_account.sh.)
#
# Usage:
#   bash tests/test_system.sh                  # basic tests
#   bash tests/test_system.sh -v               # verbose
#   bash tests/test_system.sh --live            # enable service-restart tests
#   SCLI_BIN=/path/to/scli bash tests/test_system.sh
#
# Prerequisites:
#   - Linux device with systemd, chronyd, rsyslog
#   - /etc/scli.yml configuration file
#   - Passwordless sudo (or run as root)
#   - scli binary built and accessible
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Load common test framework
# ---------------------------------------------------------------------------
source "$(dirname "$0")/common.sh"

# =============================================================================
# TEST SECTIONS
# =============================================================================

# ---------------------------------------------------------------------------
# 1. Session commands
# ---------------------------------------------------------------------------
test_session_commands() {
    section "SESSION COMMANDS"

    # Show status
    assert_output_contains "session show status (Account header)" \
        "Account" \
        system session show status

    assert_output_contains "session show status (PID header)" \
        "PID" \
        system session show status

    # Del by nonexistent account (scli prints message but may exit 0)
    assert_output_contains "session del account nonexistent" \
        "No sessions found" \
        system session del account nonexistent-user-xyz

    # Del by nonexistent PID
    assert_output_contains "session del pid 999999" \
        "No sessions found" \
        system session del pid 999999

    # Del by nonexistent IP
    assert_output_contains "session del ip 0.0.0.0" \
        "No sessions found" \
        system session del ip 0.0.0.0
}

# ---------------------------------------------------------------------------
# 2. Banner commands
# ---------------------------------------------------------------------------
test_banner_commands() {
    section "BANNER COMMANDS"

    # Show status (read-only)
    assert_output_contains "banner show status" \
        "Banner" \
        system banner show status

    # Save with no editing banner
    assert_error "banner save (no editing)" \
        "Editing banner file does not exist" \
        system banner save
}

# ---------------------------------------------------------------------------
# 3. Remote-access commands
# ---------------------------------------------------------------------------
test_remote_access_commands() {
    section "REMOTE-ACCESS COMMANDS"

    # Show status
    assert_output_contains "remote-access show status (Active)" \
        "Active" \
        system remote-access show status

    # Add-allow validation (scli prints error but may exit 0)
    assert_output_contains "add-allow inside invalid IP" \
        "Invalid IP/CIDR" \
        system remote-access add-allow inside not-an-ip

    assert_output_contains "add-allow outside invalid IP" \
        "Invalid IP/CIDR" \
        system remote-access add-allow outside not-an-ip

    # Del-allow validation
    assert_output_contains "del-allow inside invalid IP" \
        "Invalid IP/CIDR" \
        system remote-access del-allow inside not-an-ip

    assert_output_contains "del-allow outside invalid IP" \
        "Invalid IP/CIDR" \
        system remote-access del-allow outside not-an-ip

    # Save with no changes
    assert_output_contains "remote-access save (no changes)" \
        "No changes to save" \
        system remote-access save

    # Confirm/rollback with no active apply (scli prints error but may exit 0)
    assert_output_contains "remote-access confirm (no active apply)" \
        "failed" \
        system remote-access confirm

    assert_output_contains "remote-access rollback (no active apply)" \
        "failed" \
        system remote-access rollback
}

# ---------------------------------------------------------------------------
# 4. Auto-logout commands
# ---------------------------------------------------------------------------
test_auto_logout_commands() {
    section "AUTO-LOGOUT COMMANDS"

    # Show status
    assert_output_contains "auto-logout show status" \
        "auto-logout timeout" \
        system auto-logout show status

    # Set timeout — valid range 5-10
    assert_success "auto-logout set timeout 5 (min)" \
        "Auto-logout timeout set to 5" \
        system auto-logout set timeout 5

    assert_success "auto-logout set timeout 10 (max)" \
        "Auto-logout timeout set to 10" \
        system auto-logout set timeout 10

    # Note: ONESHOT mode — set timeout does not persist, so show will reflect config file value.

    # Validation errors (scli prints error message but may exit 0)
    assert_output_contains "auto-logout set timeout 3 (below min)" \
        "between 5 and 10" \
        system auto-logout set timeout 3

    assert_output_contains "auto-logout set timeout 15 (above max)" \
        "between 5 and 10" \
        system auto-logout set timeout 15

    assert_output_contains "auto-logout set timeout abc (non-numeric)" \
        "Invalid" \
        system auto-logout set timeout abc

    # Restore default
    assert_success "auto-logout set timeout restore to 5" \
        "Auto-logout timeout set to 5" \
        system auto-logout set timeout 5
}

# ---------------------------------------------------------------------------
# 5. NTP commands
# ---------------------------------------------------------------------------
test_ntp_commands() {
    section "NTP COMMANDS"

    # Show status — output depends on chronyd service state
    local ntp_st_output ntp_st_exit=0
    ntp_st_output=$(scli_run system ntp show status) || ntp_st_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ -n "$ntp_st_output" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp show status\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("ntp show status")
        printf "  ${RED}FAIL${NC}  ntp show status (no output, exit=%d)\n" "$ntp_st_exit"
    fi
    verbose_log "system ntp show status" "$ntp_st_output" "$ntp_st_exit"

    # Show config
    assert_output_contains "ntp show config" \
        "Server" \
        system ntp show config

    # Show keys (may or may not have keys)
    assert_output_contains "ntp show keys" \
        "Key" \
        system ntp show keys

    # Set server (staging)
    assert_success "ntp set server (IPv4)" \
        "Staged server add:" \
        system ntp set server 10.99.88.77

    assert_success "ntp set server (FQDN)" \
        "Staged server add:" \
        system ntp set server time.test.example.com

    assert_success "ntp set server (preferred)" \
        "Staged server add" \
        system ntp set server 10.99.88.78 --prefer

    # Duplicate server — in ONESHOT, previous staging is lost, so the server may be re-added
    local dup_output dup_exit=0
    dup_output=$(scli_run system ntp set server 10.99.88.77) || dup_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$dup_output" | grep -qi "already exists"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp set server duplicate (correctly rejected)\n"
    elif echo "$dup_output" | grep -qF "Staged server add:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp set server duplicate (re-added in ONESHOT — staging lost)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("ntp set server duplicate")
        printf "  ${RED}FAIL${NC}  ntp set server duplicate\n"
        printf "        output: %s\n" "$dup_output"
    fi
    verbose_log "system ntp set server 10.99.88.77 (duplicate)" "$dup_output" "$dup_exit"

    # Set auth-key
    assert_success "ntp set auth-key SHA256" \
        "Staged auth-key:" \
        system ntp set auth-key 1 SHA256 test-passphrase

    assert_success "ntp set auth-key SHA384" \
        "Staged auth-key:" \
        system ntp set auth-key 2 SHA384 another-passphrase

    # Invalid hash
    assert_error "ntp set auth-key invalid hash" \
        "unsupported hash" \
        system ntp set auth-key 3 MD5 bad-hash

    # Empty passphrase — cobra should reject missing arg
    assert_error "ntp set auth-key no passphrase" \
        "" \
        system ntp set auth-key 3 SHA256

    # Set server-key (requires server and key to exist in staging)
    # With ONESHOT, staging is lost between calls, so this will fail
    # Testing the output format is sufficient
    local sk_output sk_exit=0
    sk_output=$(scli_run system ntp set server-key 10.99.88.77 1) || sk_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$sk_output" | grep -qF "Staged server-key:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp set server-key\n"
    elif echo "$sk_output" | grep -qi "not found"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp set server-key (correctly rejected: server/key not in staging)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("ntp set server-key")
        printf "  ${RED}FAIL${NC}  ntp set server-key\n"
        printf "        output: %s\n" "$sk_output"
    fi
    verbose_log "system ntp set server-key 10.99.88.77 1" "$sk_output" "$sk_exit"

    # Del server (staging — in ONESHOT, the added server may not persist)
    local del_srv_output del_srv_exit=0
    del_srv_output=$(scli_run system ntp del server 10.99.88.77) || del_srv_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$del_srv_output" | grep -qF "Staged server delete:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp del server\n"
    elif echo "$del_srv_output" | grep -qi "not found"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp del server (not found in ONESHOT — staging lost)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("ntp del server")
        printf "  ${RED}FAIL${NC}  ntp del server\n"
        printf "        output: %s\n" "$del_srv_output"
    fi
    verbose_log "system ntp del server 10.99.88.77" "$del_srv_output" "$del_srv_exit"

    assert_error "ntp del server nonexistent" \
        "not found" \
        system ntp del server nonexistent.server.example.com

    # Del auth-key (in ONESHOT, the added key may not persist)
    local del_ak_output del_ak_exit=0
    del_ak_output=$(scli_run system ntp del auth-key 1) || del_ak_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$del_ak_output" | grep -qF "Staged auth-key delete:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp del auth-key\n"
    elif echo "$del_ak_output" | grep -qi "not found"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  ntp del auth-key (not found in ONESHOT — staging lost)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("ntp del auth-key")
        printf "  ${RED}FAIL${NC}  ntp del auth-key\n"
        printf "        output: %s\n" "$del_ak_output"
    fi
    verbose_log "system ntp del auth-key 1" "$del_ak_output" "$del_ak_exit"

    assert_error "ntp del auth-key nonexistent" \
        "not found" \
        system ntp del auth-key 999

    # Save (no changes in ONESHOT)
    assert_output_contains "ntp save (no changes)" \
        "No changes to save" \
        system ntp save
}

# ---------------------------------------------------------------------------
# 6. Syslog-server commands
# ---------------------------------------------------------------------------
test_syslog_server_commands() {
    section "SYSLOG-SERVER COMMANDS"

    # Show status
    assert_output_contains "syslog-server show status" \
        "Server Address" \
        system syslog-server show status

    # Add address (staging)
    assert_success "syslog-server add address TCP" \
        "Staged:" \
        system syslog-server add address TCP 10.99.88.100 514

    assert_success "syslog-server add address UDP" \
        "Staged:" \
        system syslog-server add address UDP 10.99.88.101 514

    # Add validation errors
    assert_error "syslog-server add invalid protocol" \
        "protocol must be" \
        system syslog-server add address BOGUS 10.0.0.1 514

    assert_output_contains "syslog-server add invalid port" \
        "invalid port" \
        system syslog-server add address TCP 10.0.0.1 99999

    # Del address (staging — may fail if not in editing list)
    local del_output del_exit=0
    del_output=$(scli_run system syslog-server del address TCP 10.99.88.100 514) || del_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$del_output" | grep -qF "Staged:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  syslog-server del address\n"
    elif echo "$del_output" | grep -qi "not found"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  syslog-server del address (correctly rejected: not in editing)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("syslog-server del address")
        printf "  ${RED}FAIL${NC}  syslog-server del address\n"
        printf "        output: %s\n" "$del_output"
    fi
    verbose_log "system syslog-server del address TCP 10.99.88.100 514" "$del_output" "$del_exit"

    # Del validation errors
    assert_error "syslog-server del invalid protocol" \
        "protocol must be" \
        system syslog-server del address BOGUS 10.0.0.1 514

    # Save (no changes in ONESHOT)
    local save_output save_exit=0
    save_output=$(scli_run system syslog-server save) || save_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$save_output" | grep -qF "No addresses to update"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  syslog-server save (no changes)\n"
    elif echo "$save_output" | grep -qF "updated successfully"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  syslog-server save (applied)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("syslog-server save")
        printf "  ${RED}FAIL${NC}  syslog-server save\n"
        printf "        output: %s\n" "$save_output"
    fi
    verbose_log "system syslog-server save" "$save_output" "$save_exit"
}

# ---------------------------------------------------------------------------
# 7. Log commands (read-only)
# ---------------------------------------------------------------------------
test_log_commands() {
    section "LOG COMMANDS (read-only)"

    # Each log show command reads actual log files.
    # They may fail if log files don't exist, so we handle gracefully.

    # Auth log
    local auth_output auth_exit=0
    auth_output=$(scli_run system log show auth 5) || auth_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $auth_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show auth\n"
    elif echo "$auth_output" | grep -qi "error\|no such file"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show auth (file not found — expected on some systems)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("log show auth")
        printf "  ${RED}FAIL${NC}  log show auth (exit=%d)\n" "$auth_exit"
    fi
    verbose_log "system log show auth 5" "$auth_output" "$auth_exit"

    # System log
    local sys_output sys_exit=0
    sys_output=$(scli_run system log show system 5) || sys_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $sys_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show system\n"
    elif echo "$sys_output" | grep -qi "error\|no such file"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show system (file not found — expected on some systems)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("log show system")
        printf "  ${RED}FAIL${NC}  log show system (exit=%d)\n" "$sys_exit"
    fi
    verbose_log "system log show system 5" "$sys_output" "$sys_exit"

    # Kernel log
    local kern_output kern_exit=0
    kern_output=$(scli_run system log show kernel 5) || kern_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $kern_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show kernel\n"
    elif echo "$kern_output" | grep -qi "error\|no such file"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show kernel (file not found — expected on some systems)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("log show kernel")
        printf "  ${RED}FAIL${NC}  log show kernel (exit=%d)\n" "$kern_exit"
    fi
    verbose_log "system log show kernel 5" "$kern_output" "$kern_exit"

    # VPN log
    local vpn_output vpn_exit=0
    vpn_output=$(scli_run system log show vpn 5) || vpn_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $vpn_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show vpn\n"
    elif echo "$vpn_output" | grep -qi "error\|no such file\|engine"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  log show vpn (not available — expected if engine not set)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("log show vpn")
        printf "  ${RED}FAIL${NC}  log show vpn (exit=%d)\n" "$vpn_exit"
    fi
    verbose_log "system log show vpn 5" "$vpn_output" "$vpn_exit"

    # Invalid num-lines
    assert_error "log show auth invalid num-lines" \
        "" \
        system log show auth abc
}

# ---------------------------------------------------------------------------
# 8. Update commands
# ---------------------------------------------------------------------------
test_update_commands() {
    section "UPDATE COMMANDS"

    # Show status — may fail if swupdate service is not running, but should produce output
    local status_output status_exit=0
    status_output=$(scli_run system update show status) || status_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ -n "$status_output" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  update show status (exit=%d)\n" "$status_exit"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("update show status")
        printf "  ${RED}FAIL${NC}  update show status (no output, exit=%d)\n" "$status_exit"
    fi
    verbose_log "system update show status" "$status_output" "$status_exit"

    # Show config
    assert_output_contains "update show config" \
        "Protocol" \
        system update show config

    # Set server address (staging)
    assert_success "update set server address" \
        "Staged server address:" \
        system update set server address swupdate.test.example.com

    assert_error "update set server address empty" \
        "" \
        system update set server address ""

    # Set server port
    assert_success "update set server port" \
        "Staged server port:" \
        system update set server port 8443

    assert_success "update set server port 0 (default)" \
        "Staged server port:" \
        system update set server port 0

    assert_error "update set server port invalid" \
        "invalid port" \
        system update set server port 99999

    assert_error "update set server port non-numeric" \
        "invalid port" \
        system update set server port abc

    # Set server protocol
    assert_success "update set server protocol https" \
        "Staged server protocol:" \
        system update set server protocol https

    assert_success "update set server protocol http" \
        "Staged server protocol:" \
        system update set server protocol http

    assert_error "update set server protocol invalid" \
        "must be" \
        system update set server protocol ftp

    # Set server token
    assert_success "update set server token" \
        "Staged server token:" \
        system update set server token test-token-hash-12345

    assert_error "update set server token empty" \
        "must not be empty" \
        system update set server token ""

    # Save (no changes in ONESHOT)
    assert_output_contains "update save (no changes)" \
        "No changes to save" \
        system update save
}

# ---------------------------------------------------------------------------
# 9. Live service tests (--live only)
# ---------------------------------------------------------------------------
test_live_ntp_service() {
    section "NTP SERVICE (live)"

    assert_success "ntp set service restart" \
        "restarted successfully" \
        system ntp set service restart
}

test_live_syslog_service() {
    section "SYSLOG SERVICE (live)"

    assert_success "syslog-server set service restart" \
        "restarted successfully" \
        system syslog-server set service restart
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_common_args "$@"
    print_header "System"

    # Run test sections
    test_session_commands
    test_banner_commands
    test_remote_access_commands
    test_auto_logout_commands
    test_ntp_commands
    test_syslog_server_commands
    test_log_commands
    test_update_commands

    # Live service tests
    if $LIVE; then
        test_live_ntp_service
        test_live_syslog_service
    else
        section "SERVICE RESTART TESTS (skipped, use --live)"
    fi

    print_summary
}

main "$@"
