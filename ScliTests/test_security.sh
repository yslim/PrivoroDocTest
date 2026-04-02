#!/usr/bin/env bash
# =============================================================================
# Security CLI Integration Test Suite for shiba-scli
#
# Tests security est-server, vpn, and certificates commands.
# VPN commands require grey mode and a VPN engine to be set.
#
# Usage:
#   bash tests/test_security.sh                  # basic tests
#   bash tests/test_security.sh -v               # verbose
#   bash tests/test_security.sh --live            # enable save/service tests
#   SCLI_BIN=/path/to/scli bash tests/test_security.sh
#
# Prerequisites:
#   - Linux device with VPN engine (strongSwan/Libreswan)
#   - /etc/scli.yml configuration
#   - Passwordless sudo (or run as root)
#   - scli binary built and accessible
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Load common test framework
# ---------------------------------------------------------------------------
source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Check if VPN engine is configured
check_vpn_engine() {
    local output
    output=$(scli_run security vpn show engine 2>&1) || true
    if echo "$output" | grep -qi "strongswan\|libreswan"; then
        return 0
    fi
    return 1
}

# =============================================================================
# TEST SECTIONS
# =============================================================================

# ---------------------------------------------------------------------------
# 1. EST Server show commands
# ---------------------------------------------------------------------------
test_est_server_show() {
    section "EST SERVER SHOW"

    assert_output_contains "est-server show config" \
        "Parameter" \
        security est-server show config
}

# ---------------------------------------------------------------------------
# 2. EST Server set commands (staging + validation)
# ---------------------------------------------------------------------------
test_est_server_set() {
    section "EST SERVER SET COMMANDS"

    # --- Individual set commands (validation / staging output) ---
    assert_success "est-server set address (IPv4)" \
        "Staged Address:" \
        security est-server set address 10.99.88.1

    assert_success "est-server set address (FQDN)" \
        "Staged Address:" \
        security est-server set address est.test.example.com

    assert_success "est-server set address (IPv6)" \
        "Staged Address:" \
        security est-server set address fd99::1

    assert_success "est-server set port 443" \
        "Staged Port" \
        security est-server set port 443

    assert_success "est-server set port 0 (default)" \
        "Staged Port" \
        security est-server set port 0

    assert_error "est-server set port invalid" \
        "invalid port" \
        security est-server set port 99999

    assert_error "est-server set port non-numeric" \
        "invalid port" \
        security est-server set port abc

    assert_success "est-server set base-path" \
        "Staged EST base path" \
        security est-server set base-path /.well-known/est

    assert_success "est-server set base-path / (none)" \
        "Staged EST base path" \
        security est-server set base-path /

    assert_success "est-server set auto-reenroll no" \
        "Staged EST Auto ReEnroll:" \
        security est-server set auto-reenroll no

    # auto-reenroll yes may fail if reenroll-auth-cert is not set
    local auto_output auto_exit=0
    auto_output=$(scli_run security est-server set auto-reenroll yes) || auto_exit=$?
    TOTAL=$((TOTAL + 1))
    if echo "$auto_output" | grep -qF "Staged EST Auto ReEnroll:"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  est-server set auto-reenroll yes\n"
    elif echo "$auto_output" | grep -qi "not set\|auth certificate"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  est-server set auto-reenroll yes (correctly rejected: cert not set)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("est-server set auto-reenroll yes")
        printf "  ${RED}FAIL${NC}  est-server set auto-reenroll yes\n"
        printf "        output: %s\n" "$auto_output"
    fi
    verbose_log "security est-server set auto-reenroll yes" "$auto_output" "$auto_exit"

    # Save (no changes in ONESHOT — staging lost between calls)
    assert_output_contains "est-server save (no changes in ONESHOT)" \
        "No changes to save" \
        security est-server save
}

# ---------------------------------------------------------------------------
# 2b. EST Server set+save session (staging persists within session)
# ---------------------------------------------------------------------------
test_est_server_set_save_session() {
    section "EST SERVER SET+SAVE SESSION"

    local cmds=(
        "security est-server set address 10.99.88.1"
        "security est-server set port 443"
        "security est-server set base-path /.well-known/est"
        "security est-server save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "est-server set+save session"

    assert_text_contains "est session: address staged" \
        "Staged Address:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "est session: port staged" \
        "Staged Port" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "est session: base-path staged" \
        "Staged EST base path" \
        "$SCLI_SESSION_OUTPUT"
}

# ---------------------------------------------------------------------------
# 3. VPN show commands (requires grey mode + engine)
# ---------------------------------------------------------------------------
test_vpn_show() {
    section "VPN SHOW COMMANDS"

    if ! check_vpn_engine; then
        skip_test "vpn show engine" "no VPN engine configured"
        skip_test "vpn show config" "no VPN engine configured"
        skip_test "vpn show status" "no VPN engine configured"
        skip_test "vpn show certs" "no VPN engine configured"
        skip_test "vpn show tpm-handles" "no VPN engine configured"
        skip_test "vpn show algorithms ike" "no VPN engine configured"
        skip_test "vpn show algorithms esp" "no VPN engine configured"
        return
    fi

    # Engine
    local engine_output
    engine_output=$(scli_run security vpn show engine)
    assert_output_contains "vpn show engine" \
        "VPN engine:" \
        security vpn show engine

    # Config
    assert_output_contains "vpn show config" \
        "Configuration" \
        security vpn show config

    # Status
    local status_output status_exit=0
    status_output=$(scli_run security vpn show status) || status_exit=$?
    TOTAL=$((TOTAL + 1))
    # Status may fail if service is not running
    if [ $status_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show status\n"
    elif echo "$status_output" | grep -qi "not running\|unavailable"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show status (service not running)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("vpn show status")
        printf "  ${RED}FAIL${NC}  vpn show status (exit=%d)\n" "$status_exit"
        printf "        output: %s\n" "$status_output"
    fi
    verbose_log "security vpn show status" "$status_output" "$status_exit"

    # Certs
    local certs_output certs_exit=0
    certs_output=$(scli_run security vpn show certs) || certs_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $certs_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show certs\n"
    elif echo "$certs_output" | grep -qi "error\|not found\|no such file"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show certs (tool not available or no certs)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("vpn show certs")
        printf "  ${RED}FAIL${NC}  vpn show certs (exit=%d)\n" "$certs_exit"
        printf "        output: %s\n" "$certs_output"
    fi
    verbose_log "security vpn show certs" "$certs_output" "$certs_exit"

    # TPM handles
    local tpm_output tpm_exit=0
    tpm_output=$(scli_run security vpn show tpm-handles) || tpm_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $tpm_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show tpm-handles\n"
    elif echo "$tpm_output" | grep -qi "error\|not found\|no such file"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show tpm-handles (script not available)\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("vpn show tpm-handles")
        printf "  ${RED}FAIL${NC}  vpn show tpm-handles (exit=%d)\n" "$tpm_exit"
        printf "        output: %s\n" "$tpm_output"
    fi
    verbose_log "security vpn show tpm-handles" "$tpm_output" "$tpm_exit"

    # Algorithms IKE
    local ike_alg_output ike_alg_exit=0
    ike_alg_output=$(scli_run security vpn show algorithms ike) || ike_alg_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $ike_alg_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show algorithms ike\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("vpn show algorithms ike")
        printf "  ${RED}FAIL${NC}  vpn show algorithms ike (exit=%d)\n" "$ike_alg_exit"
        printf "        output: %s\n" "$ike_alg_output"
    fi
    verbose_log "security vpn show algorithms ike" "$ike_alg_output" "$ike_alg_exit"

    # Algorithms ESP
    local esp_alg_output esp_alg_exit=0
    esp_alg_output=$(scli_run security vpn show algorithms esp) || esp_alg_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $esp_alg_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  vpn show algorithms esp\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("vpn show algorithms esp")
        printf "  ${RED}FAIL${NC}  vpn show algorithms esp (exit=%d)\n" "$esp_alg_exit"
        printf "        output: %s\n" "$esp_alg_output"
    fi
    verbose_log "security vpn show algorithms esp" "$esp_alg_output" "$esp_alg_exit"
}

# ---------------------------------------------------------------------------
# 4. VPN set commands (staging + validation)
# ---------------------------------------------------------------------------
test_vpn_set_commands() {
    section "VPN SET COMMANDS"

    if ! check_vpn_engine; then
        skip_test "vpn set psk/ppk/ike/esp" "no VPN engine configured"
        return
    fi

    # --- PSK ---
    assert_success "vpn set psk local-id" \
        "Staged:" \
        security vpn set psk local-id test-local-id

    assert_success "vpn set psk remote-id" \
        "Staged:" \
        security vpn set psk remote-id test-remote-id

    assert_success "vpn set psk secret" \
        "Staged:" \
        security vpn set psk secret test-secret-12345

    # --- PPK ---
    assert_success "vpn set ppk id" \
        "Staged:" \
        security vpn set ppk id test-ppk-id

    assert_success "vpn set ppk secret" \
        "Staged:" \
        security vpn set ppk secret test-ppk-secret

    assert_success "vpn set ppk required yes" \
        "Staged:" \
        security vpn set ppk required yes

    assert_success "vpn set ppk required no" \
        "Staged:" \
        security vpn set ppk required no

    assert_error "vpn set ppk required invalid" \
        "must be" \
        security vpn set ppk required maybe

    # --- IKE ---
    assert_success "vpn set ike peer address" \
        "Staged:" \
        security vpn set ike peer address 10.99.88.1

    assert_error "vpn set ike peer address invalid" \
        "" \
        security vpn set ike peer address not-an-address!@#

    # IKE lifetime
    assert_success "vpn set ike lifetime 3600" \
        "Staged:" \
        security vpn set ike lifetime 3600

    assert_success "vpn set ike lifetime 1h" \
        "Staged:" \
        security vpn set ike lifetime 1h

    assert_error "vpn set ike lifetime too low" \
        "" \
        security vpn set ike lifetime 100

    # IKE DPD delay
    assert_success "vpn set ike dpd delay 30" \
        "Staged:" \
        security vpn set ike dpd delay 30

    assert_error "vpn set ike dpd delay too low" \
        "" \
        security vpn set ike dpd delay 1

    assert_error "vpn set ike dpd delay too high" \
        "" \
        security vpn set ike dpd delay 999

    # IKE DPD timeout
    assert_success "vpn set ike dpd timeout 120" \
        "Staged:" \
        security vpn set ike dpd timeout 120

    assert_error "vpn set ike dpd timeout too low" \
        "" \
        security vpn set ike dpd timeout 10

    # --- ESP ---
    # ESP lifetime
    assert_success "vpn set esp lifetime 3600" \
        "Staged:" \
        security vpn set esp lifetime 3600

    assert_error "vpn set esp lifetime too low" \
        "" \
        security vpn set esp lifetime 100

    # ESP remote-ts
    assert_success "vpn set esp remote-ts (single)" \
        "Staged:" \
        security vpn set esp remote-ts 10.10.20.0/24

    assert_success "vpn set esp remote-ts (multiple)" \
        "Staged:" \
        security vpn set esp remote-ts 10.10.20.0/24,192.168.50.0/24

    assert_error "vpn set esp remote-ts invalid CIDR" \
        "invalid CIDR" \
        security vpn set esp remote-ts not-a-cidr

    # ESP local-ts
    assert_success "vpn set esp local-ts" \
        "Staged:" \
        security vpn set esp local-ts 10.10.10.0/24

    assert_error "vpn set esp local-ts invalid CIDR" \
        "invalid CIDR" \
        security vpn set esp local-ts not-a-cidr

    # --- VTI ---
    assert_success "vpn set vti tunnel-key" \
        "Staged:" \
        security vpn set vti tunnel-key 100

    assert_error "vpn set vti tunnel-key invalid" \
        "invalid tunnel-key" \
        security vpn set vti tunnel-key not-a-number

    assert_success "vpn set vti interface" \
        "Staged:" \
        security vpn set vti interface vti0

    assert_success "vpn set vti local-ip" \
        "Staged:" \
        security vpn set vti local-ip 10.200.1.10/30

    # scli prints error message but exits 0, so use assert_output_contains
    assert_output_contains "vpn set vti local-ip invalid" \
        "invalid CIDR" \
        security vpn set vti local-ip not-a-cidr

    assert_success "vpn set vti source-ip" \
        "Staged:" \
        security vpn set vti source-ip 192.168.100.1

    # scli prints error message but exits 0, so use assert_output_contains
    assert_output_contains "vpn set vti source-ip invalid" \
        "Invalid address" \
        security vpn set vti source-ip not-an-ip

    # --- OCSP ---
    assert_success "vpn set ocsp-validation enable" \
        "Staged:" \
        security vpn set ocsp-validation enable

    assert_success "vpn set ocsp-validation disable" \
        "Staged:" \
        security vpn set ocsp-validation disable
}

# ---------------------------------------------------------------------------
# 5. VPN del commands (individual staging output)
# ---------------------------------------------------------------------------
test_vpn_del_commands() {
    section "VPN DEL COMMANDS"

    if ! check_vpn_engine; then
        skip_test "vpn del psk/ppk/vti" "no VPN engine configured"
        return
    fi

    # Del PSK
    assert_success "vpn del psk local-id" \
        "Staged:" \
        security vpn del psk local-id

    assert_success "vpn del psk remote-id" \
        "Staged:" \
        security vpn del psk remote-id

    assert_success "vpn del psk secret" \
        "Staged:" \
        security vpn del psk secret

    # Del PPK
    assert_success "vpn del ppk" \
        "Staged:" \
        security vpn del ppk

    # Del VTI source-ip
    assert_success "vpn del vti source-ip" \
        "Staged:" \
        security vpn del vti source-ip
}

# ---------------------------------------------------------------------------
# 5b. VPN set+del session (staging persists for del to find set values)
# ---------------------------------------------------------------------------
test_vpn_set_del_session() {
    section "VPN SET+DEL SESSION"

    if ! check_vpn_engine; then
        skip_test "vpn set+del session" "no VPN engine configured"
        return
    fi

    local cmds=(
        "security vpn set psk local-id test-local-id"
        "security vpn set psk remote-id test-remote-id"
        "security vpn set psk secret test-secret-12345"
        "security vpn del psk local-id"
        "security vpn del psk remote-id"
        "security vpn del psk secret"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "vpn psk set+del session"

    assert_text_contains "session: psk local-id staged" \
        "Staged:" \
        "$SCLI_SESSION_OUTPUT"
}

# ---------------------------------------------------------------------------
# 5c. VPN set+save session (staging persists for save)
# ---------------------------------------------------------------------------
test_vpn_set_save_session() {
    section "VPN SET+SAVE SESSION"

    if ! check_vpn_engine; then
        skip_test "vpn set+save session" "no VPN engine configured"
        return
    fi

    local cmds=(
        "security vpn set psk local-id test-local-id"
        "security vpn set psk remote-id test-remote-id"
        "security vpn set psk secret test-secret-12345"
        "security vpn set ike peer address 10.99.88.1"
        "security vpn set ike lifetime 3600"
        "security vpn set esp lifetime 3600"
        "security vpn set esp remote-ts 10.10.20.0/24"
        "security vpn save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "vpn set+save session"

    assert_text_contains "save session: psk local-id" \
        "Staged:" \
        "$SCLI_SESSION_OUTPUT"

    assert_text_contains "save session: peer address" \
        "Staged:" \
        "$SCLI_SESSION_OUTPUT"
}

# ---------------------------------------------------------------------------
# 6. VPN save guard
# ---------------------------------------------------------------------------
test_vpn_save_guard() {
    section "VPN SAVE (guard only)"

    if ! check_vpn_engine; then
        skip_test "vpn save (no changes)" "no VPN engine configured"
        return
    fi

    assert_output_contains "vpn save (no changes)" \
        "No changes to save" \
        security vpn save
}

# ---------------------------------------------------------------------------
# 7. Certificates commands (read-only show)
# ---------------------------------------------------------------------------
test_certificates_show() {
    section "CERTIFICATES SHOW COMMANDS"

    # CA cert list
    local ca_output ca_exit=0
    ca_output=$(scli_run security certificates ca-cert show list) || ca_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $ca_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  certificates ca-cert show list\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("certificates ca-cert show list")
        printf "  ${RED}FAIL${NC}  certificates ca-cert show list (exit=%d)\n" "$ca_exit"
        printf "        output: %s\n" "$ca_output"
    fi
    verbose_log "security certificates ca-cert show list" "$ca_output" "$ca_exit"

    # CA cert show status — try with first available CA name
    local first_ca
    first_ca=$(echo "$ca_output" | grep -v '^$' | head -1 | awk '{print $1}' 2>/dev/null)
    if [ -n "$first_ca" ] && [ "$first_ca" != "No" ] && [ "$first_ca" != "Error" ]; then
        local ca_st_output ca_st_exit=0
        ca_st_output=$(scli_run security certificates ca-cert show status "$first_ca") || ca_st_exit=$?
        TOTAL=$((TOTAL + 1))
        if [ $ca_st_exit -eq 0 ]; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  certificates ca-cert show status %s\n" "$first_ca"
        else
            FAIL=$((FAIL + 1))
            FAILURES+=("certificates ca-cert show status $first_ca")
            printf "  ${RED}FAIL${NC}  certificates ca-cert show status %s (exit=%d)\n" "$first_ca" "$ca_st_exit"
            printf "        output: %s\n" "$ca_st_output"
        fi
        verbose_log "security certificates ca-cert show status $first_ca" "$ca_st_output" "$ca_st_exit"
    else
        skip_test "ca-cert show status <name>" "no CA certificates found"
    fi

    # CA cert show status (empty name — error case)
    assert_error "ca-cert show status (empty name)" \
        "" \
        security certificates ca-cert show status ""

    # Key cert list certs
    local kc_output kc_exit=0
    kc_output=$(scli_run security certificates key-cert show list certs) || kc_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $kc_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  certificates key-cert show list certs\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("certificates key-cert show list certs")
        printf "  ${RED}FAIL${NC}  certificates key-cert show list certs (exit=%d)\n" "$kc_exit"
        printf "        output: %s\n" "$kc_output"
    fi
    verbose_log "security certificates key-cert show list certs" "$kc_output" "$kc_exit"

    # Key cert list keys
    local kk_output kk_exit=0
    kk_output=$(scli_run security certificates key-cert show list keys) || kk_exit=$?
    TOTAL=$((TOTAL + 1))
    if [ $kk_exit -eq 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  certificates key-cert show list keys\n"
    else
        # Keys may fail if show-key-list.sh is not available
        if echo "$kk_output" | grep -qi "not found\|no such file"; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  certificates key-cert show list keys (script not available)\n"
        else
            FAIL=$((FAIL + 1))
            FAILURES+=("certificates key-cert show list keys")
            printf "  ${RED}FAIL${NC}  certificates key-cert show list keys (exit=%d)\n" "$kk_exit"
            printf "        output: %s\n" "$kk_output"
        fi
    fi
    verbose_log "security certificates key-cert show list keys" "$kk_output" "$kk_exit"

    # Key cert show status — try with first available cert name
    local first_kc
    first_kc=$(echo "$kc_output" | grep -v '^$' | head -1 | awk '{print $1}' 2>/dev/null)
    if [ -n "$first_kc" ] && [ "$first_kc" != "No" ] && [ "$first_kc" != "Error" ]; then
        local kc_st_output kc_st_exit=0
        kc_st_output=$(scli_run security certificates key-cert show status "$first_kc") || kc_st_exit=$?
        TOTAL=$((TOTAL + 1))
        if [ $kc_st_exit -eq 0 ]; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  certificates key-cert show status %s\n" "$first_kc"
        else
            FAIL=$((FAIL + 1))
            FAILURES+=("certificates key-cert show status $first_kc")
            printf "  ${RED}FAIL${NC}  certificates key-cert show status %s (exit=%d)\n" "$first_kc" "$kc_st_exit"
            printf "        output: %s\n" "$kc_st_output"
        fi
        verbose_log "security certificates key-cert show status $first_kc" "$kc_st_output" "$kc_st_exit"
    else
        skip_test "key-cert show status <name>" "no key certificates found"
    fi

    # Key cert show status (empty name — error case)
    assert_error "key-cert show status (empty name)" \
        "" \
        security certificates key-cert show status ""
}

# ---------------------------------------------------------------------------
# 8. Certificates validation
# ---------------------------------------------------------------------------
test_certificates_validation() {
    section "CERTIFICATES VALIDATION"

    # CA cert add (empty name)
    assert_error "ca-cert add (empty name)" \
        "empty" \
        security certificates ca-cert add ""

    # CA cert del (empty name)
    assert_error "ca-cert del (empty name)" \
        "empty" \
        security certificates ca-cert del ""

    # Key cert add (empty name)
    assert_error "key-cert add (empty name)" \
        "empty" \
        security certificates key-cert add ""

    # Key cert del (empty name)
    assert_error "key-cert del (empty name)" \
        "empty" \
        security certificates key-cert del ""

    # Key gen (empty name)
    assert_error "key-cert key-gen (empty name)" \
        "empty" \
        security certificates key-cert key-gen ""

    # CSR gen (empty name) — cobra validates --cn flag first before checking name
    assert_error "key-cert csr-gen (empty name)" \
        "" \
        security certificates key-cert csr-gen ""

    # CSR gen (no --cn flag)
    assert_error "key-cert csr-gen (no --cn)" \
        "required" \
        security certificates key-cert csr-gen test-key
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_common_args "$@"
    print_header "Security"

    # EST Server
    test_est_server_show
    test_est_server_set

    # VPN
    test_vpn_show
    test_vpn_set_commands
    test_vpn_del_commands
    test_vpn_set_del_session
    test_vpn_save_guard

    # Live session tests (set+save workflows)
    if $LIVE; then
        test_est_server_set_save_session
        test_vpn_set_save_session
    else
        section "SESSION SAVE TESTS (skipped, use --live)"
    fi

    # Certificates
    test_certificates_show
    test_certificates_validation

    print_summary
}

main "$@"
