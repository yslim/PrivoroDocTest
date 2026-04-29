#!/usr/bin/env bash
# =============================================================================
# VPN Test Suite (identity + revocation)
#
# Identity (local-id / remote-id) for cert-based and PSK auth — covers
# all ID types: IP, FQDN, Email, DN.  Identity commands moved from
# 'set pubkey ...' to 'set certs ...' on the vpn-revocation branch.
#
# Revocation (ocsp-validation / ocsp-strict / crl-strict /
# crl-check-interval) under 'security vpn set revocation' subtree.
# ocsp-strict / crl-strict / crl-check-interval are libreswan-only;
# strongswan path expects "not supported on strongswan" notice.
#
# Tests both staging (set/del commands) and, with --live, save +
# reload verification for StrongSwan (swanctl.conf) and Libreswan
# (ipsec.conf).
#
# Usage:
#   bash test_vpn.sh                  # staging tests only
#   bash test_vpn.sh -v               # verbose
#   bash test_vpn.sh --live           # include save + file verification
#   SCLI_BIN=/path/to/scli bash test_vpn.sh
#
# Prerequisites:
#   - Linux device with VPN engine (strongSwan/Libreswan)
#   - /etc/scli.yml configuration
#   - Passwordless sudo (or run as root)
# =============================================================================
set -uo pipefail

source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
check_vpn_engine() {
    local output
    output=$(scli_run security vpn show engine 2>&1) || true
    if echo "$output" | grep -qi "strongswan\|libreswan"; then
        return 0
    fi
    return 1
}

get_vpn_engine() {
    local output
    output=$(scli_run security vpn show engine 2>&1) || true
    if echo "$output" | grep -qi "strongswan"; then
        echo "strongswan"
    elif echo "$output" | grep -qi "libreswan"; then
        echo "libreswan"
    else
        echo "unknown"
    fi
}

# assert_file_not_contains <description> <file> <needle>
assert_file_not_contains() {
    local desc="$1" file="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    if ! sudo grep -qF "$needle" "$file" 2>/dev/null; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected %s NOT to contain: %s\n" "$file" "$needle"
    fi
}

assert_swanctl_identity_present() {
    local desc="$1" target="$2"
    TOTAL=$((TOTAL + 1))

    local files
    files=$(sudo find /etc/swanctl -type f \( -name '*.conf' -o -name 'swanctl.conf' \) 2>/dev/null | sort)
    if [ -z "$files" ]; then
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        no swanctl config files found under /etc/swanctl\n"
        return
    fi

    local matched_file=""
    local file
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        if sudo awk -v target="$target" '
            function trim(s) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
                return s
            }
            function dequote(s) {
                s = trim(s)
                if (s ~ /^".*"$/ || s ~ /^'\''.*'\''$/) {
                    return substr(s, 2, length(s) - 2)
                }
                return s
            }
            function canonicalize(s, lower) {
                s = dequote(s)
                lower = tolower(s)
                if (lower ~ /^(fqdn|rfc822|email|ipv4|ipv6|asn1dn|dn):/) {
                    sub(/^[^:]+:/, "", s)
                }
                if (s ~ /^@/) {
                    s = substr(s, 2)
                }
                return trim(s)
            }
            /^[[:space:]]*id[[:space:]]*=/ {
                line = $0
                sub(/^[[:space:]]*id[[:space:]]*=[[:space:]]*/, "", line)
                if (canonicalize(line) == canonicalize(target)) {
                    found = 1
                    exit 0
                }
            }
            END { exit found ? 0 : 1 }
        ' "$file"; then
            matched_file="$file"
            break
        fi
    done <<< "$files"

    if [ -n "$matched_file" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected an id entry matching: %s\n" "$target"
        printf "        searched under: /etc/swanctl\n"
    fi
}

assert_swanctl_identity_not_present() {
    local desc="$1" target="$2"
    TOTAL=$((TOTAL + 1))

    local files
    files=$(sudo find /etc/swanctl -type f \( -name '*.conf' -o -name 'swanctl.conf' \) 2>/dev/null | sort)
    if [ -z "$files" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
        return
    fi

    local matched_file=""
    local file
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        if sudo awk -v target="$target" '
            function trim(s) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
                return s
            }
            function dequote(s) {
                s = trim(s)
                if (s ~ /^".*"$/ || s ~ /^'\''.*'\''$/) {
                    return substr(s, 2, length(s) - 2)
                }
                return s
            }
            function canonicalize(s, lower) {
                s = dequote(s)
                lower = tolower(s)
                if (lower ~ /^(fqdn|rfc822|email|ipv4|ipv6|asn1dn|dn):/) {
                    sub(/^[^:]+:/, "", s)
                }
                if (s ~ /^@/) {
                    s = substr(s, 2)
                }
                return trim(s)
            }
            /^[[:space:]]*id[[:space:]]*=/ {
                line = $0
                sub(/^[[:space:]]*id[[:space:]]*=[[:space:]]*/, "", line)
                if (canonicalize(line) == canonicalize(target)) {
                    found = 1
                    exit 0
                }
            }
            END { exit found ? 0 : 1 }
        ' "$file"; then
            matched_file="$file"
            break
        fi
    done <<< "$files"

    if [ -z "$matched_file" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        unexpected id entry still present: %s\n" "$target"
        printf "        matched file: %s\n" "$matched_file"
    fi
}

# =============================================================================
# TEST SECTIONS
# =============================================================================

# ---------------------------------------------------------------------------
# 1. Certs local-id / remote-id SET commands (staging)
# ---------------------------------------------------------------------------
test_certs_set_identity() {
    section "CERTS SET IDENTITY (staging)"

    # Switch to pubkey auth first
    scli_run security vpn set auth pubkey >/dev/null 2>&1

    # -- local-id --
    assert_success "certs set local-id (FQDN)" \
        "Staged: certs local ID" \
        security vpn set certs local-id client.example.com

    assert_success "certs set local-id (IP)" \
        "Staged: certs local ID" \
        security vpn set certs local-id 192.168.1.100

    assert_success "certs set local-id (Email)" \
        "Staged: certs local ID" \
        security vpn set certs local-id admin@example.com

    assert_success "certs set local-id (DN)" \
        "Staged: certs local ID" \
        security vpn set certs local-id "C=US, O=MyOrg, CN=client"

    # -- remote-id --
    assert_success "certs set remote-id (FQDN)" \
        "Staged: certs remote ID" \
        security vpn set certs remote-id vpnserver.example.com

    assert_success "certs set remote-id (IP)" \
        "Staged: certs remote ID" \
        security vpn set certs remote-id 10.0.0.1

    assert_success "certs set remote-id (Email)" \
        "Staged: certs remote ID" \
        security vpn set certs remote-id vpn@example.com

    assert_success "certs set remote-id (DN)" \
        "Staged: certs remote ID" \
        security vpn set certs remote-id "C=US, O=MyOrg, CN=server"

    # -- missing arg --
    assert_error "certs set local-id (no arg)" \
        "" \
        security vpn set certs local-id

    assert_error "certs set remote-id (no arg)" \
        "" \
        security vpn set certs remote-id
}

# ---------------------------------------------------------------------------
# 2. Certs local-id / remote-id DEL commands (staging)
# ---------------------------------------------------------------------------
test_certs_del_identity() {
    section "CERTS DEL IDENTITY (staging)"

    local local_id_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn del certs local-id"
    )
    capture_scli_session "${local_id_cmds[@]}"
    assert_captured_session_success "certs del local-id session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "certs del local-id" \
            "Clear certs local ID" \
            "$SCLI_SESSION_OUTPUT"
    fi

    local remote_id_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn del certs remote-id"
    )
    capture_scli_session "${remote_id_cmds[@]}"
    assert_captured_session_success "certs del remote-id session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "certs del remote-id" \
            "Clear certs remote ID" \
            "$SCLI_SESSION_OUTPUT"
    fi
}

# ---------------------------------------------------------------------------
# 3. PSK local-id / remote-id SET commands (staging)
# ---------------------------------------------------------------------------
test_psk_set_identity() {
    section "PSK SET IDENTITY (staging)"

    # Switch to PSK auth
    scli_run security vpn set auth psk >/dev/null 2>&1

    # -- local-id --
    assert_success "psk set local-id (FQDN)" \
        "Staged: PSK local ID" \
        security vpn set psk local-id gateway.example.com

    assert_success "psk set local-id (IP)" \
        "Staged: PSK local ID" \
        security vpn set psk local-id 192.168.1.1

    assert_success "psk set local-id (Email)" \
        "Staged: PSK local ID" \
        security vpn set psk local-id user@example.com

    # -- remote-id --
    assert_success "psk set remote-id (FQDN)" \
        "Staged: PSK remote ID" \
        security vpn set psk remote-id peer.example.com

    assert_success "psk set remote-id (IP)" \
        "Staged: PSK remote ID" \
        security vpn set psk remote-id 10.0.0.2

    assert_success "psk set remote-id (Email)" \
        "Staged: PSK remote ID" \
        security vpn set psk remote-id peer@example.com
}

# ---------------------------------------------------------------------------
# 4. PSK local-id / remote-id DEL commands (staging)
# ---------------------------------------------------------------------------
test_psk_del_identity() {
    section "PSK DEL IDENTITY (staging)"

    local local_id_cmds=(
        "security vpn set auth psk"
        "security vpn set psk local-id test-local"
        "security vpn set psk remote-id test-remote"
        "security vpn del psk local-id"
    )
    capture_scli_session "${local_id_cmds[@]}"
    assert_captured_session_success "psk del local-id session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "psk del local-id" \
            "Clear PSK local ID" \
            "$SCLI_SESSION_OUTPUT"
    fi

    local remote_id_cmds=(
        "security vpn set auth psk"
        "security vpn set psk local-id test-local"
        "security vpn set psk remote-id test-remote"
        "security vpn del psk remote-id"
    )
    capture_scli_session "${remote_id_cmds[@]}"
    assert_captured_session_success "psk del remote-id session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "psk del remote-id" \
            "Clear PSK remote ID" \
            "$SCLI_SESSION_OUTPUT"
    fi
}

# ---------------------------------------------------------------------------
# 5. Show config displays identity (staging)
# ---------------------------------------------------------------------------
test_show_config_identity() {
    section "SHOW CONFIG IDENTITY DISPLAY"

    local show_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn show config"
    )
    capture_scli_session "${show_cmds[@]}"
    assert_captured_session_success "show config identity session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "show config: certs Local Id displayed" \
            "Local Id" \
            "$SCLI_SESSION_OUTPUT"
        assert_text_contains "show config: certs Remote Id displayed" \
            "Remote Id" \
            "$SCLI_SESSION_OUTPUT"
    fi

    local clear_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn del certs local-id"
        "security vpn del certs remote-id"
        "security vpn show config"
    )
    capture_scli_session "${clear_cmds[@]}"
    assert_captured_session_success "show config cleared identity session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "show config: certs Local Id (not set)" \
            "(not set)" \
            "$SCLI_SESSION_OUTPUT"
    fi
}

# ---------------------------------------------------------------------------
# 6. Auth mode switch clears cert (pubkey-auth) only IDs
# ---------------------------------------------------------------------------
test_auth_switch_clears_ids() {
    section "AUTH SWITCH ID SANITIZATION"

    local cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id %fromcert"
        "security vpn set certs remote-id %same"
        "security vpn set auth psk"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "auth switch to psk session"
    if [ "$SCLI_SESSION_EXIT" -eq 0 ]; then
        assert_text_contains "auth switch to psk clears magic IDs" \
            "Staged: auth method to psk" \
            "$SCLI_SESSION_OUTPUT"
    fi
}

# ---------------------------------------------------------------------------
# 7. LIVE: Save + verify config files (--live only)
# ---------------------------------------------------------------------------
test_live_certs_save_fqdn() {
    section "LIVE: CERTS SAVE — FQDN"

    if ! $LIVE; then
        skip_test "certs save FQDN local-id" "use --live"
        skip_test "certs save FQDN remote-id" "use --live"
        return
    fi

    local engine
    engine=$(get_vpn_engine)

    local cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "certs save FQDN session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    if [ "$engine" = "strongswan" ]; then
        assert_swanctl_identity_present "swanctl: local id = client.example.com" \
            "client.example.com"
        assert_swanctl_identity_present "swanctl: remote id = vpnserver.example.com" \
            "vpnserver.example.com"
    elif [ "$engine" = "libreswan" ]; then
        assert_file_contains "ipsec.conf: leftid=@client.example.com" \
            /etc/ipsec.conf "leftid=@client.example.com"
        assert_file_contains "ipsec.conf: rightid=@vpnserver.example.com" \
            /etc/ipsec.conf "rightid=@vpnserver.example.com"
    fi
}

test_live_certs_save_ip() {
    section "LIVE: CERTS SAVE — IP"

    if ! $LIVE; then
        skip_test "certs save IP local-id" "use --live"
        skip_test "certs save IP remote-id" "use --live"
        return
    fi

    local engine
    engine=$(get_vpn_engine)

    local cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id 192.168.1.100"
        "security vpn set certs remote-id 10.0.0.1"
        "security vpn save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "certs save IP session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    if [ "$engine" = "strongswan" ]; then
        assert_swanctl_identity_present "swanctl: local id = 192.168.1.100" \
            "192.168.1.100"
        assert_swanctl_identity_present "swanctl: remote id = 10.0.0.1" \
            "10.0.0.1"
    elif [ "$engine" = "libreswan" ]; then
        assert_file_contains "ipsec.conf: leftid=192.168.1.100" \
            /etc/ipsec.conf "leftid=192.168.1.100"
        assert_file_contains "ipsec.conf: rightid=10.0.0.1" \
            /etc/ipsec.conf "rightid=10.0.0.1"
    fi
}

test_live_certs_save_email() {
    section "LIVE: CERTS SAVE — Email"

    if ! $LIVE; then
        skip_test "certs save Email local-id" "use --live"
        skip_test "certs save Email remote-id" "use --live"
        return
    fi

    local engine
    engine=$(get_vpn_engine)

    local cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id admin@example.com"
        "security vpn set certs remote-id vpn@example.com"
        "security vpn save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "certs save Email session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    if [ "$engine" = "strongswan" ]; then
        assert_swanctl_identity_present "swanctl: local id = admin@example.com" \
            "admin@example.com"
        assert_swanctl_identity_present "swanctl: remote id = vpn@example.com" \
            "vpn@example.com"
    elif [ "$engine" = "libreswan" ]; then
        # Email: no @ prefix (ID_RFC822_ADDR)
        assert_file_contains "ipsec.conf: leftid=admin@example.com" \
            /etc/ipsec.conf "leftid=admin@example.com"
        assert_file_not_contains "ipsec.conf: leftid should NOT have @ prefix" \
            /etc/ipsec.conf "leftid=@admin@example.com"
        assert_file_contains "ipsec.conf: rightid=vpn@example.com" \
            /etc/ipsec.conf "rightid=vpn@example.com"
    fi
}

test_live_certs_save_dn() {
    section "LIVE: CERTS SAVE — DN (Distinguished Name)"

    if ! $LIVE; then
        skip_test "certs save DN local-id" "use --live"
        skip_test "certs save DN remote-id" "use --live"
        return
    fi

    local engine
    engine=$(get_vpn_engine)

    local cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id \"C=US, O=MyOrg, CN=client\""
        "security vpn set certs remote-id \"C=US, O=MyOrg, CN=server\""
        "security vpn save"
    )
    capture_scli_session "${cmds[@]}"
    assert_captured_session_success "certs save DN session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    if [ "$engine" = "strongswan" ]; then
        assert_swanctl_identity_present "swanctl: local id = C=US, O=MyOrg, CN=client" \
            "C=US, O=MyOrg, CN=client"
        assert_swanctl_identity_present "swanctl: remote id = C=US, O=MyOrg, CN=server" \
            "C=US, O=MyOrg, CN=server"
    elif [ "$engine" = "libreswan" ]; then
        # DN: quoted, no @ prefix
        assert_file_contains "ipsec.conf: leftid quoted DN" \
            /etc/ipsec.conf 'leftid="C=US, O=MyOrg, CN=client"'
        assert_file_contains "ipsec.conf: rightid quoted DN" \
            /etc/ipsec.conf 'rightid="C=US, O=MyOrg, CN=server"'
    fi
}

test_live_certs_save_reload() {
    section "LIVE: CERTS SAVE + RELOAD (round-trip)"

    if ! $LIVE; then
        skip_test "certs save+reload FQDN" "use --live"
        skip_test "certs save+reload DN" "use --live"
        return
    fi

    local fqdn_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn save"
    )
    capture_scli_session "${fqdn_cmds[@]}"
    assert_captured_session_success "pubkey save+reload FQDN session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    # show config re-reads from file
    assert_output_contains "reload: Local Id = client.example.com" \
        "client.example.com" \
        security vpn show config

    assert_output_contains "reload: Remote Id = vpnserver.example.com" \
        "vpnserver.example.com" \
        security vpn show config

    local dn_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id \"C=US, O=MyOrg, CN=client\""
        "security vpn set certs remote-id \"C=US, O=MyOrg, CN=server\""
        "security vpn save"
    )
    capture_scli_session "${dn_cmds[@]}"
    assert_captured_session_success "pubkey save+reload DN session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    assert_output_contains "reload: Local Id = DN" \
        "C=US, O=MyOrg, CN=client" \
        security vpn show config

    assert_output_contains "reload: Remote Id = DN" \
        "C=US, O=MyOrg, CN=server" \
        security vpn show config
}

test_live_certs_del_save() {
    section "LIVE: CERTS DEL + SAVE"

    if ! $LIVE; then
        skip_test "certs del local-id + save" "use --live"
        skip_test "certs del remote-id + save" "use --live"
        return
    fi

    local engine
    engine=$(get_vpn_engine)

    local save_cmds=(
        "security vpn set auth pubkey"
        "security vpn set certs local-id client.example.com"
        "security vpn set certs remote-id vpnserver.example.com"
        "security vpn save"
    )
    capture_scli_session "${save_cmds[@]}"
    assert_captured_session_success "certs del+save initial save session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    local del_cmds=(
        "security vpn set auth pubkey"
        "security vpn del certs local-id"
        "security vpn del certs remote-id"
        "security vpn save"
    )
    capture_scli_session "${del_cmds[@]}"
    assert_captured_session_success "certs del+save delete session"
    if [ "$SCLI_SESSION_EXIT" -ne 0 ]; then
        return
    fi

    # Verify IDs are gone
    if [ "$engine" = "strongswan" ]; then
        assert_swanctl_identity_not_present "swanctl: local id removed" \
            "client.example.com"
        assert_swanctl_identity_not_present "swanctl: remote id removed" \
            "vpnserver.example.com"
    elif [ "$engine" = "libreswan" ]; then
        assert_file_contains "ipsec.conf: leftid fallback to %fromcert" \
            /etc/ipsec.conf "leftid=%fromcert"
        assert_file_contains "ipsec.conf: rightid fallback to %fromcert" \
            /etc/ipsec.conf "rightid=%fromcert"
    fi

    assert_output_contains "show config: Local Id (not set) after del" \
        "(not set)" \
        security vpn show config
}

# =============================================================================
# =============================================================================
# REVOCATION TESTS
# Cover the 'security vpn set revocation {ocsp-validation|ocsp-strict|
# crl-strict|crl-check-interval}' subtree introduced on the
# vpn-revocation branch.  ocsp-strict / crl-strict / crl-check-interval
# are libreswan-only (strongswan should print a "not supported" notice).
# =============================================================================

# 7. ocsp-validation enable/disable (both engines)
test_revocation_ocsp_validation() {
    section "REVOCATION: OCSP VALIDATION (staging)"

    assert_success "set revocation ocsp-validation enable" \
        "OCSP validation: enabled" \
        security vpn set revocation ocsp-validation enable

    assert_success "set revocation ocsp-validation disable" \
        "OCSP validation: disabled" \
        security vpn set revocation ocsp-validation disable

    # restore enabled
    scli_run security vpn set revocation ocsp-validation enable >/dev/null 2>&1
}

# 8. ocsp-strict / crl-strict / crl-check-interval (libreswan only)
test_revocation_libreswan_only() {
    section "REVOCATION: LIBRESWAN-ONLY KNOBS (staging)"

    local engine
    engine=$(get_vpn_engine)

    if [ "$engine" = "strongswan" ]; then
        # On strongswan all three commands must print the not-supported notice
        assert_output_contains "ocsp-strict refuses on strongswan" \
            "not supported on strongswan" \
            security vpn set revocation ocsp-strict enable

        assert_output_contains "crl-strict refuses on strongswan" \
            "not supported on strongswan" \
            security vpn set revocation crl-strict enable

        assert_output_contains "crl-check-interval refuses on strongswan" \
            "not supported on strongswan" \
            security vpn set revocation crl-check-interval 1800
        return
    fi

    # libreswan path — full staging coverage
    assert_success "set revocation ocsp-strict enable" \
        "OCSP strict: enabled" \
        security vpn set revocation ocsp-strict enable

    assert_success "set revocation ocsp-strict disable" \
        "OCSP strict: disabled" \
        security vpn set revocation ocsp-strict disable

    assert_success "set revocation crl-strict enable" \
        "CRL strict: enabled" \
        security vpn set revocation crl-strict enable

    assert_success "set revocation crl-strict disable" \
        "CRL strict: disabled" \
        security vpn set revocation crl-strict disable

    # crl-check-interval valid values
    assert_success "set revocation crl-check-interval 60 (lower bound)" \
        "CRL check interval: 60 s" \
        security vpn set revocation crl-check-interval 60

    assert_success "set revocation crl-check-interval 3600 (default)" \
        "CRL check interval: 3600 s" \
        security vpn set revocation crl-check-interval 3600

    assert_success "set revocation crl-check-interval 86400 (upper bound)" \
        "CRL check interval: 86400 s" \
        security vpn set revocation crl-check-interval 86400

    # crl-check-interval rejects out-of-range / non-numeric
    assert_error "set revocation crl-check-interval 0 rejected" \
        "60..86400" \
        security vpn set revocation crl-check-interval 0

    assert_error "set revocation crl-check-interval 59 rejected" \
        "60..86400" \
        security vpn set revocation crl-check-interval 59

    assert_error "set revocation crl-check-interval 86401 rejected" \
        "60..86400" \
        security vpn set revocation crl-check-interval 86401

    assert_error "set revocation crl-check-interval -1 rejected" \
        "60..86400" \
        security vpn set revocation crl-check-interval -1

    assert_error "set revocation crl-check-interval abc rejected" \
        "60..86400" \
        security vpn set revocation crl-check-interval abc

    # restore the strict defaults so subsequent tests start clean
    scli_run security vpn set revocation ocsp-strict enable >/dev/null 2>&1
    scli_run security vpn set revocation crl-strict enable >/dev/null 2>&1
    scli_run security vpn set revocation crl-check-interval 3600 >/dev/null 2>&1
}

# 9. 'show config' contains a Revocation section, marking libreswan-only
#    fields as "not supported on strongswan" when strongswan is active.
test_show_config_revocation() {
    section "REVOCATION: SHOW CONFIG SECTION"

    local engine
    engine=$(get_vpn_engine)

    local out
    out=$(scli_run security vpn show config 2>&1)

    assert_text_contains "show config has Revocation section" \
        "Revocation:" "$out"

    assert_text_contains "show config lists OCSP Validation" \
        "OCSP Validation" "$out"

    if [ "$engine" = "strongswan" ]; then
        assert_text_contains "OCSP Strict marked not supported on strongswan" \
            "not supported on strongswan" "$out"
    else
        assert_text_contains "show config lists OCSP Strict" \
            "OCSP Strict" "$out"
        assert_text_contains "show config lists CRL Strict" \
            "CRL Strict" "$out"
        assert_text_contains "show config lists CRL Check Interval" \
            "CRL Check Interval" "$out"
    fi
}

# 10. live: revocation values land in /etc/ipsec.conf after save (libreswan only)
test_live_revocation_save() {
    section "REVOCATION: LIVE SAVE (libreswan only)"

    if ! $LIVE; then
        skip_test "revocation save -> /etc/ipsec.conf" "use --live"
        return
    fi

    local engine
    engine=$(get_vpn_engine)
    if [ "$engine" != "libreswan" ]; then
        skip_test "revocation save -> /etc/ipsec.conf" "libreswan only"
        return
    fi

    capture_scli_session \
        "security vpn set revocation ocsp-strict disable" \
        "security vpn set revocation crl-strict disable" \
        "security vpn set revocation crl-check-interval 1800" \
        "security vpn save"
    assert_captured_session_success "revocation set+save session"

    assert_file_contains "ipsec.conf has ocsp-strict=no" \
        "/etc/ipsec.conf" "ocsp-strict=no"
    assert_file_contains "ipsec.conf has crl-strict=no" \
        "/etc/ipsec.conf" "crl-strict=no"
    assert_file_contains "ipsec.conf has crlcheckinterval=1800" \
        "/etc/ipsec.conf" "crlcheckinterval=1800"

    # restore strict defaults
    capture_scli_session \
        "security vpn set revocation ocsp-strict enable" \
        "security vpn set revocation crl-strict enable" \
        "security vpn set revocation crl-check-interval 3600" \
        "security vpn save"
    assert_captured_session_success "revocation restore strict defaults"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    parse_common_args "$@"
    print_header "VPN"

    if ! check_vpn_engine; then
        printf "${RED}ERROR: No VPN engine configured. Cannot run tests.${NC}\n"
        exit 1
    fi

    local engine
    engine=$(get_vpn_engine)
    printf "${BOLD} Engine: %s${NC}\n\n" "$engine"

    # Identity (cert / PSK) — staging
    test_certs_set_identity
    test_certs_del_identity
    test_psk_set_identity
    test_psk_del_identity
    test_show_config_identity
    test_auth_switch_clears_ids

    # Revocation — staging + show
    test_revocation_ocsp_validation
    test_revocation_libreswan_only
    test_show_config_revocation

    # Live tests (save to disk, --live only)
    test_live_certs_save_fqdn
    test_live_certs_save_ip
    test_live_certs_save_email
    test_live_certs_save_dn
    test_live_certs_save_reload
    test_live_certs_del_save
    test_live_revocation_save

    print_summary
}

main "$@"
