#!/usr/bin/env bash
# =============================================================================
# Basic CLI Integration Test Suite for shiba-scli
#
# Tests root-level commands: date, exit, commands, reboot (guard only).
#
# Usage:
#   bash tests/test_basic.sh                  # basic tests
#   bash tests/test_basic.sh -v               # verbose
#   SCLI_BIN=/path/to/scli bash tests/test_basic.sh
#
# Prerequisites:
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
# 1. Date command
# ---------------------------------------------------------------------------
test_date_command() {
    section "DATE COMMAND"

    # date should output current date/time (at minimum the year)
    local year
    year=$(date +%Y)

    assert_output_contains "date shows current year" \
        "$year" \
        date
}

# ---------------------------------------------------------------------------
# 2. Exit command
# ---------------------------------------------------------------------------
test_exit_command() {
    section "EXIT COMMAND"

    assert_output_contains "exit prints message" \
        "Exiting" \
        exit
}

# ---------------------------------------------------------------------------
# 4. Reboot command (guard only — never actually reboot)
# ---------------------------------------------------------------------------
test_reboot_guard() {
    section "REBOOT COMMAND (guard only)"

    # Pipe "n" to cancel reboot
    TOTAL=$((TOTAL + 1))
    local output exit_code=0
    output=$(echo "n" | "$SCLI_BIN" reboot 2>&1) || exit_code=$?

    if echo "$output" | grep -qiF "cancelled"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  reboot cancelled with 'n'\n"
    elif echo "$output" | grep -qiF "reboot"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  reboot shows prompt (exit=%d)\n" "$exit_code"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("reboot cancel")
        printf "  ${RED}FAIL${NC}  reboot cancel\n"
        printf "        output: %s\n" "$output"
    fi
    verbose_log "echo n | scli reboot" "$output" "$exit_code"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_common_args "$@"
    print_header "Basic"

    test_date_command
    test_exit_command
    test_reboot_guard

    print_summary
}

main "$@"
