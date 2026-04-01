#!/usr/bin/env bash
# =============================================================================
# Common Test Framework for shiba-scli integration tests
#
# Source this file from each test script:
#   source "$(dirname "$0")/common.sh"
#
# Provides:
#   - Color definitions
#   - Pass/fail/skip counters
#   - scli_run, verbose_log
#   - assert_success, assert_error, assert_output_contains,
#     assert_output_not_contains, assert_dir_not_exists
#   - assert_file_contains, assert_cmd, assert_cmd_fail
#   - skip_test, section
#   - print_summary (call at the end of main)
#   - parse_common_args (call at the start of main)
# =============================================================================

# ---------------------------------------------------------------------------
# Configuration (can be overridden before sourcing)
# ---------------------------------------------------------------------------
SCLI_BIN="${SCLI_BIN:-scli}"
VERBOSE=false
LIVE=false
export SCLI_ONESHOT=1

# ---------------------------------------------------------------------------
# Counters & state
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0
TOTAL=0
FAILURES=()

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

# Run scli and capture combined stdout+stderr; return the exit code.
scli_run() {
    "$SCLI_BIN" "$@" 2>&1
}

# verbose_log <cmd_args_string> <output> <exit_code>
#   Print command, exit code, and output when VERBOSE=true.
verbose_log() {
    if $VERBOSE; then
        local cmd_str="$1" output="$2" exit_code="$3"
        printf "        ${CYAN}cmd:${NC}  %s %s\n" "$SCLI_BIN" "$cmd_str"
        printf "        ${CYAN}exit:${NC} %d\n" "$exit_code"
        if [ -n "$output" ]; then
            printf "        ${CYAN}out:${NC}\n"
            echo "$output" | sed 's/^/          /'
        fi
    fi
}

# assert_success <description> <expected-substring> <args...>
#   Runs the command. PASS if output contains the expected substring.
assert_success() {
    local desc="$1" expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(scli_run "$@") || exit_code=$?

    if echo "$output" | grep -qF -- "$expected"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected to contain: %s\n" "$expected"
        printf "        got (exit=%d): %s\n" "$exit_code" "$output"
    fi
    verbose_log "$*" "$output" "$exit_code"
}

# assert_error <description> <expected-error-substring> <args...>
#   Runs the command. PASS if output contains "Error" or "error" (or non-zero exit)
#   AND the expected substring is found (if non-empty).
assert_error() {
    local desc="$1" expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(scli_run "$@") || exit_code=$?

    local has_error=false
    if echo "$output" | grep -qi -- "error\|unknown command\|required flag"; then
        has_error=true
    elif [ $exit_code -ne 0 ]; then
        has_error=true
    fi

    if $has_error; then
        if [ -n "$expected" ]; then
            if echo "$output" | grep -qiF -- "$expected"; then
                PASS=$((PASS + 1))
                printf "  ${GREEN}PASS${NC}  %s (correctly rejected)\n" "$desc"
            else
                FAIL=$((FAIL + 1))
                FAILURES+=("$desc")
                printf "  ${RED}FAIL${NC}  %s\n" "$desc"
                printf "        expected error containing: %s\n" "$expected"
                printf "        got: %s\n" "$output"
            fi
        else
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  %s (correctly rejected)\n" "$desc"
        fi
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s (expected error, got success)\n" "$desc"
        printf "        output: %s\n" "$output"
    fi
    verbose_log "$*" "$output" "$exit_code"
}

# assert_output_contains <description> <needle> <args...>
#   Runs the command. PASS if needle is found in output.
assert_output_contains() {
    local desc="$1" needle="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(scli_run "$@") || exit_code=$?

    if echo "$output" | grep -qF -- "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected to find: %s\n" "$needle"
        printf "        in output:\n%s\n" "$output"
    fi
    verbose_log "$*" "$output" "$exit_code"
}

# assert_output_not_contains <description> <needle> <args...>
#   Runs the command. PASS if needle is NOT found in output.
assert_output_not_contains() {
    local desc="$1" needle="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$(scli_run "$@") || exit_code=$?

    if ! echo "$output" | grep -qF -- "$needle"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected NOT to find: %s\n" "$needle"
    fi
    verbose_log "$*" "$output" "$exit_code"
}

# assert_dir_not_exists <description> <path>
assert_dir_not_exists() {
    local desc="$1" path="$2"
    TOTAL=$((TOTAL + 1))
    if [ ! -d "$path" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s (directory still exists)\n" "$desc"
    fi
}

# assert_file_contains <description> <file> <needle>
#   PASS if file contains the needle string.
assert_file_contains() {
    local desc="$1" file="$2" needle="$3"
    TOTAL=$((TOTAL + 1))

    if sudo grep -qF "$needle" "$file" 2>/dev/null; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected %s to contain: %s\n" "$file" "$needle"
    fi
}

# assert_cmd <description> <expected-substring> <command...>
#   Runs an arbitrary command (not scli). PASS if output contains expected.
assert_cmd() {
    local desc="$1" expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$("$@" 2>&1) || exit_code=$?

    if echo "$output" | grep -qF -- "$expected"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s\n" "$desc"
        printf "        expected to contain: %s\n" "$expected"
        printf "        got (exit=%d): %s\n" "$exit_code" "$output"
    fi
}

# assert_cmd_fail <description> <command...>
#   Runs an arbitrary command. PASS if it fails (non-zero exit).
assert_cmd_fail() {
    local desc="$1"
    shift
    TOTAL=$((TOTAL + 1))

    local output exit_code=0
    output=$("$@" 2>&1) || exit_code=$?

    if [ $exit_code -ne 0 ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s (correctly failed)\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s (expected failure, got success)\n" "$desc"
        printf "        output: %s\n" "$output"
    fi
}

# skip_test <description> <reason>
skip_test() {
    local desc="$1" reason="$2"
    TOTAL=$((TOTAL + 1))
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}SKIP${NC}  %s (%s)\n" "$desc" "$reason"
}

section() {
    printf "\n${BOLD}${CYAN}===== %s =====${NC}\n" "$1"
}

# ---------------------------------------------------------------------------
# parse_common_args: call from main() to parse -v/--verbose, --live
# ---------------------------------------------------------------------------
parse_common_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose) VERBOSE=true; shift ;;
            --live) LIVE=true; shift ;;
            *) shift ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# print_header <suite-name>: prints test suite banner
# ---------------------------------------------------------------------------
print_header() {
    local suite_name="$1"
    printf "${BOLD}============================================${NC}\n"
    printf "${BOLD} SHIBA SCLI %s Test Suite${NC}\n" "$suite_name"
    printf "${BOLD} Date:   $(date '+%Y-%m-%d %H:%M:%S')${NC}\n"
    printf "${BOLD} Binary: %s${NC}\n" "$SCLI_BIN"
    if $VERBOSE; then
        printf "${BOLD} Mode:   ${YELLOW}VERBOSE${NC}\n"
    fi
    if $LIVE; then
        printf "${BOLD} Mode:   ${RED}LIVE (save tests enabled)${NC}\n"
    fi
    printf "${BOLD}============================================${NC}\n"

    # Verify binary exists
    if ! command -v "$SCLI_BIN" &>/dev/null; then
        printf "${RED}ERROR: scli binary not found: %s${NC}\n" "$SCLI_BIN"
        printf "Set SCLI_BIN=/path/to/scli and try again.\n"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# print_summary: call at the end of main
# ---------------------------------------------------------------------------
print_summary() {
    printf "\n${BOLD}============================================${NC}\n"
    printf "${BOLD} RESULTS: "
    printf "${GREEN}%d passed${NC}" "$PASS"
    if [ "$SKIP" -gt 0 ]; then
        printf ", ${YELLOW}%d skipped${NC}" "$SKIP"
    fi
    if [ "$FAIL" -gt 0 ]; then
        printf ", ${RED}%d failed${NC}" "$FAIL"
    else
        printf ", ${GREEN}0 failed${NC}"
    fi
    printf "  (total: %d)\n" "$TOTAL"
    printf "${BOLD}============================================${NC}\n"

    if [ ${#FAILURES[@]} -gt 0 ]; then
        printf "\n${RED}Failed tests:${NC}\n"
        for f in "${FAILURES[@]}"; do
            printf "  - %s\n" "$f"
        done
    fi

    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
    exit 0
}
