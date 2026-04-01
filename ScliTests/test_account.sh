#!/usr/bin/env bash
# =============================================================================
# Account Security CLI Integration Test Suite for shiba-scli
#
# Tests NIAP FIA_PMG_EXT.1 (Password Management) and FIA_AFL.1
# (Authentication Failure Handling) related features.
#
# Runs on a real Linux device with PAM faillock configured.
# Uses one-shot mode (SCLI_ONESHOT=1) to run each command independently.
#
# Usage:
#   bash tests/test_account.sh                  # uses 'scli' from $PATH
#   bash tests/test_account.sh -v               # verbose (show command + output)
#   bash tests/test_account.sh --verbose         # same as -v
#   bash tests/test_account.sh --live            # enable SSH faillock tests
#   bash tests/test_account.sh -v --live         # verbose + live
#   SCLI_BIN=/path/to/scli bash tests/test_account.sh
#
# Prerequisites:
#   - Linux device with PAM faillock (pam_faillock.so)
#   - /etc/scli.yml configuration file
#   - Passwordless sudo (or run as root)
#   - scli binary built and accessible
#   - sshpass (only for --live SSH faillock tests)
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Load common test framework
# ---------------------------------------------------------------------------
source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Account-specific configuration
# ---------------------------------------------------------------------------
CONFIG_FILE="/etc/scli.yml"
CONFIG_BACKUP="/tmp/scli.yml.test_backup"
PAM_AUTH_FILE="/etc/pam.d/common-auth"

# For --live SSH faillock tests
TARGET_HOST="${TARGET_HOST:-localhost}"
SSH_USER="${SSH_USER:-admin}"
SSH_CORRECT_PASS="${SSH_CORRECT_PASS:-}"

# ---------------------------------------------------------------------------
# Backup / Restore helpers
# ---------------------------------------------------------------------------

backup_config() {
    if [ -f "$CONFIG_FILE" ]; then
        sudo cp "$CONFIG_FILE" "$CONFIG_BACKUP"
    fi
}

restore_config() {
    if [ -f "$CONFIG_BACKUP" ]; then
        sudo cp "$CONFIG_BACKUP" "$CONFIG_FILE"
        sudo chown root:root "$CONFIG_FILE"
        sudo chmod 644 "$CONFIG_FILE"
        rm -f "$CONFIG_BACKUP"
    fi
}

# ---------------------------------------------------------------------------
# Test Sections
# ---------------------------------------------------------------------------

test_password_min_length() {
    section "PASSWORD MIN LENGTH"

    # Set to 20
    assert_success \
        "Set password-min-length to 20" \
        "Minimum password length set to 20" \
        system account set password-min-length 20

    # Verify in show policy
    assert_output_contains \
        "Show policy reflects min length 20" \
        "Password min length: 20" \
        system account show policy

    # Reject value below 15
    assert_error \
        "Reject password-min-length below 15" \
        "at least 15" \
        system account set password-min-length 10

    # Reject non-integer
    assert_error \
        "Reject password-min-length non-integer" \
        "at least 15" \
        system account set password-min-length abc

    # Restore to default
    assert_success \
        "Restore password-min-length to 15" \
        "Minimum password length set to 15" \
        system account set password-min-length 15
}

test_password_max_age() {
    section "PASSWORD MAX AGE"

    # Set to 60 days
    assert_success \
        "Set password-max-age to 60 days" \
        "Password max age set to 60" \
        system account set password-max-age 60

    # Verify in show policy
    assert_output_contains \
        "Show policy reflects max age 60" \
        "Password max age: 60 day(s)" \
        system account show policy

    # Disable (set to 0)
    assert_success \
        "Disable password expiry (max-age 0)" \
        "Password expiry disabled" \
        system account set password-max-age 0

    # Verify disabled in show policy
    assert_output_contains \
        "Show policy reflects max age disabled" \
        "Password max age: disabled" \
        system account show policy

    # Reject negative
    assert_error \
        "Reject negative password-max-age" \
        "non-negative integer" \
        system account set password-max-age -1

    # Restore to default
    assert_success \
        "Restore password-max-age to 90" \
        "Password max age set to 90" \
        system account set password-max-age 90
}

test_password_warn_days() {
    section "PASSWORD WARN DAYS"

    # Set to 14
    assert_success \
        "Set password-warn-days to 14" \
        "Password warning period set to 14" \
        system account set password-warn-days 14

    # Verify in show policy
    assert_output_contains \
        "Show policy reflects warn days 14" \
        "Password warn days: 14" \
        system account show policy

    # Reject negative
    assert_error \
        "Reject negative password-warn-days" \
        "non-negative integer" \
        system account set password-warn-days -1

    # Restore to default
    assert_success \
        "Restore password-warn-days to 7" \
        "Password warning period set to 7" \
        system account set password-warn-days 7
}

test_login_max_attempts() {
    section "LOGIN MAX ATTEMPTS"

    # Set to 5
    assert_success \
        "Set login-max-attempts to 5" \
        "Login max attempts set to 5" \
        system account set login-max-attempts 5

    # Verify in show policy
    assert_output_contains \
        "Show policy reflects max attempts 5" \
        "Login max attempts: 5" \
        system account show policy

    # Verify PAM file updated
    assert_file_contains \
        "PAM common-auth updated with deny=5" \
        "$PAM_AUTH_FILE" \
        "deny=5"

    # Reject zero
    assert_error \
        "Reject login-max-attempts 0" \
        "positive integer" \
        system account set login-max-attempts 0

    # Reject negative
    assert_error \
        "Reject login-max-attempts negative" \
        "positive integer" \
        system account set login-max-attempts -1

    # Restore to default
    assert_success \
        "Restore login-max-attempts to 3" \
        "Login max attempts set to 3" \
        system account set login-max-attempts 3

    # Verify PAM file restored
    assert_file_contains \
        "PAM common-auth restored with deny=3" \
        "$PAM_AUTH_FILE" \
        "deny=3"
}

test_login_lockout_time() {
    section "LOGIN LOCKOUT TIME"

    # Set to 300 seconds
    assert_success \
        "Set login-lockout-time to 300" \
        "Login lockout time set to 300" \
        system account set login-lockout-time 300

    # Verify in show policy
    assert_output_contains \
        "Show policy reflects lockout time 300" \
        "Login lockout time: 300 second(s)" \
        system account show policy

    # Verify PAM file updated
    assert_file_contains \
        "PAM common-auth updated with unlock_time=300" \
        "$PAM_AUTH_FILE" \
        "unlock_time=300"

    # Set to permanent (0)
    assert_success \
        "Set login-lockout-time to permanent (0)" \
        "permanent" \
        system account set login-lockout-time 0

    # Verify permanent in show policy
    assert_output_contains \
        "Show policy reflects permanent lockout" \
        "permanent" \
        system account show policy

    # Verify PAM file updated
    assert_file_contains \
        "PAM common-auth updated with unlock_time=0" \
        "$PAM_AUTH_FILE" \
        "unlock_time=0"

    # Restore to default
    assert_success \
        "Restore login-lockout-time to 600" \
        "Login lockout time set to 600" \
        system account set login-lockout-time 600

    # Verify PAM file restored
    assert_file_contains \
        "PAM common-auth restored with unlock_time=600" \
        "$PAM_AUTH_FILE" \
        "unlock_time=600"
}

test_show_policy() {
    section "SHOW POLICY"

    # Verify all 5 fields are present
    assert_output_contains \
        "Show policy contains password min length" \
        "Password min length:" \
        system account show policy

    assert_output_contains \
        "Show policy contains password max age" \
        "Password max age:" \
        system account show policy

    assert_output_contains \
        "Show policy contains password warn days" \
        "Password warn days:" \
        system account show policy

    assert_output_contains \
        "Show policy contains login max attempts" \
        "Login max attempts:" \
        system account show policy

    assert_output_contains \
        "Show policy contains login lockout time" \
        "Login lockout time:" \
        system account show policy
}

test_show_status() {
    section "SHOW STATUS"

    # Admin status
    assert_output_contains \
        "Show admin status contains account info" \
        "Admin account" \
        system account show admin status

    # Admin password expiry info
    local output
    output=$(scli_run system account show admin status)
    if echo "$output" | grep -qF "Password expiry:"; then
        TOTAL=$((TOTAL + 1))
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  Show admin status contains password expiry info\n"
    else
        TOTAL=$((TOTAL + 1))
        FAIL=$((FAIL + 1))
        FAILURES+=("Show admin status contains password expiry info")
        printf "  ${RED}FAIL${NC}  Show admin status contains password expiry info\n"
        printf "        output: %s\n" "$output"
    fi

    # User status
    assert_output_contains \
        "Show user status contains account info" \
        "account" \
        system account show user status
}

test_account_unlock() {
    section "ACCOUNT UNLOCK"

    # Admin unlock
    assert_success \
        "Admin account unlock" \
        "reset" \
        system account set admin unlock

    # User unlock
    assert_success \
        "User account unlock" \
        "reset" \
        system account set user unlock
}

# ---------------------------------------------------------------------------
# Password validation helper (uses hidden internal command)
# ---------------------------------------------------------------------------
validate_pw() {
    echo "$1" | "$SCLI_BIN" system internal-validate-password 2>&1
}

assert_pw_valid() {
    local desc="$1" password="$2"
    TOTAL=$((TOTAL + 1))
    local output exit_code=0
    output=$(validate_pw "$password") || exit_code=$?
    if [ $exit_code -eq 0 ] && echo "$output" | grep -qF "OK"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("$desc")
        printf "  ${RED}FAIL${NC}  %s (expected valid)\n" "$desc"
        printf "        got: %s\n" "$output"
    fi
}

assert_pw_invalid() {
    local desc="$1" password="$2" expected="$3"
    TOTAL=$((TOTAL + 1))
    local output exit_code=0
    output=$(validate_pw "$password") || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        if [ -n "$expected" ]; then
            if echo "$output" | grep -qiF "$expected"; then
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
        printf "  ${RED}FAIL${NC}  %s (expected rejection, got OK)\n" "$desc"
    fi
}

# ---------------------------------------------------------------------------
# Password complexity tests
# ---------------------------------------------------------------------------
test_password_complexity() {
    section "PASSWORD COMPLEXITY"

    # Test passwords use chars spread across the keyboard to avoid triggering
    # keyboard sequential pattern detection (e.g. "123", "jkl", "ijk").
    assert_pw_valid   "Accept valid password (all rules satisfied)"          "Zmt#Rvx5Bnq8\$Hpw"
    assert_pw_invalid "Reject missing lowercase"        "ZMT#RVX5BNQ8\$HPW"  "lowercase"
    assert_pw_invalid "Reject missing uppercase"        "zmt#rvx5bnq8\$hpw"  "uppercase"
    assert_pw_invalid "Reject missing digit"            "ZmtcRvxgBn#q\$Hpw"  "digit"
    assert_pw_invalid "Reject missing special char"     "Zmt4Rvx5Bnq8Hpw6"  "special character"
    assert_pw_invalid "Reject too short (< 15)"         "Zm#5Rv"             "at least"
    assert_pw_valid   "Accept allowed special chars ()" "Zmt(Rvx5Bnq8)Hpw"
    assert_pw_valid   "Accept allowed special chars -_" "Zmt_Rvx5Bnq8-Hpw"
    assert_pw_valid   "Accept allowed special chars +=" "Zmt+Rvx5Bnq8=Hpw"
    assert_pw_invalid "Reject disallowed char ~"        "Zmt~Rvx5Bnq8#Hpw"  "disallowed"
    assert_pw_invalid "Reject disallowed char {}"       "Zmt{Rvx5Bnq8#Hpw"  "disallowed"
}

test_consecutive_chars() {
    section "CONSECUTIVE CHARACTERS"

    assert_pw_invalid "Reject 3 consecutive identical (aaa)"   "Zmtaaa#Rv5Bnq8Hp"   "consecutive"
    assert_pw_invalid "Reject 3 consecutive identical (111)"   "ZmtRvx#nq8Hp1119"   "consecutive"
    assert_pw_valid   "Accept 2 consecutive identical (aa)"    "ZmtaaRvx#5Bnq8Hp"
}

test_keyboard_patterns() {
    section "KEYBOARD PATTERNS"

    assert_pw_invalid "Reject horizontal pattern (qwerty)"  "Abcqwerty1#hijk"   "keyboard"
    assert_pw_invalid "Reject horizontal pattern (asdf)"    "Xasdf12345#hijk"   "keyboard"
    assert_pw_invalid "Reject reverse pattern (rewq)"       "Xrewq12345#hijk"   "keyboard"
}

test_faillock_ssh() {
    section "PAM FAILLOCK SSH TESTS (live)"

    # Check sshpass availability
    if ! command -v sshpass &>/dev/null; then
        skip_test "SSH faillock tests" "sshpass not installed"
        return
    fi

    if [ -z "$SSH_CORRECT_PASS" ]; then
        skip_test "SSH faillock tests" "SSH_CORRECT_PASS not set"
        return
    fi

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

    # First, reset any existing lockout
    sudo faillock --user "$SSH_USER" --reset 2>/dev/null

    # Get current deny count from config
    local deny_count
    deny_count=$(scli_run system account show policy | grep "Login max attempts:" | grep -o '[0-9]*')
    if [ -z "$deny_count" ]; then
        deny_count=3
    fi

    # Attempt wrong password N times to trigger lockout
    printf "  ${CYAN}INFO${NC}  Attempting %d failed logins to trigger lockout...\n" "$deny_count"
    for i in $(seq 1 "$deny_count"); do
        sshpass -p "WRONG_PASSWORD_${i}" ssh $ssh_opts "$SSH_USER@$TARGET_HOST" exit 2>/dev/null || true
    done

    # Verify faillock records exist
    assert_cmd \
        "Faillock records show failures for $SSH_USER" \
        "$SSH_USER" \
        sudo faillock --user "$SSH_USER"

    # Verify account is locked (correct password should fail)
    TOTAL=$((TOTAL + 1))
    local lock_output lock_exit=0
    lock_output=$(sshpass -p "$SSH_CORRECT_PASS" ssh $ssh_opts "$SSH_USER@$TARGET_HOST" echo "LOGIN_OK" 2>&1) || lock_exit=$?
    if [ $lock_exit -ne 0 ] && ! echo "$lock_output" | grep -qF "LOGIN_OK"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  Account locked: correct password rejected after %d failures\n" "$deny_count"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("Account locked after $deny_count failures")
        printf "  ${RED}FAIL${NC}  Account should be locked but login succeeded\n"
    fi

    # Unlock via faillock reset
    sudo faillock --user "$SSH_USER" --reset

    # Verify login works after unlock
    TOTAL=$((TOTAL + 1))
    local unlock_output unlock_exit=0
    unlock_output=$(sshpass -p "$SSH_CORRECT_PASS" ssh $ssh_opts "$SSH_USER@$TARGET_HOST" echo "LOGIN_OK" 2>&1) || unlock_exit=$?
    if echo "$unlock_output" | grep -qF "LOGIN_OK"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  Account unlocked: login succeeds after reset\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("Account unlock: login after reset")
        printf "  ${RED}FAIL${NC}  Login should succeed after unlock but failed (exit=%d)\n" "$unlock_exit"
        printf "        output: %s\n" "$unlock_output"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_common_args "$@"
    print_header "Account Security"

    # Backup config
    backup_config

    # Trap to restore config on exit
    trap restore_config EXIT

    # Run test sections
    test_password_min_length
    test_password_max_age
    test_password_warn_days
    test_login_max_attempts
    test_login_lockout_time
    test_show_policy
    test_show_status
    test_account_unlock
    test_password_complexity
    test_consecutive_chars
    test_keyboard_patterns

    # SSH faillock tests (only when --live is passed)
    if $LIVE; then
        test_faillock_ssh
    else
        section "PAM FAILLOCK SSH TESTS (skipped, use --live)"
    fi

    # Restore config (also done by trap)
    restore_config

    print_summary
}

main "$@"
