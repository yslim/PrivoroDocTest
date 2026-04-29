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
    section "PASSWORD MIN LENGTH (admin policy)"

    # Set to 20
    assert_success \
        "Set admin password-min-length to 20" \
        "[admin] password-min-length = 20 characters" \
        system account set admin policy password-min-length 20

    # Verify in show policy
    assert_output_contains \
        "Show admin policy reflects min length 20" \
        "password-min-length: 20 characters" \
        system account show admin policy

    # Reject value below 15
    assert_error \
        "Reject password-min-length below 15" \
        "must be >= 15" \
        system account set admin policy password-min-length 10

    # Reject non-integer
    assert_error \
        "Reject password-min-length non-integer" \
        "must be an integer" \
        system account set admin policy password-min-length abc

    # Restore to default
    assert_success \
        "Restore admin password-min-length to 15" \
        "[admin] password-min-length = 15 characters" \
        system account set admin policy password-min-length 15
}

test_password_max_age() {
    section "PASSWORD MAX AGE (admin policy)"

    # Set to 60 days
    assert_success \
        "Set admin password-max-age to 60 days" \
        "[admin] password-max-age = 60 day(s)" \
        system account set admin policy password-max-age 60

    # Verify in show policy
    assert_output_contains \
        "Show admin policy reflects max age 60" \
        "password-max-age:" \
        system account show admin policy

    # Disable (set to 0)
    assert_success \
        "Disable admin password expiry (max-age 0)" \
        "[admin] password-max-age = disabled" \
        system account set admin policy password-max-age 0

    # Verify disabled in show policy
    assert_output_contains \
        "Show admin policy reflects max age disabled" \
        "disabled" \
        system account show admin policy

    # Reject negative
    assert_error \
        "Reject negative password-max-age" \
        "must be >= 0" \
        system account set admin policy password-max-age -1

    # Restore to default
    assert_success \
        "Restore admin password-max-age to 90" \
        "[admin] password-max-age = 90 day(s)" \
        system account set admin policy password-max-age 90
}

test_password_warn_days() {
    section "PASSWORD WARN DAYS (admin policy)"

    # Set to 14
    assert_success \
        "Set admin password-warn-days to 14" \
        "[admin] password-warn-days = 14 day(s)" \
        system account set admin policy password-warn-days 14

    # Verify in show policy (note: 2-space separator due to %-20s padding)
    assert_output_contains \
        "Show admin policy reflects warn days 14" \
        "password-warn-days:  14 day(s)" \
        system account show admin policy

    # Reject negative
    assert_error \
        "Reject negative password-warn-days" \
        "must be >= 0" \
        system account set admin policy password-warn-days -1

    # Restore to default
    assert_success \
        "Restore admin password-warn-days to 7" \
        "[admin] password-warn-days = 7 day(s)" \
        system account set admin policy password-warn-days 7
}

test_login_max_attempts() {
    section "LOGIN MAX ATTEMPTS (admin policy)"

    # Set to 5
    assert_success \
        "Set admin login-max-attempts to 5" \
        "[admin] login-max-attempts = 5" \
        system account set admin policy login-max-attempts 5

    # Verify in show policy (note: 2-space separator due to %-20s padding)
    assert_output_contains \
        "Show admin policy reflects max attempts 5" \
        "login-max-attempts:  5" \
        system account show admin policy

    # Verify PAM file updated
    assert_file_contains \
        "PAM common-auth updated with deny=5" \
        "$PAM_AUTH_FILE" \
        "deny=5"

    # Reject zero (range is 1..10)
    assert_error \
        "Reject login-max-attempts 0" \
        "must be in [1..10]" \
        system account set admin policy login-max-attempts 0

    # Reject negative
    assert_error \
        "Reject login-max-attempts negative" \
        "must be in [1..10]" \
        system account set admin policy login-max-attempts -1

    # Reject above upper bound
    assert_error \
        "Reject login-max-attempts above 10" \
        "must be in [1..10]" \
        system account set admin policy login-max-attempts 11

    # Restore to default
    assert_success \
        "Restore admin login-max-attempts to 3" \
        "[admin] login-max-attempts = 3" \
        system account set admin policy login-max-attempts 3

    # Verify PAM file restored
    assert_file_contains \
        "PAM common-auth restored with deny=3" \
        "$PAM_AUTH_FILE" \
        "deny=3"
}

test_login_lockout_time() {
    section "LOGIN LOCKOUT TIME (admin policy)"

    # Set to 300 seconds (lower bound)
    assert_success \
        "Set admin login-lockout-time to 300" \
        "[admin] login-lockout-time = 300 second(s)" \
        system account set admin policy login-lockout-time 300

    # Verify in show policy (note: 2-space separator due to %-20s padding)
    assert_output_contains \
        "Show admin policy reflects lockout time 300" \
        "login-lockout-time:  300 second(s)" \
        system account show admin policy

    # Verify PAM file updated
    assert_file_contains \
        "PAM common-auth updated with unlock_time=300" \
        "$PAM_AUTH_FILE" \
        "unlock_time=300"

    # Reject 0 — new policy requires range 300..7200 (no "permanent" option)
    assert_error \
        "Reject login-lockout-time 0 (out of range)" \
        "must be in [300..7200]" \
        system account set admin policy login-lockout-time 0

    # Reject just below lower bound
    assert_error \
        "Reject login-lockout-time 299" \
        "must be in [300..7200]" \
        system account set admin policy login-lockout-time 299

    # Reject above upper bound
    assert_error \
        "Reject login-lockout-time 7201" \
        "must be in [300..7200]" \
        system account set admin policy login-lockout-time 7201

    # Restore to default
    assert_success \
        "Restore admin login-lockout-time to 600" \
        "[admin] login-lockout-time = 600 second(s)" \
        system account set admin policy login-lockout-time 600

    # Verify PAM file restored
    assert_file_contains \
        "PAM common-auth restored with unlock_time=600" \
        "$PAM_AUTH_FILE" \
        "unlock_time=600"
}

test_show_policy() {
    section "SHOW POLICY (per-account)"

    # show admin policy contains the account header + all 5 fields
    assert_output_contains \
        "Show admin policy lists Account header" \
        "Account: admin" \
        system account show admin policy

    assert_output_contains \
        "Show admin policy contains password-min-length" \
        "password-min-length:" \
        system account show admin policy

    assert_output_contains \
        "Show admin policy contains password-max-age" \
        "password-max-age:" \
        system account show admin policy

    assert_output_contains \
        "Show admin policy contains password-warn-days" \
        "password-warn-days:" \
        system account show admin policy

    assert_output_contains \
        "Show admin policy contains login-max-attempts" \
        "login-max-attempts:" \
        system account show admin policy

    assert_output_contains \
        "Show admin policy contains login-lockout-time" \
        "login-lockout-time:" \
        system account show admin policy

    # Verify the same tree exists for recovery and user accounts.
    assert_output_contains \
        "Show recovery policy lists Account header" \
        "Account: recovery" \
        system account show recovery policy

    assert_output_contains \
        "Show user policy lists Account header" \
        "Account: user" \
        system account show user policy
}

test_show_status() {
    section "SHOW STATUS (per-account)"

    # Admin status — lowercase 'admin account: <state>' line
    assert_output_contains \
        "Show admin status contains account info" \
        "admin account:" \
        system account show admin status

    # Capture once and verify the three blocks (account / aging / faillock).
    local output
    output=$(scli_run system account show admin status)

    assert_text_contains "Show admin status contains password expiry info" \
        "Password expiry:" "$output"

    # New faillock line — output starts with either "Login failures:"
    # (not locked) or "Login lockout:" (locked).
    TOTAL=$((TOTAL + 1))
    if echo "$output" | grep -qE "^Login (failures|lockout):"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  Show admin status contains faillock line\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("Show admin status contains faillock line")
        printf "  ${RED}FAIL${NC}  Show admin status contains faillock line\n"
        printf "        output: %s\n" "$output"
    fi

    # Recovery status — same shape
    assert_output_contains \
        "Show recovery status contains account info" \
        "recovery account:" \
        system account show recovery status

    # User status
    assert_output_contains \
        "Show user status contains account info" \
        "user account:" \
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

    # Get current deny count from config (per-account: matches ssh user's policy)
    local deny_count
    deny_count=$(scli_run system account show "$SSH_USER" policy | grep "login-max-attempts:" | grep -o '[0-9]\+' | head -1)
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
# Recovery-admin branch tests
# ---------------------------------------------------------------------------

# Run a single SCLI command in a one-shot session as <user>.  Returns the
# command output (stdout+stderr) on stdout.
scli_run_as() {
    local user="$1"
    shift
    if [ "$(id -u)" -eq 0 ]; then
        printf '%s\nexit\n' "$*" | su - "$user" 2>&1
    else
        printf '%s\nexit\n' "$*" | sudo -n su - "$user" 2>&1
    fi
}

# 'system account reset admin-passwd' was added on the recovery-admin
# branch.  It is gated to the recovery account, prints a y/N confirm
# prompt, generates a 16-char one-time password, and back-dates the
# admin SCLI aging record so the next admin login forces a change.
test_recovery_reset_admin_passwd_permission() {
    section "RECOVERY: 'reset admin-passwd' permission"

    local out
    out=$(scli_run_as admin "system account reset admin-passwd")
    if echo "$out" | grep -qiE "permission denied|requires .*recovery"; then
        TOTAL=$((TOTAL + 1))
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  admin denied access to 'reset admin-passwd'\n"
    else
        TOTAL=$((TOTAL + 1))
        FAIL=$((FAIL + 1))
        FAILURES+=("admin denied access to 'reset admin-passwd'")
        printf "  ${RED}FAIL${NC}  admin denied access to 'reset admin-passwd'\n"
        printf "        output: %s\n" "$out"
    fi
}

# Recovery user runs 'reset admin-passwd' and answers 'no' to the y/N
# prompt — the command must cancel without changing /etc/shadow.
test_recovery_reset_admin_passwd_cancel() {
    section "RECOVERY: 'reset admin-passwd' y/N cancel path"

    if ! id recovery >/dev/null 2>&1; then
        skip_test "reset admin-passwd cancel" "recovery account not present"
        return
    fi

    local before_hash after_hash out
    before_hash=$(sudo grep '^admin:' /etc/shadow | cut -d: -f2)

    # Feed 'n' as the answer; SCLI shell wraps the command, so two
    # writes are needed — the SCLI command, then the prompt answer.
    if [ "$(id -u)" -eq 0 ]; then
        out=$(printf 'system account reset admin-passwd\nn\nexit\n' | su - recovery 2>&1)
    else
        out=$(printf 'system account reset admin-passwd\nn\nexit\n' | sudo -n su - recovery 2>&1)
    fi

    after_hash=$(sudo grep '^admin:' /etc/shadow | cut -d: -f2)

    assert_text_contains "y/N prompt cancels (output says Cancelled)" \
        "Cancelled" "$out"

    TOTAL=$((TOTAL + 1))
    if [ "$before_hash" = "$after_hash" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  /etc/shadow admin hash unchanged after cancel\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("/etc/shadow admin hash unchanged after cancel")
        printf "  ${RED}FAIL${NC}  /etc/shadow admin hash unchanged after cancel\n"
    fi
}

# 'exit' and 'date' got requiredLevel="all" so they survive recovery's
# strict whitelist while still being visible to admin and normal user.
test_basics_visible_for_all_levels() {
    section "RECOVERY: exit/date accessible to all levels"

    if ! id recovery >/dev/null 2>&1; then
        skip_test "basics access for recovery" "recovery account not present"
        return
    fi

    local out
    out=$(scli_run_as recovery "date")
    if echo "$out" | grep -qiE "permission denied|unknown command"; then
        TOTAL=$((TOTAL + 1))
        FAIL=$((FAIL + 1))
        FAILURES+=("recovery can run 'date'")
        printf "  ${RED}FAIL${NC}  recovery can run 'date'\n"
        printf "        output: %s\n" "$out"
    else
        TOTAL=$((TOTAL + 1))
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  recovery can run 'date'\n"
    fi

    # admin path (same command must still work)
    out=$(scli_run_as admin "date")
    if echo "$out" | grep -qiE "permission denied|unknown command"; then
        TOTAL=$((TOTAL + 1))
        FAIL=$((FAIL + 1))
        FAILURES+=("admin can run 'date'")
        printf "  ${RED}FAIL${NC}  admin can run 'date'\n"
    else
        TOTAL=$((TOTAL + 1))
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  admin can run 'date'\n"
    fi
}

# Recovery user must not see / run commands that change unrelated CLI
# settings (NDcPP "NO privilege to change any other CLI Setting").
# Each case below should be rejected with a 'requires admin'
# permission denied or 'unknown command' (after pruning).
test_recovery_strict_whitelist() {
    section "RECOVERY: strict whitelist (denied commands)"

    if ! id recovery >/dev/null 2>&1; then
        skip_test "recovery whitelist" "recovery account not present"
        return
    fi

    local cases=(
        # security tree — entire subtree gated as admin
        "security vpn show config"
        "security vpn set engine libreswan"
        # system children (audit / ntp / banner / etc.) — admin-only
        "system audit show status"
        "system ntp show config"
        "system banner show status"
        "system update show config"
        "system remote-access show status"
        "system session show status"
        "system serial-console show status"
        "system auto-logout show status"
        "system syslog-server show status"
        "system log show auth"
        # network state-modifying — admin-only
        "network interface create dummy0"
        # basics — destructive
        "basics reboot"
    )
    local cmd out
    for cmd in "${cases[@]}"; do
        out=$(scli_run_as recovery "$cmd")
        TOTAL=$((TOTAL + 1))
        if echo "$out" | grep -qiE "permission denied|unknown command|requires .*admin"; then
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  recovery denied: %s\n" "$cmd"
        else
            FAIL=$((FAIL + 1))
            FAILURES+=("recovery denied: $cmd")
            printf "  ${RED}FAIL${NC}  recovery denied: %s\n" "$cmd"
            printf "        output: %s\n" "$out"
        fi
    done
}

# Recovery's 'system' menu must list only 'account'; siblings (audit /
# ntp / banner / ...) carry admin annotations and disappear from the
# pruned tree.  We grep the 'help'-style listing produced by running
# the bare 'system' command.
test_recovery_system_subtree_visibility() {
    section "RECOVERY: 'system' subtree shows only 'account'"

    if ! id recovery >/dev/null 2>&1; then
        skip_test "recovery system subtree" "recovery account not present"
        return
    fi

    local out
    out=$(scli_run_as recovery "system")

    assert_text_contains "recovery sees 'system account'" \
        "account" "$out"

    # Every sibling under 'system' should be pruned for recovery.
    local siblings=(audit auto-logout banner log ntp remote-access \
                    serial-console session syslog-server update)
    local sib
    for sib in "${siblings[@]}"; do
        TOTAL=$((TOTAL + 1))
        if echo "$out" | grep -qE "^[[:space:]]*${sib}\b"; then
            FAIL=$((FAIL + 1))
            FAILURES+=("recovery system pruned: $sib")
            printf "  ${RED}FAIL${NC}  recovery should NOT see 'system %s'\n" "$sib"
        else
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  recovery does not see 'system %s'\n" "$sib"
        fi
    done
}

# 'security' subtree is admin-only; recovery's top-level menu and
# direct invocation should both deny access.
test_recovery_security_denied() {
    section "RECOVERY: 'security' subtree denied entirely"

    if ! id recovery >/dev/null 2>&1; then
        skip_test "recovery security denied" "recovery account not present"
        return
    fi

    local top
    top=$(scli_run_as recovery "")
    TOTAL=$((TOTAL + 1))
    if echo "$top" | grep -qE "^[[:space:]]*security\b"; then
        FAIL=$((FAIL + 1))
        FAILURES+=("recovery top menu hides 'security'")
        printf "  ${RED}FAIL${NC}  recovery top menu should NOT list 'security'\n"
    else
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  recovery top menu does not list 'security'\n"
    fi

    local out
    out=$(scli_run_as recovery "security vpn show config")
    TOTAL=$((TOTAL + 1))
    if echo "$out" | grep -qiE "permission denied|unknown command|requires .*admin"; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}PASS${NC}  recovery cannot run 'security vpn show config'\n"
    else
        FAIL=$((FAIL + 1))
        FAILURES+=("recovery cannot run security vpn show config")
        printf "  ${RED}FAIL${NC}  recovery should be denied: 'security vpn show config'\n"
        printf "        output: %s\n" "$out"
    fi
}

# Recovery user can run the admin-recovery actions that the branch
# explicitly enables: show admin status, set admin policy, set admin
# unlock, set recovery passwd (own).
test_recovery_allowed_admin_recovery_actions() {
    section "RECOVERY: allowed admin-recovery actions"

    if ! id recovery >/dev/null 2>&1; then
        skip_test "recovery allowed actions" "recovery account not present"
        return
    fi

    local cmds=(
        "system account show admin status"
        "system account show admin policy"
        "system account show recovery status"
        "system account set admin unlock"
    )
    local cmd out
    for cmd in "${cmds[@]}"; do
        out=$(scli_run_as recovery "$cmd")
        TOTAL=$((TOTAL + 1))
        if echo "$out" | grep -qiE "permission denied|unknown command"; then
            FAIL=$((FAIL + 1))
            FAILURES+=("recovery allowed: $cmd")
            printf "  ${RED}FAIL${NC}  recovery allowed: %s\n" "$cmd"
            printf "        output: %s\n" "$out"
        else
            PASS=$((PASS + 1))
            printf "  ${GREEN}PASS${NC}  recovery allowed: %s\n" "$cmd"
        fi
    done
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

    # Recovery-admin branch features
    test_recovery_reset_admin_passwd_permission
    test_recovery_reset_admin_passwd_cancel
    test_basics_visible_for_all_levels
    test_recovery_strict_whitelist
    test_recovery_system_subtree_visibility
    test_recovery_security_denied
    test_recovery_allowed_admin_recovery_actions

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
