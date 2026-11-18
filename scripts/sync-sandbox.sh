#!/usr/bin/env bash
#
# End-to-end run of `chamber sync` with the real binary and two fake machines.
#
# A "machine" is a directory used as HOME for one `chamber` process, so each machine has its own
# vault, registry, and sync directory at the default paths. Copying snapshot files between the
# two sync directories stands in for the transport.
#
# Run it from a terminal: every unlock asks for the master key on /dev/tty, so nothing here can
# type it for you. The master key is `a` on machine A and `b` on machine B. Expect about 26
# prompts. The CLI has no delete command, so the one deletion is done by hand in the TUI.
#
# Usage: bash scripts/sync-sandbox.sh
#   CHAMBER_BIN=/path/to/chamber   use this binary instead of building one
#   SANDBOX_ROOT=/path             use this directory (it must not exist) instead of a temp one
#
# Exit status: 0 when every check passed, 1 when any failed, 2 when the run could not start.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -t 0 ] || [ ! -t 1 ]; then
    echo "Run this from a terminal: chamber reads master keys from /dev/tty." >&2
    exit 2
fi

# ---- Binary ----

if [ -n "${CHAMBER_BIN:-}" ]; then
    BIN="$CHAMBER_BIN"
else
    (cd "$REPO" && cargo build -p chamber-tui --bin chamber) || exit 2
    BIN="${CARGO_TARGET_DIR:-$REPO/target}/debug/chamber"
fi
if [ ! -x "$BIN" ]; then
    echo "No chamber binary at $BIN" >&2
    exit 2
fi

# ---- Sandbox layout ----

ROOT="${SANDBOX_ROOT:-}"
if [ -z "$ROOT" ]; then
    ROOT="$(mktemp -d "${TMPDIR:-/tmp}/chamber-sandbox.XXXXXX")" || exit 2
elif [ -e "$ROOT" ]; then
    echo "SANDBOX_ROOT already exists: $ROOT" >&2
    exit 2
else
    mkdir -p "$ROOT" || exit 2
fi

A="$ROOT/machine-a"
B="$ROOT/machine-b"
OUT="$ROOT/out"
PKG="$ROOT/transfer/b.chenroll"
mkdir -p "$A" "$B" "$OUT" "$ROOT/transfer"

# Where the `dirs` crate puts the config and data directories under a home directory.
case "$(uname -s)" in
    Darwin)
        CONFIG_REL="Library/Application Support"
        DATA_REL="Library/Application Support"
        ;;
    *)
        CONFIG_REL=".config"
        DATA_REL=".local/share"
        ;;
esac
A_VAULT="$A/$CONFIG_REL/chamber/vault.sqlite3"
A_SYNC="$A/$DATA_REL/chamber/sync"
B_SYNC="$B/$DATA_REL/chamber/sync"

# ---- Helpers ----

failures=0

pass() { printf '  PASS  %s\n' "$1"; }

fail() {
    printf '  FAIL  %s\n' "$1"
    failures=$((failures + 1))
}

step() { printf '\n== %s ==\n' "$1"; }

# check <description> <command...>: passes when the command succeeds.
check() {
    local what=$1
    shift
    if "$@"; then pass "$what"; else fail "$what"; fi
}

# expect_ok <description> <status> and expect_fail <description> <status>
expect_ok() { if [ "$2" -eq 0 ]; then pass "$1"; else fail "$1 (exit status $2)"; fi; }
expect_fail() { if [ "$2" -ne 0 ]; then pass "$1"; else fail "$1 (exit status 0)"; fi; }

home_of() {
    case "$1" in
        A) echo "$A" ;;
        B) echo "$B" ;;
    esac
}

key_of() {
    case "$1" in
        A) echo a ;;
        B) echo b ;;
    esac
}

# chamber <machine> <args...>: runs the binary as that machine. The XDG variables and
# CHAMBER_SYNC_DIR are removed so that HOME alone decides every default path.
chamber() {
    local machine=$1
    shift
    printf '\n[%s] chamber %s    (master key: %s)\n' "$machine" "$*" "$(key_of "$machine")" >&2
    env -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u CHAMBER_SYNC_DIR HOME="$(home_of "$machine")" "$BIN" "$@"
}

copy_snapshots() {
    mkdir -p "$2"
    cp "$1"/*.chsnap "$2"/
}

mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# normalized <list-output-file>: one line per entry as `name [kind] created-timestamp`, sorted.
# Drops the bullet and the relative age, which differ between two runs.
normalized() {
    grep ' - created ' "$1" | sed -e 's/^[^ ]* //' -e 's/ - created .* (\(.*\))$/ \1/' | sort
}

# ---- 1. Isolation guard ----

step "1. An uninitialized vault is refused, and the fake home is in effect"
chamber A sync publish
expect_fail "sync publish refuses an uninitialized vault without asking for a key" $?
if [ ! -f "$A_VAULT" ]; then
    echo "The vault was not created at $A_VAULT, so HOME does not redirect chamber here." >&2
    echo "Stopping before anything can touch a real vault." >&2
    exit 2
fi
pass "the vault file is created under the fake home"

# ---- 2. Machine A ----

step "2. Machine A: create a vault with two entries"
chamber A init
expect_ok "init" $?
chamber A add -n sbx-alpha -k password -v alpha-v1
expect_ok "add sbx-alpha" $?
chamber A add -n sbx-beta -k note -v beta-v1
expect_ok "add sbx-beta" $?

# ---- 3. Enrollment ----

step "3. Enroll machine B"
chamber A sync enroll "$PKG"
expect_ok "enroll writes a package" $?
check "the package is readable by its owner only" [ "$(mode_of "$PKG")" = 600 ]

echo
echo "Next: type the transfer secret shown above, answer y, then set the master key b twice."
chamber B sync join "$PKG"
expect_ok "join" $?
check "join leaves the package in place" test -f "$PKG"

echo
echo "Next: no prompt is expected. A second join must be refused outright."
chamber B sync join "$PKG"
expect_fail "join refuses an initialized vault" $?

# ---- 4. Offline changes ----

step "4. Both machines change the vault while disconnected"
chamber A update -n sbx-alpha -v alpha-from-a
expect_ok "A edits sbx-alpha" $?
chamber A add -n sbx-dup -k note -v dup-from-a
expect_ok "A adds sbx-dup" $?
chamber B add -n sbx-dup -k note -v dup-from-b
expect_ok "B adds its own sbx-dup" $?
chamber B update -n sbx-alpha -v alpha-from-b
expect_ok "B edits sbx-alpha after A did" $?

echo
echo "Next: the TUI opens as machine B. Unlock with b, delete the entry sbx-beta, then quit."
read -r -p "Press Enter to open the TUI. " _
chamber B
expect_ok "the TUI exits cleanly" $?

chamber A update -n sbx-beta -v beta-edited-after-delete
expect_ok "A edits sbx-beta after B deleted it" $?

# ---- 5. Exchange ----

step "5. Exchange snapshots: A publishes, B merges and publishes, A merges"
chamber A sync
expect_ok "A sync" $?
copy_snapshots "$A_SYNC" "$B_SYNC"
chamber B sync
expect_ok "B sync" $?
copy_snapshots "$B_SYNC" "$A_SYNC"
chamber A sync
expect_ok "A sync" $?

# ---- 6. Convergence ----

step "6. Both machines hold the same state"
chamber A list | tee "$OUT/list-a.txt"
chamber B list | tee "$OUT/list-b.txt"
normalized "$OUT/list-a.txt" >"$OUT/norm-a.txt"
normalized "$OUT/list-b.txt" >"$OUT/norm-b.txt"
check "the listing is not empty" test -s "$OUT/norm-a.txt"
check "both machines list the same entries" cmp -s "$OUT/norm-a.txt" "$OUT/norm-b.txt"
check "sbx-alpha is listed" grep -q '^sbx-alpha \[' "$OUT/norm-a.txt"
if grep -q 'sbx-beta' "$OUT/norm-a.txt" "$OUT/norm-b.txt"; then
    fail "sbx-beta is gone from both machines (the delete beats the later edit)"
else
    pass "sbx-beta is gone from both machines (the delete beats the later edit)"
fi
dups="$(grep -c '^sbx-dup ([0-9a-f]\{8\}) \[' "$OUT/norm-a.txt")"
check "both sbx-dup entries are kept and listed with a UUID suffix" [ "$dups" -eq 2 ]

value_a="$(chamber A get -n sbx-alpha)"
value_b="$(chamber B get -n sbx-alpha)"
check "A holds the later edit of sbx-alpha" [ "$value_a" = alpha-from-b ]
check "B holds the later edit of sbx-alpha" [ "$value_b" = alpha-from-b ]

check "each sync directory holds one file per machine" \
    [ "$(ls "$A_SYNC" | grep -c '\.chsnap$')" -eq 2 ]
if ls -A "$A_SYNC" "$B_SYNC" | grep -q '\.tmp$'; then
    fail "no temporary file is left in a sync directory"
else
    pass "no temporary file is left in a sync directory"
fi
if grep -r -a -q -e 'sbx-' -e 'alpha-' -e 'beta-' -e 'dup-from' "$A_SYNC" "$B_SYNC" "$PKG"; then
    fail "no entry name or value is readable in the snapshots or the package"
else
    pass "no entry name or value is readable in the snapshots or the package"
fi

# ---- 7. Shared names ----

step "7. A name shared by two entries"
chamber A get -n sbx-dup </dev/null >"$OUT/dup-noninteractive.txt"
expect_fail "get fails when the name is shared and stdin is not a terminal" $?
check "and it prints no value" [ ! -s "$OUT/dup-noninteractive.txt" ]

echo
echo "Next: a numbered list appears after the key. Choose 1."
dup_value="$(chamber A get -n sbx-dup)"
case "$dup_value" in
    dup-from-a | dup-from-b) pass "choosing from the list returns one of the two values" ;;
    *) fail "choosing from the list returns one of the two values (got '$dup_value')" ;;
esac

# ---- 8. Hostile sync directory ----

step "8. Machine B merges a directory holding damaged and irrelevant files"
valid="$(ls "$B_SYNC"/*.chsnap | head -n 1)"
size="$(($(wc -c <"$valid")))"
head -c "$((size - 10))" "$valid" >"$B_SYNC/partial.chsnap"
head -c 300 /dev/urandom >"$B_SYNC/junk.chsnap"
cp "$valid" "$B_SYNC/$(basename "$valid" .chsnap).sync-conflict-20261117-120000-ABCDEFG.chsnap"
cp "$PKG" "$B_SYNC/renamed-package.chsnap"
cp "$PKG" "$B_SYNC/b.chenroll"
cp "$valid" "$B_SYNC/.hidden.chsnap"
ln -s "$valid" "$B_SYNC/link.chsnap"
mkdir "$B_SYNC/nested"
cp "$valid" "$B_SYNC/nested/inner.chsnap"

chamber B sync merge | tee "$OUT/hostile.txt"
expect_fail "merge exits non-zero when a file was skipped" "${PIPESTATUS[0]}"
check "the truncated file is skipped" grep -q 'Skipped partial\.chsnap' "$OUT/hostile.txt"
check "the random file is skipped" grep -q 'Skipped junk\.chsnap' "$OUT/hostile.txt"
check "the renamed enrollment package is skipped" \
    grep -q 'Skipped renamed-package\.chsnap' "$OUT/hostile.txt"
check "the conflict copy is merged" grep -q 'Merged .*sync-conflict.*\.chsnap' "$OUT/hostile.txt"
for ignored in .hidden.chsnap link.chsnap b.chenroll inner.chsnap; do
    if grep -q -F "$ignored" "$OUT/hostile.txt"; then
        fail "$ignored is not a candidate and is not reported"
    else
        pass "$ignored is not a candidate and is not reported"
    fi
done

chamber B list >"$OUT/list-b-after.txt"
normalized "$OUT/list-b-after.txt" >"$OUT/norm-b-after.txt"
check "machine B is unchanged by that merge" cmp -s "$OUT/norm-b.txt" "$OUT/norm-b-after.txt"

# ---- Summary ----

echo
echo "Sandbox kept at $ROOT (remove it with: rm -rf \"$ROOT\")"
if [ "$failures" -eq 0 ]; then
    echo "All checks passed."
    exit 0
fi
echo "$failures check(s) failed."
exit 1
