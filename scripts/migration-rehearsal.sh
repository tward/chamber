#!/usr/bin/env bash
#
# Rehearses the schema version 0 to version 1 migration on a copy of a real vault.
#
# The real vault is only ever read, with `cp`. The copy lives under a fake HOME in a temp
# directory, and the new binary migrates the copy when it opens it. A second, untouched copy is
# kept beside it so the original can be restored if anything ever goes wrong.
#
# The copy is throwaway. The vault UUID and device ID minted here must never be used again: do
# not point a sync directory at this sandbox and do not keep the migrated copy.
#
# Run it from a terminal, with no chamber process running. It asks for your real master key
# three times: to list (which decrypts every entry), to publish, and to merge the published file
# back (which runs the real data through every snapshot validation rule).
#
# Usage: bash scripts/migration-rehearsal.sh
#   CHAMBER_VAULT=/path/vault.sqlite3   rehearse on this vault instead of the default one
#   CHAMBER_BIN=/path/to/chamber        use this new binary instead of building one
#   OLD_CHAMBER_BIN=/path/to/chamber    also show what a pre-sync binary does to a migrated copy
#   KEEP_SANDBOX=1                      keep the sandbox even when every check passes
#
# Exit status: 0 when every check passed, 1 when any failed, 2 when the run could not start.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -t 0 ] || [ ! -t 1 ]; then
    echo "Run this from a terminal: chamber reads the master key from /dev/tty." >&2
    exit 2
fi
for tool in sqlite3 pgrep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "This script needs $tool." >&2
        exit 2
    fi
done
if command -v sha256sum >/dev/null 2>&1; then
    SHA="sha256sum"
else
    SHA="shasum -a 256"
fi

# ---- Source vault ----

case "$(uname -s)" in
    Darwin)
        CONFIG_REL="Library/Application Support"
        DATA_REL="Library/Application Support"
        default_src="$HOME/$CONFIG_REL/chamber/vault.sqlite3"
        ;;
    *)
        CONFIG_REL=".config"
        DATA_REL=".local/share"
        default_src="${XDG_CONFIG_HOME:-$HOME/.config}/chamber/vault.sqlite3"
        ;;
esac
SRC="${CHAMBER_VAULT:-$default_src}"
if [ ! -f "$SRC" ]; then
    echo "No vault at $SRC" >&2
    exit 2
fi
if pgrep -x chamber >/dev/null; then
    echo "A chamber process is running. Close it first: copying a database in use is unsafe." >&2
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

# ---- Sandbox ----

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/chamber-migration.XXXXXX")" || exit 2
FAKE="$ROOT/home"
PRISTINE="$ROOT/pristine"
COPY="$FAKE/$CONFIG_REL/chamber/vault.sqlite3"
SYNC="$FAKE/$DATA_REL/chamber/sync"
mkdir -p "$(dirname "$COPY")" "$PRISTINE"

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

# chamber <args...>: runs the new binary against the copy. The XDG variables and
# CHAMBER_SYNC_DIR are removed so that the fake HOME alone decides every default path.
chamber() {
    printf '\n[copy] chamber %s\n' "$*" >&2
    env -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u CHAMBER_SYNC_DIR HOME="$FAKE" "$BIN" "$@"
}

# q <sql>: runs one query against the copy.
q() { sqlite3 "$COPY" "$1"; }

# Digests of the original vault files, to show that the run never changed them.
digest_originals() {
    local file
    for file in "$SRC" "$SRC-wal" "$SRC-shm"; do
        if [ -f "$file" ]; then $SHA "$file"; else echo "absent  $file"; fi
    done
}

# The columns that exist in both schema versions, as one digest. Names are unique before the
# migration and nothing merges here, so ordering by name is stable.
ROWS_SQL="SELECT name, kind, hex(nonce), hex(ciphertext), created_at, updated_at FROM items ORDER BY name, hex(ciphertext);"
META_SQL="SELECT kdf_params, hex(wrapped_key), hex(verifier) FROM meta;"
SYNC_META_SQL="SELECT hex(vault_uuid), hex(device_id), hwm_wall_ms, hwm_counter FROM sync_meta;"

rows_digest() { q "$ROWS_SQL" | $SHA; }
meta_digest() { q "$META_SQL" | $SHA; }

# ---- 1. Copy ----

step "1. Copy the vault"
originals_before="$(digest_originals)"
for suffix in "" "-wal" "-shm"; do
    if [ -f "$SRC$suffix" ]; then
        cp -p "$SRC$suffix" "$COPY$suffix" || exit 2
        cp -p "$SRC$suffix" "$PRISTINE/vault.sqlite3$suffix" || exit 2
    fi
done
echo "  Source:        $SRC"
echo "  Working copy:  $COPY"
echo "  Pristine copy: $PRISTINE/vault.sqlite3"

version_before="$(q 'PRAGMA user_version;')"
if [ "$version_before" != 0 ]; then
    echo "The copy is at schema version $version_before, not 0, so there is no migration to rehearse." >&2
    echo "Sandbox kept at $ROOT" >&2
    exit 2
fi
count_before="$(q 'SELECT count(*) FROM items;')"
rows_before="$(rows_digest)"
meta_before="$(meta_digest)"
echo "  Schema version 0, $count_before entries."

# ---- 2. Migrate and decrypt ----

step "2. Open the copy with the new binary"
echo "Next: type your real master key. Listing decrypts every entry; the list itself is not shown."
listed="$(
    chamber list | grep -c ' - created '
    exit "${PIPESTATUS[0]}"
)"
list_status=$?
check "the new binary opens the copy and decrypts every entry" [ "$list_status" -eq 0 ]
check "it lists all $count_before entries (listed: $listed)" [ "$listed" = "$count_before" ]

if [ "$(digest_originals)" != "$originals_before" ]; then
    fail "the original vault files are unchanged"
    echo >&2
    echo "The ORIGINAL vault changed during this run. Stop here." >&2
    echo "An untouched copy from before the run is in $PRISTINE" >&2
    exit 1
fi
pass "the original vault files are unchanged"

# ---- 3. What the migration did ----

step "3. The migrated copy"
check "schema version is 1" [ "$(q 'PRAGMA user_version;')" = 1 ]
check "the entry count is unchanged" [ "$(q 'SELECT count(*) FROM items;')" = "$count_before" ]
check "every name, kind, nonce, ciphertext, and timestamp is unchanged" \
    [ "$(rows_digest)" = "$rows_before" ]
check "the wrapped vault key and KDF parameters are unchanged" [ "$(meta_digest)" = "$meta_before" ]
check "every entry has a 16-byte UUID and a complete revision" \
    [ "$(q 'SELECT count(*) FROM items WHERE uuid IS NULL OR length(uuid) != 16 OR rev_wall_ms IS NULL OR rev_counter IS NULL OR rev_device_id IS NULL OR length(rev_device_id) != 16;')" = 0 ]
check "every entry UUID is distinct" \
    [ "$(q 'SELECT count(DISTINCT uuid) FROM items;')" = "$count_before" ]
check "one vault identity row exists" [ "$(q 'SELECT count(*) FROM sync_meta;')" = 1 ]
check "every revision is seeded with counter 0 and this device ID" \
    [ "$(q 'SELECT count(*) FROM items WHERE rev_counter != 0 OR rev_device_id != (SELECT device_id FROM sync_meta);')" = 0 ]
check "the high-water mark is the greatest seeded revision" \
    [ "$(q 'SELECT hwm_wall_ms = (SELECT coalesce(max(rev_wall_ms), 0) FROM items) AND hwm_counter = 0 FROM sync_meta;')" = 1 ]
check "there are no tombstones" [ "$(q 'SELECT count(*) FROM tombstones;')" = 0 ]
check "the unique index on name is gone" \
    [ "$(q "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_items_name';")" = 0 ]
check "the unique index on uuid exists" \
    [ "$(q "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_items_uuid';")" = 1 ]

# ---- 4. Reopening ----

step "4. Reopening does not migrate again"
identity_before="$(q "$SYNC_META_SQL")"
echo "Next: no prompt is expected. Joining an initialized vault is refused, which still opens it."
chamber sync join "$ROOT/absent.chenroll"
check "the vault and device IDs and the high-water mark are unchanged" \
    [ "$(q "$SYNC_META_SQL")" = "$identity_before" ]
check "the entries are unchanged" [ "$(rows_digest)" = "$rows_before" ]

# ---- 5. Real data through a snapshot ----

step "5. Publish the migrated copy and merge its own snapshot back"
echo "Next: type your real master key twice more, once per command."
chamber sync publish
check "publish succeeds" [ $? -eq 0 ]
chamber sync merge | tee "$ROOT/merge.txt"
check "the published snapshot passes validation and merges (exit status 0)" [ "${PIPESTATUS[0]}" -eq 0 ]
if grep -q 'Skipped' "$ROOT/merge.txt"; then
    fail "no file is skipped"
else
    pass "no file is skipped"
fi
check "the entries are still unchanged" [ "$(rows_digest)" = "$rows_before" ]
check "exactly one snapshot file was published" [ "$(ls "$SYNC" | grep -c '\.chsnap$')" -eq 1 ]

# ---- 6. Optional: a pre-sync binary on the migrated copy ----

if [ -n "${OLD_CHAMBER_BIN:-}" ]; then
    step "6. Information only: the old binary on a migrated copy"
    OLD_HOME="$ROOT/old-home"
    OLD_COPY="$OLD_HOME/$CONFIG_REL/chamber/vault.sqlite3"
    mkdir -p "$(dirname "$OLD_COPY")"
    sqlite3 "$COPY" "VACUUM INTO '$OLD_COPY';"
    echo "Next: type your real master key for the old binary."
    printf '\n[old binary] chamber list\n' >&2
    env -u XDG_CONFIG_HOME -u XDG_DATA_HOME HOME="$OLD_HOME" "$OLD_CHAMBER_BIN" list >/dev/null
    echo "  INFO  old binary list exit status: $?"
    echo "  INFO  unique index on name present afterwards: $(sqlite3 "$OLD_COPY" "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_items_name';")"
    echo "  INFO  schema version afterwards: $(sqlite3 "$OLD_COPY" 'PRAGMA user_version;')"
fi

# ---- Summary ----

step "Summary"
check "the original vault files are unchanged at the end" [ "$(digest_originals)" = "$originals_before" ]

echo
if [ "$failures" -eq 0 ]; then
    echo "All checks passed."
    if [ -n "${KEEP_SANDBOX:-}" ]; then
        echo "Sandbox kept at $ROOT. It holds copies of your vault: remove it when done."
    else
        rm -rf "$ROOT"
        echo "Sandbox removed."
    fi
    exit 0
fi
echo "$failures check(s) failed."
echo "Sandbox kept at $ROOT. It holds copies of your vault: remove it when done."
exit 1
