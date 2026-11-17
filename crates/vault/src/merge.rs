//! Merging: combining another machine's copy of a vault into the local database.
//!
//! A [`SyncState`] is a vault's complete synchronization state: every entry exactly as stored
//! (still encrypted) and every tombstone. [`Db::export_sync_state`] reads one consistently, and
//! [`Db::merge_sync_state`] merges one into the local database in a single transaction.
//!
//! The outcome of a merge depends only on entry UUIDs, revisions, content digests
//! ([`content_digest`]), and tombstones. Names, timestamps, and the order of entries or
//! tombstones within a state play no part, which makes merging idempotent, commutative, and
//! associative: copies that exchange states in any order converge on the same state.
//!
//! Merging never decrypts anything, never assigns a revision, and never reads the clock.

use crate::db::{
    Db, parse_timestamp, read_sync_meta, read_tombstones, wall_ms_from_sql, wall_ms_to_sql, write_high_water_mark,
};
use crate::revision::{HighWaterMark, Revision};
use color_eyre::Result;
use color_eyre::eyre::eyre;
use rusqlite::{Connection, OptionalExtension, Row, params};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

/// One vault entry exactly as stored, without the local row ID.
///
/// `nonce` and `ciphertext` are opaque here: nothing in this module decrypts them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEntry {
    /// The entry's permanent UUID, which identifies it across devices.
    pub uuid: Uuid,
    pub name: String,
    /// The kind string as stored, for example `password`.
    pub kind: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// When the entry was created, by the writing device's clock. Display data only.
    pub created_at: OffsetDateTime,
    /// When the entry was last written, by the writing device's clock. Display data only.
    pub updated_at: OffsetDateTime,
    /// The revision of the entry's latest write, as assigned by the device that made it.
    pub revision: Revision,
}

/// A vault's complete synchronization state.
///
/// [`Db::export_sync_state`] returns `entries` ascending by UUID bytes and `tombstones`
/// ascending by bytes, so two databases with the same logical state return equal values.
/// [`Db::merge_sync_state`] accepts them in any order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncState {
    /// Every live entry.
    pub entries: Vec<SyncEntry>,
    /// The UUID of every deleted entry.
    pub tombstones: Vec<Uuid>,
}

/// What a merge did, as returned by [`Db::merge_sync_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MergeCounts {
    /// Incoming entries inserted because no local entry or tombstone had their UUID.
    pub added: usize,
    /// Local entries replaced by an incoming entry that won the comparison.
    pub replaced: usize,
    /// Local live entries removed by an incoming tombstone. An incoming tombstone that removed
    /// nothing is not counted.
    pub removed: usize,
    /// Incoming entries that changed nothing: blocked by a tombstone, older than the local
    /// entry, equal to it, losing a digest tie, or losing to a duplicate of the same UUID in
    /// the same state.
    pub unchanged: usize,
}

/// The content digest of an entry, used to break ties between equal revisions.
///
/// SHA-256 over the UUID bytes, the name, the kind, the nonce, and the ciphertext, in that
/// order, each preceded by its length in bytes as a 32-bit big-endian integer, so that field
/// boundaries are unambiguous. Timestamps and the revision are not covered.
///
/// A field longer than `u32::MAX` bytes has its length prefix saturated at `u32::MAX`. Such a
/// field cannot be stored (`SQLite` limits a value to well under that), so a merge carrying one
/// fails when it writes it.
#[must_use]
pub fn content_digest(entry: &SyncEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let fields: [&[u8]; 5] = [
        entry.uuid.as_bytes(),
        entry.name.as_bytes(),
        entry.kind.as_bytes(),
        &entry.nonce,
        &entry.ciphertext,
    ];
    for field in fields {
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        hasher.update(len.to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Whether `incoming` should replace `local`, which has the same UUID.
///
/// The greater revision wins. On equal revisions the greater content digest, compared as
/// unsigned bytes, wins; equal digests mean the entries are the same and nothing changes.
fn incoming_wins(incoming: &SyncEntry, local: &SyncEntry) -> bool {
    match incoming.revision.cmp(&local.revision) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => content_digest(incoming) > content_digest(local),
    }
}

/// A total order over entries with the same UUID, used only to choose one among duplicates
/// within a single incoming state. It extends the revision-then-digest rule with the
/// timestamps (the only fields the digest does not cover), so the choice never depends on the
/// order of the entries.
fn duplicate_order(a: &SyncEntry, b: &SyncEntry) -> Ordering {
    a.revision
        .cmp(&b.revision)
        .then_with(|| content_digest(a).cmp(&content_digest(b)))
        .then_with(|| a.created_at.cmp(&b.created_at))
        .then_with(|| a.updated_at.cmp(&b.updated_at))
}

/// Keeps one entry per UUID: the greatest under [`duplicate_order`]. The result iterates in
/// ascending UUID byte order.
fn preferred_by_uuid(entries: &[SyncEntry]) -> BTreeMap<[u8; 16], &SyncEntry> {
    let mut chosen: BTreeMap<[u8; 16], &SyncEntry> = BTreeMap::new();
    for entry in entries {
        chosen
            .entry(*entry.uuid.as_bytes())
            .and_modify(|current| {
                if duplicate_order(entry, current) == Ordering::Greater {
                    *current = entry;
                }
            })
            .or_insert(entry);
    }
    chosen
}

/// The `items` columns of a [`SyncEntry`], in the order [`entry_from_row`] reads them and
/// the `?1` to `?10` order of [`INSERT_ENTRY`] and [`REPLACE_ENTRY`].
const ENTRY_COLUMNS: &str =
    "uuid, name, kind, nonce, ciphertext, created_at, updated_at, rev_wall_ms, rev_counter, rev_device_id";

/// Builds a [`SyncEntry`] from columns 0 to 9 of a row selected with [`ENTRY_COLUMNS`].
fn entry_from_row(r: &Row<'_>) -> rusqlite::Result<SyncEntry> {
    Ok(SyncEntry {
        uuid: Uuid::from_bytes(r.get::<_, [u8; 16]>(0)?),
        name: r.get(1)?,
        kind: r.get(2)?,
        nonce: r.get(3)?,
        ciphertext: r.get(4)?,
        created_at: parse_timestamp(5, &r.get::<_, String>(5)?)?,
        updated_at: parse_timestamp(6, &r.get::<_, String>(6)?)?,
        revision: Revision {
            wall_ms: wall_ms_from_sql(r.get(7)?),
            counter: r.get(8)?,
            device_id: Uuid::from_bytes(r.get::<_, [u8; 16]>(9)?),
        },
    })
}

/// Formats a carried timestamp for storage: RFC 3339 in UTC, like every stored timestamp.
fn stamp(t: OffsetDateTime) -> Result<String> {
    let utc = t
        .checked_to_offset(UtcOffset::UTC)
        .ok_or_else(|| eyre!("The timestamp {t} cannot be expressed in UTC"))?;
    Ok(utc.format(&Rfc3339)?)
}

/// What merging one incoming entry did.
enum EntryOutcome {
    Added,
    Replaced,
    Unchanged,
}

/// Inserts a carried entry as a new row.
const INSERT_ENTRY: &str = "INSERT INTO items (uuid, name, kind, nonce, ciphertext, created_at, updated_at, \
     rev_wall_ms, rev_counter, rev_device_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

/// Overwrites every carried field of the row with the same UUID. Entry UUIDs are unique and
/// the UUID itself does not change, so the row keeps its local row ID.
const REPLACE_ENTRY: &str = "UPDATE items SET name = ?2, kind = ?3, nonce = ?4, ciphertext = ?5, \
     created_at = ?6, updated_at = ?7, rev_wall_ms = ?8, rev_counter = ?9, rev_device_id = ?10 \
     WHERE uuid = ?1";

/// Records every incoming tombstone and removes the local live entries they name. Returns the
/// number of entries removed.
fn apply_tombstones(conn: &Connection, tombstones: &[Uuid]) -> Result<usize> {
    let unique: BTreeSet<[u8; 16]> = tombstones.iter().map(|u| *u.as_bytes()).collect();
    let mut record = conn.prepare("INSERT OR IGNORE INTO tombstones (uuid) VALUES (?1)")?;
    let mut remove = conn.prepare("DELETE FROM items WHERE uuid = ?1")?;
    let mut removed = 0;
    for uuid in &unique {
        record.execute(params![uuid])?;
        removed += remove.execute(params![uuid])?;
    }
    Ok(removed)
}

/// Merges one incoming entry, already chosen among any duplicates of its UUID, after the
/// incoming tombstones have been applied.
fn merge_entry(conn: &Connection, incoming: &SyncEntry) -> Result<EntryOutcome> {
    let uuid = incoming.uuid.as_bytes();
    let tombstoned: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM tombstones WHERE uuid = ?1)",
        params![uuid],
        |r| r.get(0),
    )?;
    if tombstoned {
        return Ok(EntryOutcome::Unchanged);
    }

    let local = conn
        .query_row(
            &format!("SELECT {ENTRY_COLUMNS} FROM items WHERE uuid = ?1"),
            params![uuid],
            entry_from_row,
        )
        .optional()?;
    let (sql, outcome) = match local {
        None => (INSERT_ENTRY, EntryOutcome::Added),
        Some(local) if incoming_wins(incoming, &local) => (REPLACE_ENTRY, EntryOutcome::Replaced),
        Some(_) => return Ok(EntryOutcome::Unchanged),
    };

    write_entry(conn, sql, incoming)?;
    Ok(outcome)
}

/// Runs `sql` ([`INSERT_ENTRY`] or [`REPLACE_ENTRY`]) with every carried field of `entry`.
fn write_entry(conn: &Connection, sql: &str, entry: &SyncEntry) -> Result<()> {
    conn.execute(
        sql,
        params![
            entry.uuid.as_bytes(),
            entry.name,
            entry.kind,
            entry.nonce,
            entry.ciphertext,
            stamp(entry.created_at)?,
            stamp(entry.updated_at)?,
            wall_ms_to_sql(entry.revision.wall_ms),
            entry.revision.counter,
            entry.revision.device_id.as_bytes(),
        ],
    )?;
    Ok(())
}

/// Inserts `entry` as a new row exactly as carried (UUID, name, kind, nonce, ciphertext, both
/// timestamps as RFC 3339 in UTC, and revision). Nothing is checked first: a row with the same
/// UUID makes the insert fail on the unique index.
///
/// # Errors
/// Returns an error if a timestamp cannot be formatted or the insert fails.
pub(crate) fn insert_entry(conn: &Connection, entry: &SyncEntry) -> Result<()> {
    write_entry(conn, INSERT_ENTRY, entry)
}

/// Reads every entry exactly as stored, ascending by UUID bytes, and every tombstone, ascending
/// by bytes. The caller provides the transaction that makes the two reads consistent.
///
/// # Errors
/// Returns an error if the database cannot be read or a stored row is malformed.
pub(crate) fn read_sync_state(conn: &Connection) -> Result<SyncState> {
    let entries = {
        let mut stmt = conn.prepare(&format!("SELECT {ENTRY_COLUMNS} FROM items ORDER BY uuid ASC"))?;
        stmt.query_map([], entry_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let tombstones = read_tombstones(conn)?;
    Ok(SyncState { entries, tombstones })
}

/// Raises the stored high-water mark to the greatest `(wall_ms, counter)` among its current
/// value and every revision in `entries`. It never decreases.
fn raise_high_water_mark(conn: &Connection, entries: &[SyncEntry]) -> Result<()> {
    let current = read_sync_meta(conn)?.hwm;
    let raised = entries
        .iter()
        .map(|e| e.revision.high_water_mark())
        .fold(current, HighWaterMark::max);
    if raised > current {
        write_high_water_mark(conn, raised)?;
    }
    Ok(())
}

impl Db {
    /// Returns this vault's complete synchronization state: every entry exactly as stored and
    /// every tombstone.
    ///
    /// Both are read inside one read transaction, so a write committed by another process
    /// meanwhile is either wholly included or not at all. Entries are ascending by UUID bytes
    /// and tombstones ascending by bytes, so two databases with the same logical state return
    /// equal values. Nothing is decrypted.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read, or a stored row is malformed (a
    /// timestamp that is not RFC 3339, a `uuid`, `rev_device_id`, or tombstone that is not a
    /// 16-byte blob, or a `rev_counter` that does not fit in a `u32`).
    pub fn export_sync_state(&self) -> Result<SyncState> {
        let tx = self.read_transaction()?;
        let state = read_sync_state(&tx)?;
        tx.commit()?;
        Ok(state)
    }

    /// Merges another copy's synchronization state into this database.
    ///
    /// Everything happens in one `IMMEDIATE` transaction, which takes the write lock up front:
    /// 1. Every incoming tombstone is recorded, and a local live entry with that UUID is
    ///    removed. Revisions play no part: a tombstone always wins.
    /// 2. An incoming entry whose UUID has a local tombstone (including one recorded in step 1)
    ///    changes nothing.
    /// 3. An incoming entry with no local entry of its UUID is inserted.
    /// 4. An incoming entry with a local entry of its UUID replaces it if its revision is
    ///    greater. On equal revisions it replaces the local entry only if its
    ///    [`content_digest`] is greater (as unsigned bytes); equal digests change nothing.
    /// 5. The high-water mark is raised to the greatest `(wall_ms, counter)` among its current
    ///    value and every incoming entry's revision, including entries that lost or were
    ///    blocked by a tombstone. It never decreases.
    ///
    /// An inserted or replaced row is written exactly as carried (UUID, name, kind, nonce,
    /// ciphertext, both timestamps, and revision); a replaced row keeps its local row ID.
    /// Timestamps are stored as RFC 3339 in UTC. A losing entry is discarded, not combined.
    /// An entry missing from `state` means nothing: only tombstones delete. Names play no part,
    /// so entries sharing a name are all kept. Nothing is decrypted, no revision is assigned,
    /// and the clock is not read.
    ///
    /// The result does not depend on the order of `state.entries` or `state.tombstones`. A
    /// UUID listed both as an entry and as a tombstone ends up deleted. A UUID listed more than
    /// once among the entries is resolved by the same revision and digest rules (then by the
    /// timestamps, if the duplicates differ only there) before it is merged; the losing
    /// duplicates count as unchanged.
    ///
    /// No kinds, names, or nonce lengths are validated here.
    ///
    /// # Errors
    /// Returns an error if a carried timestamp cannot be formatted as RFC 3339, a stored row is
    /// malformed, or any database operation fails (for example the database is locked, or a
    /// value is too large to store). The transaction is then rolled back: no entry, tombstone,
    /// or high-water mark change is kept.
    pub fn merge_sync_state(&self, state: &SyncState) -> Result<MergeCounts> {
        let tx = self.write_transaction()?;
        let mut counts = MergeCounts {
            removed: apply_tombstones(&tx, &state.tombstones)?,
            ..MergeCounts::default()
        };

        let chosen = preferred_by_uuid(&state.entries);
        counts.unchanged = state.entries.len() - chosen.len();
        for incoming in chosen.values() {
            match merge_entry(&tx, incoming)? {
                EntryOutcome::Added => counts.added += 1,
                EntryOutcome::Replaced => counts.replaced += 1,
                EntryOutcome::Unchanged => counts.unchanged += 1,
            }
        }

        raise_high_water_mark(&tx, &state.entries)?;
        tx.commit()?;
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::revision::unix_millis;
    use tempfile::TempDir;
    use time::Duration;
    use time::macros::datetime;

    /// A fixed write time for tests that do not care about the exact value.
    const T0: OffsetDateTime = datetime!(2026-03-04 05:06:07.123_456_789 UTC);

    const fn dev(b: u8) -> Uuid {
        Uuid::from_bytes([b; 16])
    }

    /// An entry UUID whose first byte is `b`, so test UUIDs sort in the order of `b`.
    const fn uid(b: u8) -> Uuid {
        let mut bytes = [0x5Au8; 16];
        bytes[0] = b;
        Uuid::from_bytes(bytes)
    }

    const fn rev(wall_ms: u64, counter: u32, device: Uuid) -> Revision {
        Revision {
            wall_ms,
            counter,
            device_id: device,
        }
    }

    const fn hwm(wall_ms: u64, counter: u32) -> HighWaterMark {
        HighWaterMark { wall_ms, counter }
    }

    fn entry(uuid: Uuid, name: &str, ciphertext: &[u8], revision: Revision) -> SyncEntry {
        SyncEntry {
            uuid,
            name: name.to_string(),
            kind: "note".to_string(),
            nonce: vec![7; 24],
            ciphertext: ciphertext.to_vec(),
            created_at: T0,
            updated_at: T0 + Duration::seconds(1),
            revision,
        }
    }

    fn state(entries: &[SyncEntry], tombstones: &[Uuid]) -> SyncState {
        SyncState {
            entries: entries.to_vec(),
            tombstones: tombstones.to_vec(),
        }
    }

    fn open(dir: &TempDir, name: &str) -> Db {
        Db::open(&dir.path().join(format!("{name}.sqlite3"))).unwrap()
    }

    fn export(db: &Db) -> SyncState {
        db.export_sync_state().unwrap()
    }

    fn merge(db: &Db, state: &SyncState) -> MergeCounts {
        db.merge_sync_state(state).unwrap()
    }

    /// Merges the current state of `src` into `dst`.
    fn pull(dst: &Db, src: &Db) -> MergeCounts {
        merge(dst, &export(src))
    }

    const fn counts(added: usize, replaced: usize, removed: usize, unchanged: usize) -> MergeCounts {
        MergeCounts {
            added,
            replaced,
            removed,
            unchanged,
        }
    }

    fn row_id(db: &Db, uuid: Uuid) -> u64 {
        db.list_items()
            .unwrap()
            .into_iter()
            .find(|r| r.uuid == uuid)
            .expect("row exists")
            .id
    }

    fn uuid_of(db: &Db, name: &str) -> Uuid {
        db.list_items()
            .unwrap()
            .into_iter()
            .find(|r| r.name == name)
            .expect("row exists")
            .uuid
    }

    /// Two entries with the same UUID and revision but different ciphertext, returned as
    /// `(smaller digest, greater digest)`.
    fn digest_tie_pair(uuid: Uuid, revision: Revision) -> (SyncEntry, SyncEntry) {
        let a = entry(uuid, "tie", b"alpha", revision);
        let b = entry(uuid, "tie", b"bravo", revision);
        assert_ne!(content_digest(&a), content_digest(&b));
        if content_digest(&a) < content_digest(&b) {
            (a, b)
        } else {
            (b, a)
        }
    }

    // ---- Reading the state ----

    #[test]
    fn test_export_orders_entries_and_tombstones_by_bytes() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "order");
        // Merged in descending order; the high bit checks unsigned comparison.
        let entries = [
            entry(uid(0xF0), "z", b"c1", rev(1, 0, dev(1))),
            entry(uid(0x80), "a", b"c2", rev(2, 0, dev(1))),
            entry(uid(0x01), "m", b"c3", rev(3, 0, dev(1))),
        ];
        merge(&db, &state(&entries, &[uid(0xEE), uid(0x02), uid(0x7F)]));

        let got = export(&db);
        let uuids: Vec<Uuid> = got.entries.iter().map(|e| e.uuid).collect();
        assert_eq!(uuids, vec![uid(0x01), uid(0x80), uid(0xF0)]);
        assert_eq!(got.tombstones, vec![uid(0x02), uid(0x7F), uid(0xEE)]);
    }

    #[test]
    fn test_export_of_empty_database_is_empty() {
        let dir = TempDir::new().unwrap();
        assert_eq!(export(&open(&dir, "empty")), SyncState::default());
    }

    #[test]
    fn test_export_matches_local_rows() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "local");
        db.insert_item("a", "password", b"n1", b"c1", T0).unwrap();
        db.insert_item("b", "note", b"n2", b"c2", T0).unwrap();
        let doomed = row_id(&db, uuid_of(&db, "b"));
        db.delete_item(doomed).unwrap();

        let got = export(&db);
        let row = db.list_items().unwrap().remove(0);
        assert_eq!(
            got.entries,
            vec![SyncEntry {
                uuid: row.uuid,
                name: row.name,
                kind: row.kind,
                nonce: row.nonce,
                ciphertext: row.ciphertext,
                created_at: row.created_at,
                updated_at: row.updated_at,
                revision: row.revision,
            }]
        );
        assert_eq!(got.tombstones, db.tombstones().unwrap());
    }

    // ---- Merge table ----

    #[test]
    fn test_entry_on_one_side_only() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "one_side");
        let local = entry(uid(1), "local", b"l", rev(1_000, 0, dev(1)));
        let incoming = entry(uid(2), "incoming", b"i", rev(2_000, 0, dev(2)));
        merge(&db, &state(std::slice::from_ref(&local), &[]));

        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&incoming), &[])),
            counts(1, 0, 0, 0)
        );
        assert_eq!(export(&db), state(&[local, incoming], &[]));
    }

    #[test]
    fn test_same_revision_same_content_is_unchanged() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "same");
        let local = entry(uid(1), "same", b"c", rev(1_000, 2, dev(1)));
        merge(&db, &state(std::slice::from_ref(&local), &[]));
        let before = export(&db);

        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&local), &[])),
            counts(0, 0, 0, 1)
        );
        assert_eq!(export(&db), before);

        // Different timestamps are not content: the local entry stays as it is.
        let restamped = SyncEntry {
            created_at: T0 + Duration::days(3),
            updated_at: T0 + Duration::days(4),
            ..local
        };
        assert_eq!(merge(&db, &state(&[restamped], &[])), counts(0, 0, 0, 1));
        assert_eq!(export(&db), before);
    }

    #[test]
    fn test_newer_revision_wins_in_both_directions() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "newer");
        let old = entry(uid(1), "item", b"old", rev(1_000, 0, dev(1)));
        let new = entry(uid(1), "item", b"new", rev(2_000, 0, dev(2)));
        merge(&db, &state(std::slice::from_ref(&old), &[]));

        assert_eq!(merge(&db, &state(std::slice::from_ref(&new), &[])), counts(0, 1, 0, 0));
        assert_eq!(export(&db), state(std::slice::from_ref(&new), &[]));

        assert_eq!(merge(&db, &state(&[old], &[])), counts(0, 0, 0, 1));
        assert_eq!(export(&db), state(&[new], &[]));
    }

    #[test]
    fn test_counter_and_device_id_order_revisions() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "counter");
        let base = entry(uid(1), "item", b"a", rev(1_000, 1, dev(0x80)));
        merge(&db, &state(std::slice::from_ref(&base), &[]));

        // Same wall_ms, greater counter, smaller device: wins.
        let by_counter = entry(uid(1), "item", b"b", rev(1_000, 2, dev(0x01)));
        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&by_counter), &[])),
            counts(0, 1, 0, 0)
        );
        // Same (wall_ms, counter), greater device ID: wins.
        let by_device = entry(uid(1), "item", b"c", rev(1_000, 2, dev(0xFF)));
        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&by_device), &[])),
            counts(0, 1, 0, 0)
        );
        assert_eq!(export(&db).entries, vec![by_device]);
    }

    #[test]
    fn test_incoming_tombstone_beats_newer_local_entry() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "tomb_in");
        let local = entry(uid(1), "item", b"c", rev(u64::MAX, u32::MAX, dev(0xFF)));
        merge(&db, &state(&[local], &[]));

        assert_eq!(merge(&db, &state(&[], &[uid(1)])), counts(0, 0, 1, 0));
        assert_eq!(export(&db), state(&[], &[uid(1)]));
    }

    #[test]
    fn test_local_tombstone_blocks_far_future_entry() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "tomb_local");
        db.insert_item("item", "note", b"n", b"c", T0).unwrap();
        let uuid = uuid_of(&db, "item");
        db.delete_item(row_id(&db, uuid)).unwrap();

        let future = entry(uuid, "item", b"resurrected", rev(u64::MAX, u32::MAX, dev(0xFF)));
        assert_eq!(merge(&db, &state(&[future], &[])), counts(0, 0, 0, 1));
        assert_eq!(export(&db), state(&[], &[uuid]));
    }

    #[test]
    fn test_tombstone_on_both_sides_stays_deleted() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "tomb_both");
        merge(&db, &state(&[entry(uid(1), "x", b"c", rev(1, 0, dev(1)))], &[uid(1)]));
        assert_eq!(export(&db), state(&[], &[uid(1)]));

        assert_eq!(merge(&db, &state(&[], &[uid(1)])), counts(0, 0, 0, 0));
        assert_eq!(export(&db), state(&[], &[uid(1)]));
    }

    #[test]
    fn test_missing_entry_is_left_in_place() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "missing");
        let kept = entry(uid(1), "kept", b"k", rev(1_000, 0, dev(1)));
        let other = entry(uid(2), "other", b"o", rev(1_000, 0, dev(1)));
        merge(&db, &state(&[kept.clone(), other.clone()], &[]));

        // The incoming state knows only `other` and an unrelated tombstone.
        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&other), &[uid(9)])),
            counts(0, 0, 0, 1)
        );
        assert_eq!(export(&db), state(&[kept, other], &[uid(9)]));
    }

    // ---- Fidelity ----

    #[test]
    fn test_inserted_row_equals_carried_entry() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "insert_fidelity");
        let sender = dev(0xAB);
        let carried = SyncEntry {
            uuid: uid(0x42),
            name: "carried name".to_string(),
            kind: "password".to_string(),
            nonce: (0u8..24).collect(),
            ciphertext: vec![0x00, 0xFF, 0x10, 0x80],
            created_at: datetime!(2025-01-02 03:04:05.000_000_001 UTC),
            updated_at: datetime!(2026-07-08 09:10:11.999_999_999 UTC),
            revision: rev(1_234_567, 89, sender),
        };
        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&carried), &[])),
            counts(1, 0, 0, 0)
        );

        assert_eq!(export(&db).entries, vec![carried.clone()]);
        let row = db.list_items().unwrap().remove(0);
        assert_eq!(row.uuid, carried.uuid);
        assert_eq!(row.name, carried.name);
        assert_eq!(row.kind, carried.kind);
        assert_eq!(row.nonce, carried.nonce);
        assert_eq!(row.ciphertext, carried.ciphertext);
        assert_eq!(row.created_at, carried.created_at);
        assert_eq!(row.updated_at, carried.updated_at);
        assert_eq!(row.revision, carried.revision);
        assert_eq!(row.revision.device_id, sender);
        assert_ne!(row.revision.device_id, db.device_id().unwrap());
    }

    #[test]
    fn test_non_utc_timestamps_are_stored_as_the_same_instant() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "offset");
        let carried = SyncEntry {
            created_at: datetime!(2026-01-01 02:00:00.5 +02:00),
            updated_at: datetime!(2026-01-01 00:00:00.5 -05:00),
            ..entry(uid(1), "x", b"c", rev(1, 0, dev(1)))
        };
        merge(&db, &state(std::slice::from_ref(&carried), &[]));
        let row = db.list_items().unwrap().remove(0);
        assert_eq!(row.created_at, datetime!(2026-01-01 00:00:00.5 UTC));
        assert_eq!(row.created_at.offset(), UtcOffset::UTC);
        assert_eq!(row.updated_at, datetime!(2026-01-01 05:00:00.5 UTC));
    }

    #[test]
    fn test_replaced_row_keeps_row_id_and_takes_every_field() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "replace_fidelity");
        db.insert_item("original", "note", b"n0", b"c0", T0).unwrap();
        db.insert_item("bystander", "note", b"n1", b"c1", T0).unwrap();
        let before = db.list_items().unwrap();
        let original = before.iter().find(|r| r.name == "original").unwrap();

        let carried = SyncEntry {
            uuid: original.uuid,
            name: "renamed".to_string(),
            kind: "password".to_string(),
            nonce: vec![9; 24],
            ciphertext: b"replacement".to_vec(),
            created_at: datetime!(2020-02-02 02:02:02 UTC),
            updated_at: datetime!(2030-03-03 03:03:03.333 UTC),
            revision: rev(original.revision.wall_ms + 1, 0, dev(0xCD)),
        };
        assert_eq!(
            merge(&db, &state(std::slice::from_ref(&carried), &[])),
            counts(0, 1, 0, 0)
        );

        let after = db.list_items().unwrap();
        assert_eq!(after.len(), 2);
        let replaced = after.iter().find(|r| r.uuid == carried.uuid).unwrap();
        assert_eq!(replaced.id, original.id, "the local row ID is kept");
        assert_eq!(replaced.name, carried.name);
        assert_eq!(replaced.kind, carried.kind);
        assert_eq!(replaced.nonce, carried.nonce);
        assert_eq!(replaced.ciphertext, carried.ciphertext);
        assert_eq!(replaced.created_at, carried.created_at);
        assert_eq!(replaced.updated_at, carried.updated_at);
        assert_eq!(replaced.revision, carried.revision);

        let bystander_before = before.iter().find(|r| r.name == "bystander").unwrap();
        let bystander_after = after.iter().find(|r| r.name == "bystander").unwrap();
        assert_eq!(
            (bystander_after.id, bystander_after.uuid, bystander_after.revision),
            (bystander_before.id, bystander_before.uuid, bystander_before.revision)
        );
    }

    /// Local entries and an incoming state that exercise every kind of count, returned as
    /// `(local entries, local tombstones, incoming state)`.
    fn counting_fixture() -> (Vec<SyncEntry>, Vec<Uuid>, SyncState) {
        let replaced_old = entry(uid(0x10), "replaced", b"old", rev(1_000, 0, dev(1)));
        let removed = entry(uid(0x20), "removed", b"r", rev(9_000, 0, dev(1)));
        let same = entry(uid(0x30), "same", b"s", rev(1_000, 0, dev(1)));
        let older_local = entry(uid(0x40), "older", b"local", rev(5_000, 0, dev(1)));
        let (tie_loser, tie_winner) = digest_tie_pair(uid(0x50), rev(3_000, 0, dev(1)));
        let blocked = uid(0x60);
        let local = vec![replaced_old, removed, same.clone(), older_local, tie_winner];

        let incoming = state(
            &[
                entry(uid(0x70), "added", b"a", rev(2_000, 0, dev(2))),
                entry(uid(0x10), "replaced", b"new", rev(2_000, 0, dev(2))),
                same,
                entry(uid(0x40), "older", b"incoming", rev(4_000, 0, dev(2))),
                tie_loser,
                entry(blocked, "blocked", b"b", rev(8_000, 0, dev(2))),
            ],
            // `uid(0x99)` is unknown locally: recorded, but not counted.
            &[uid(0x20), uid(0x99)],
        );
        (local, vec![blocked], incoming)
    }

    fn seed(db: &Db, entries: &[SyncEntry], tombstones: &[Uuid]) {
        merge(db, &state(entries, &[]));
        merge(db, &state(&[], tombstones));
    }

    #[test]
    fn test_counts_cover_every_outcome() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "counts");
        let (local, tombstones, incoming) = counting_fixture();
        seed(&db, &local, &tombstones);

        assert_eq!(merge(&db, &incoming), counts(1, 1, 1, 4));
        let got = export(&db);
        let names: Vec<&str> = got.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["replaced", "same", "older", "tie", "added"]);
        assert_eq!(got.entries[0].ciphertext, b"new");
        assert_eq!(got.entries[2].ciphertext, b"local");
        assert_eq!(got.entries[3], local[4], "the greater digest stays");
        assert_eq!(got.tombstones, vec![uid(0x20), uid(0x60), uid(0x99)]);
    }

    #[test]
    fn test_result_does_not_depend_on_order_within_the_state() {
        let dir = TempDir::new().unwrap();
        let (local, tombstones, incoming) = counting_fixture();
        let mut reversed = incoming.clone();
        reversed.entries.reverse();
        reversed.tombstones.reverse();

        let forward = open(&dir, "forward");
        let backward = open(&dir, "backward");
        seed(&forward, &local, &tombstones);
        seed(&backward, &local, &tombstones);

        assert_eq!(merge(&forward, &incoming), merge(&backward, &reversed));
        assert_eq!(export(&forward), export(&backward));
        assert_eq!(forward.high_water_mark().unwrap(), backward.high_water_mark().unwrap());
    }

    // ---- Malformed input stays safe ----

    #[test]
    fn test_entry_and_tombstone_for_same_uuid_end_deleted() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "both");
        let e = entry(uid(1), "x", b"c", rev(1_000, 0, dev(1)));
        assert_eq!(merge(&db, &state(&[e], &[uid(1)])), counts(0, 0, 0, 1));
        assert_eq!(export(&db), state(&[], &[uid(1)]));
    }

    #[test]
    fn test_duplicate_incoming_entries_resolve_by_revision_and_digest() {
        let dir = TempDir::new().unwrap();
        let old = entry(uid(1), "x", b"old", rev(1_000, 0, dev(1)));
        let new = entry(uid(1), "x", b"new", rev(2_000, 0, dev(1)));
        let (tie_loser, tie_winner) = digest_tie_pair(uid(2), rev(3_000, 0, dev(1)));
        // The same entry listed twice, differing only in timestamps.
        let twin_a = entry(uid(3), "twin", b"t", rev(4_000, 0, dev(1)));
        let twin_b = SyncEntry {
            updated_at: twin_a.updated_at + Duration::hours(1),
            ..twin_a.clone()
        };

        let forward = open(&dir, "dup_forward");
        let backward = open(&dir, "dup_backward");
        let entries = [old, new.clone(), tie_loser, tie_winner.clone(), twin_a, twin_b.clone()];
        let mut reversed = entries.clone();
        reversed.reverse();

        assert_eq!(merge(&forward, &state(&entries, &[])), counts(3, 0, 0, 3));
        assert_eq!(merge(&backward, &state(&reversed, &[])), counts(3, 0, 0, 3));
        assert_eq!(export(&forward), state(&[new, tie_winner, twin_b], &[]));
        assert_eq!(export(&forward), export(&backward));
    }

    // ---- High-water mark ----

    #[test]
    fn test_high_water_mark_rises_to_greatest_incoming_revision() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "hwm_greatest");
        let entries = [
            entry(uid(1), "a", b"a", rev(100, 9, dev(0xFF))),
            entry(uid(2), "b", b"b", rev(300, 5, dev(0x01))),
            entry(uid(3), "c", b"c", rev(300, 2, dev(0xFF))),
        ];
        merge(&db, &state(&entries, &[]));
        assert_eq!(db.high_water_mark().unwrap(), hwm(300, 5));

        // Smaller revisions never lower it.
        merge(&db, &state(&[entry(uid(4), "d", b"d", rev(1, 0, dev(1)))], &[]));
        assert_eq!(db.high_water_mark().unwrap(), hwm(300, 5));
        merge(&db, &state(&[], &[uid(2)]));
        assert_eq!(db.high_water_mark().unwrap(), hwm(300, 5));
    }

    #[test]
    fn test_high_water_mark_counts_blocked_entries() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "hwm_blocked");
        merge(&db, &state(&[], &[uid(1)]));
        assert_eq!(db.high_water_mark().unwrap(), HighWaterMark::default());

        let blocked = entry(uid(1), "x", b"c", rev(5_000_000, 7, dev(2)));
        assert_eq!(merge(&db, &state(&[blocked], &[])), counts(0, 0, 0, 1));
        assert_eq!(db.high_water_mark().unwrap(), hwm(5_000_000, 7));
    }

    #[test]
    fn test_high_water_mark_counts_losing_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hwm_loser.sqlite3");
        let db = Db::open(&path).unwrap();
        merge(&db, &state(&[entry(uid(1), "x", b"local", rev(9_000, 0, dev(3)))], &[]));

        // A consistent database never has a stored revision above its high-water mark, so a
        // losing entry cannot normally raise it. Lower the mark by hand to observe that losers
        // are still counted.
        write_high_water_mark(&Connection::open(&path).unwrap(), HighWaterMark::default()).unwrap();

        let loser = entry(uid(1), "x", b"incoming", rev(8_000, 2, dev(1)));
        assert_eq!(merge(&db, &state(&[loser], &[])), counts(0, 0, 0, 1));
        assert_eq!(export(&db).entries[0].ciphertext, b"local");
        assert_eq!(db.high_water_mark().unwrap(), hwm(8_000, 2));
    }

    #[test]
    fn test_local_writes_after_future_import_sort_after_it() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "hwm_future");
        let future_ms = unix_millis(datetime!(2400-01-01 00:00:00 UTC));
        let imported = entry(uid(1), "imported", b"c", rev(future_ms, 3, dev(0xFF)));
        merge(&db, &state(std::slice::from_ref(&imported), &[]));

        // The local clock is centuries behind the imported revision.
        db.insert_item("local", "note", b"n", b"c", T0).unwrap();
        let created = db
            .list_items()
            .unwrap()
            .into_iter()
            .find(|r| r.name == "local")
            .unwrap();
        assert!(created.revision > imported.revision);
        assert_eq!(created.revision.device_id, db.device_id().unwrap());

        db.update_item(row_id(&db, imported.uuid), b"n2", b"c2", T0).unwrap();
        let edited = db
            .list_items()
            .unwrap()
            .into_iter()
            .find(|r| r.uuid == imported.uuid)
            .unwrap();
        assert!(edited.revision > imported.revision);
        assert!(edited.revision > created.revision);
        assert_eq!(edited.revision.device_id, db.device_id().unwrap());
    }

    // ---- Ties and identity ----

    #[test]
    fn test_equal_revision_tie_converges_on_greater_digest() {
        let dir = TempDir::new().unwrap();
        // As with a cloned device: same UUID, same revision including the device ID.
        let (loser, winner) = digest_tie_pair(uid(1), rev(7_000, 1, dev(0x33)));
        let holds_loser = open(&dir, "holds_loser");
        let holds_winner = open(&dir, "holds_winner");
        merge(&holds_loser, &state(&[loser], &[]));
        merge(&holds_winner, &state(std::slice::from_ref(&winner), &[]));
        let from_loser = export(&holds_loser);
        let from_winner = export(&holds_winner);

        assert_eq!(merge(&holds_loser, &from_winner), counts(0, 1, 0, 0));
        assert_eq!(merge(&holds_winner, &from_loser), counts(0, 0, 0, 1));
        assert_eq!(export(&holds_loser), state(std::slice::from_ref(&winner), &[]));
        assert_eq!(export(&holds_winner), state(&[winner], &[]));
    }

    #[test]
    fn test_digest_covers_identity_and_content_but_not_timestamps_or_revision() {
        let base = entry(uid(1), "name", b"ciphertext", rev(1, 0, dev(1)));
        let d = content_digest(&base);

        let changed = [
            SyncEntry {
                uuid: uid(2),
                ..base.clone()
            },
            SyncEntry {
                name: "name2".into(),
                ..base.clone()
            },
            SyncEntry {
                kind: "password".into(),
                ..base.clone()
            },
            SyncEntry {
                nonce: vec![8; 24],
                ..base.clone()
            },
            SyncEntry {
                ciphertext: b"ciphertexu".to_vec(),
                ..base.clone()
            },
        ];
        for e in &changed {
            assert_ne!(content_digest(e), d, "{e:?}");
        }

        let same = SyncEntry {
            created_at: T0 - Duration::days(400),
            updated_at: T0 + Duration::days(400),
            revision: rev(u64::MAX, u32::MAX, dev(0xFF)),
            ..base
        };
        assert_eq!(content_digest(&same), d);
    }

    #[test]
    fn test_digest_distinguishes_field_boundaries() {
        let base = entry(uid(1), "", b"", rev(1, 0, dev(1)));
        let ab_c = SyncEntry {
            name: "ab".into(),
            kind: "c".into(),
            ..base.clone()
        };
        let a_bc = SyncEntry {
            name: "a".into(),
            kind: "bc".into(),
            ..base.clone()
        };
        assert_ne!(content_digest(&ab_c), content_digest(&a_bc));

        let nonce_long = SyncEntry {
            nonce: vec![1, 2],
            ciphertext: vec![3],
            ..base.clone()
        };
        let ct_long = SyncEntry {
            nonce: vec![1],
            ciphertext: vec![2, 3],
            ..base
        };
        assert_ne!(content_digest(&nonce_long), content_digest(&ct_long));
    }

    #[test]
    fn test_digest_matches_independently_assembled_sha256() {
        let e = SyncEntry {
            uuid: Uuid::from_bytes([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            ]),
            name: "gh".into(),
            kind: "note".into(),
            nonce: vec![0xA0, 0xA1, 0xA2],
            ciphertext: vec![],
            ..entry(uid(0), "", b"", rev(1, 0, dev(1)))
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0, 0, 0, 16]);
        bytes.extend_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]);
        bytes.extend_from_slice(&[0, 0, 0, 2, b'g', b'h']);
        bytes.extend_from_slice(&[0, 0, 0, 4, b'n', b'o', b't', b'e']);
        bytes.extend_from_slice(&[0, 0, 0, 3, 0xA0, 0xA1, 0xA2]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let expected: [u8; 32] = Sha256::digest(&bytes).into();

        assert_eq!(content_digest(&e), expected);
    }

    #[test]
    fn test_same_name_different_uuids_are_all_kept() {
        let dir = TempDir::new().unwrap();
        let db = open(&dir, "same_name");
        db.insert_item("dup", "note", b"n", b"local", T0).unwrap();
        let incoming = [
            entry(uid(1), "dup", b"one", rev(1, 0, dev(1))),
            entry(uid(2), "dup", b"two", rev(1, 0, dev(2))),
        ];
        assert_eq!(merge(&db, &state(&incoming, &[])), counts(2, 0, 0, 0));

        let rows = db.list_items().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.name == "dup"), "nothing is renamed");
        let mut cts: Vec<&[u8]> = rows.iter().map(|r| r.ciphertext.as_slice()).collect();
        cts.sort_unstable();
        assert_eq!(cts, vec![b"local".as_slice(), b"one", b"two"]);
    }

    // ---- Convergence across three databases ----

    /// The states of three databases with different device IDs that started from a shared
    /// state and then each created, edited, and deleted independently.
    struct Diverged {
        a: SyncState,
        b: SyncState,
        c: SyncState,
        /// Entry UUIDs by role.
        s1: Uuid,
        s2: Uuid,
        s3_old: Uuid,
        s3_new: Uuid,
    }

    fn diverged(dir: &TempDir) -> Diverged {
        let at = |secs: i64| T0 + Duration::seconds(secs);
        let a = open(dir, "origin_a");
        for name in ["s1", "s2", "s3", "s4"] {
            a.insert_item(name, "note", b"n", name.as_bytes(), T0).unwrap();
        }
        let shared = export(&a);
        let b = open(dir, "origin_b");
        let c = open(dir, "origin_c");
        merge(&b, &shared);
        merge(&c, &shared);
        let ids: Vec<Uuid> = [&a, &b, &c].iter().map(|db| db.device_id().unwrap()).collect();
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);

        let (s1, s2, s3_old) = (uuid_of(&a, "s1"), uuid_of(&a, "s2"), uuid_of(&a, "s3"));

        // A edits s1, creates two entries, deletes s3 and recreates it under the same name.
        a.update_item(row_id(&a, s1), b"n", b"s1 by a", at(10)).unwrap();
        a.insert_item("a-only", "note", b"n", b"a", at(11)).unwrap();
        a.delete_item(row_id(&a, s3_old)).unwrap();
        a.insert_item("s3", "note", b"n", b"s3 again", at(13)).unwrap();
        a.insert_item("dup", "note", b"n", b"dup by a", at(14)).unwrap();
        let s3_new = uuid_of(&a, "s3");

        // B edits s1 later than A, edits s2, and creates two entries.
        b.update_item(row_id(&b, s1), b"n", b"s1 by b", at(20)).unwrap();
        b.update_item(row_id(&b, s2), b"n", b"s2 by b", at(21)).unwrap();
        b.insert_item("b-only", "note", b"n", b"b", at(22)).unwrap();
        b.insert_item("dup", "note", b"n", b"dup by b", at(23)).unwrap();

        // C deletes s2 before B's edit, edits s3 long after A deleted it, and creates one.
        c.delete_item(row_id(&c, s2)).unwrap();
        c.update_item(row_id(&c, s3_old), b"n", b"s3 by c", at(100)).unwrap();
        c.insert_item("c-only", "note", b"n", b"c", at(101)).unwrap();

        Diverged {
            a: export(&a),
            b: export(&b),
            c: export(&c),
            s1,
            s2,
            s3_old,
            s3_new,
        }
    }

    /// A fresh database holding `initial`: a copy of another database's synchronized state.
    fn replica(dir: &TempDir, name: &str, initial: &SyncState) -> Db {
        let db = open(dir, name);
        merge(&db, initial);
        db
    }

    fn replicas(dir: &TempDir, tag: &str, d: &Diverged) -> (Db, Db, Db) {
        (
            replica(dir, &format!("{tag}_a"), &d.a),
            replica(dir, &format!("{tag}_b"), &d.b),
            replica(dir, &format!("{tag}_c"), &d.c),
        )
    }

    /// Checks the converged state against what the rules say it must be.
    fn assert_expected_outcome(converged: &SyncState, d: &Diverged) {
        let find = |uuid: Uuid| converged.entries.iter().find(|e| e.uuid == uuid);
        assert_eq!(find(d.s1).unwrap().ciphertext, b"s1 by b", "the later edit wins");
        assert!(find(d.s2).is_none(), "a delete beats a later edit");
        assert!(find(d.s3_old).is_none(), "a delete beats a later offline edit");
        assert_eq!(
            find(d.s3_new).unwrap().ciphertext,
            b"s3 again",
            "the recreated entry survives"
        );
        assert_eq!(converged.tombstones, {
            let mut t = vec![d.s2, d.s3_old];
            t.sort_by_key(|u| *u.as_bytes());
            t
        });
        let mut names: Vec<&str> = converged.entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["a-only", "b-only", "c-only", "dup", "dup", "s1", "s3", "s4"]
        );
    }

    #[test]
    fn test_merge_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let d = diverged(&dir);
        let db = replica(&dir, "idem", &d.b);

        merge(&db, &d.a);
        let once = export(&db);
        let hwm_once = db.high_water_mark().unwrap();

        assert_eq!(merge(&db, &d.a), counts(0, 0, 0, d.a.entries.len()));
        assert_eq!(export(&db), once);
        assert_eq!(db.high_water_mark().unwrap(), hwm_once);

        // A database's own state merged into itself changes nothing either.
        assert_eq!(pull(&db, &db), counts(0, 0, 0, once.entries.len()));
        assert_eq!(export(&db), once);
    }

    #[test]
    fn test_merge_is_commutative() {
        let dir = TempDir::new().unwrap();
        let d = diverged(&dir);
        let ac = replica(&dir, "comm_ac", &d.b);
        let ca = replica(&dir, "comm_ca", &d.b);

        merge(&ac, &d.a);
        merge(&ac, &d.c);
        merge(&ca, &d.c);
        merge(&ca, &d.a);

        assert_eq!(export(&ac), export(&ca));
        assert_eq!(ac.high_water_mark().unwrap(), ca.high_water_mark().unwrap());
        assert_expected_outcome(&export(&ac), &d);
    }

    #[test]
    fn test_merge_is_associative_across_exchange_orders() {
        let dir = TempDir::new().unwrap();
        let d = diverged(&dir);

        // Order 1: A is the hub.
        let (a1, b1, c1) = replicas(&dir, "hub_a", &d);
        pull(&a1, &b1);
        pull(&a1, &c1);
        pull(&b1, &a1);
        pull(&c1, &a1);

        // Order 2: A receives B's changes only through C.
        let (a2, b2, c2) = replicas(&dir, "relay", &d);
        pull(&c2, &b2);
        pull(&a2, &c2);
        assert!(
            export(&a2).entries.iter().any(|e| e.name == "b-only"),
            "B's entry reached A through C"
        );
        pull(&b2, &a2);
        pull(&c2, &a2);

        // Order 3: pairwise exchanges with B in the middle.
        let (a3, b3, c3) = replicas(&dir, "chain", &d);
        pull(&b3, &c3);
        pull(&a3, &b3);
        pull(&b3, &a3);
        pull(&c3, &b3);

        let reference = export(&a1);
        assert_expected_outcome(&reference, &d);
        for db in [&b1, &c1, &a2, &b2, &c2, &a3, &b3, &c3] {
            assert_eq!(export(db), reference);
        }
    }

    #[test]
    fn test_delete_beats_later_offline_edit_in_both_directions() {
        let dir = TempDir::new().unwrap();
        let deleter = open(&dir, "deleter");
        deleter.insert_item("x", "note", b"n", b"v1", T0).unwrap();
        let uuid = uuid_of(&deleter, "x");
        let editor = replica(&dir, "editor", &export(&deleter));

        deleter.delete_item(row_id(&deleter, uuid)).unwrap();
        editor
            .update_item(row_id(&editor, uuid), b"n", b"v2", T0 + Duration::hours(1))
            .unwrap();
        let from_deleter = export(&deleter);
        let from_editor = export(&editor);

        assert_eq!(merge(&deleter, &from_editor), counts(0, 0, 0, 1));
        assert_eq!(merge(&editor, &from_deleter), counts(0, 0, 1, 0));
        for db in [&deleter, &editor] {
            assert_eq!(export(db), state(&[], &[uuid]));
        }
    }

    #[test]
    fn test_recreated_entry_survives_while_old_tombstone_remains() {
        let dir = TempDir::new().unwrap();
        let first = open(&dir, "recreate_first");
        first.insert_item("reused", "note", b"n", b"old", T0).unwrap();
        let old = uuid_of(&first, "reused");
        let second = replica(&dir, "recreate_second", &export(&first));

        first.delete_item(row_id(&first, old)).unwrap();
        first
            .insert_item("reused", "note", b"n", b"new", T0 + Duration::seconds(1))
            .unwrap();
        let new = uuid_of(&first, "reused");
        assert_ne!(new, old);

        pull(&second, &first);
        pull(&first, &second);
        for db in [&first, &second] {
            let got = export(db);
            assert_eq!(got.entries.len(), 1);
            assert_eq!(
                (got.entries[0].uuid, got.entries[0].ciphertext.as_slice()),
                (new, b"new".as_slice())
            );
            assert_eq!(got.tombstones, vec![old]);
        }
    }

    // ---- Atomicity ----

    #[test]
    fn test_failed_merge_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("atomic.sqlite3");
        let db = Db::open(&path).unwrap();
        seed(
            &db,
            &[
                entry(uid(0x10), "to-replace", b"old", rev(1_000, 0, dev(1))),
                entry(uid(0x20), "to-remove", b"r", rev(1_000, 0, dev(1))),
            ],
            &[uid(0x30)],
        );
        let before = export(&db);
        let hwm_before = db.high_water_mark().unwrap();

        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER poison BEFORE INSERT ON items WHEN NEW.name = 'poison' \
                 BEGIN SELECT RAISE(ABORT, 'insert refused by test'); END;",
            )
            .unwrap();

        // Entries are merged in UUID order, so every other write happens before the failure.
        let incoming = state(
            &[
                entry(uid(0x10), "to-replace", b"new", rev(2_000, 0, dev(2))),
                entry(uid(0x40), "fine", b"f", rev(2_000, 0, dev(2))),
                entry(uid(0xF0), "poison", b"p", rev(u64::MAX - 1, 0, dev(2))),
            ],
            &[uid(0x20), uid(0x50)],
        );
        let err = db
            .merge_sync_state(&incoming)
            .expect_err("the trigger aborts the merge");
        assert!(format!("{err:#}").contains("insert refused by test"), "{err:#}");

        assert_eq!(export(&db), before, "entries and tombstones are unchanged");
        assert_eq!(db.high_water_mark().unwrap(), hwm_before);

        // The failed merge left no transaction open: once the trigger is gone it succeeds.
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER poison;")
            .unwrap();
        assert_eq!(merge(&db, &incoming), counts(2, 1, 1, 0));
        assert_eq!(db.high_water_mark().unwrap(), hwm(u64::MAX - 1, 0));
    }

    #[test]
    fn test_merge_failing_at_high_water_mark_write_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("atomic_hwm.sqlite3");
        let db = Db::open(&path).unwrap();
        // Seeding raises the high-water mark itself, so it happens before the trigger exists.
        seed(
            &db,
            &[
                entry(uid(0x10), "to-replace", b"old", rev(1_000, 0, dev(1))),
                entry(uid(0x20), "to-remove", b"r", rev(1_000, 0, dev(1))),
            ],
            &[uid(0x30)],
        );
        let before = export(&db);
        let hwm_before = db.high_water_mark().unwrap();

        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_hwm BEFORE UPDATE ON sync_meta \
                 BEGIN SELECT RAISE(ABORT, 'high-water mark update refused by test'); END;",
            )
            .unwrap();

        let incoming = state(
            &[
                entry(uid(0x10), "to-replace", b"new", rev(2_000, 0, dev(2))),
                entry(uid(0x40), "added", b"a", rev(3_000, 4, dev(2))),
            ],
            &[uid(0x20)],
        );
        // The merge reaches the high-water-mark write only if some incoming revision is above
        // the current mark.
        let greatest_incoming = incoming
            .entries
            .iter()
            .map(|e| e.revision.high_water_mark())
            .max()
            .unwrap();
        assert!(
            greatest_incoming > hwm_before,
            "{greatest_incoming:?} <= {hwm_before:?}"
        );

        // The tombstone and every entry write happen before the high-water mark is written, so
        // the trigger fires with all of them pending in the transaction.
        let err = db
            .merge_sync_state(&incoming)
            .expect_err("the trigger aborts the merge");
        assert!(
            format!("{err:#}").contains("high-water mark update refused by test"),
            "{err:#}"
        );

        assert_eq!(export(&db), before, "entries and tombstones are unchanged");
        assert_eq!(db.high_water_mark().unwrap(), hwm_before);

        // Once the trigger is gone the same merge succeeds and raises the mark.
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER refuse_hwm;")
            .unwrap();
        assert_eq!(merge(&db, &incoming), counts(1, 1, 1, 0));
        assert_eq!(db.high_water_mark().unwrap(), greatest_incoming);
        assert_eq!(greatest_incoming, hwm(3_000, 4));
    }
}
