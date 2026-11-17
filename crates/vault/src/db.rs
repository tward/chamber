use crate::revision::{HighWaterMark, Revision, next_local_revision, unix_millis};
use crate::{KdfParams, WrappedVaultKey};
use color_eyre::Result;
use color_eyre::eyre::{WrapErr, eyre};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// The schema version this build of Chamber reads and writes, stored in `PRAGMA user_version`.
///
/// * Version 0: `meta` and `items` (`id`, `name`, `kind`, `nonce`, `ciphertext`, `created_at`,
///   `updated_at`), with a unique index `idx_items_name` on `items(name)`.
/// * Version 1: `items` gains `uuid`, `rev_wall_ms`, `rev_counter`, and `rev_device_id`, with a
///   unique index `idx_items_uuid` on `uuid`; `idx_items_name` is dropped; the tables
///   `tombstones` and `sync_meta` are added.
pub const SCHEMA_VERSION: i32 = 1;

/// The version 0 tables. Running this first gives a brand-new file and a legacy file the same
/// starting point, so both end the migration with an identical schema.
const V0_TABLES: &str = r"
CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    kdf_params TEXT NOT NULL,
    wrapped_key BLOB NOT NULL,
    verifier BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
";

/// The version 1 columns on `items`. `ALTER TABLE ... ADD COLUMN` cannot add a `NOT NULL`
/// column without a default, so these are nullable in the schema; the migration fills them on
/// every existing row and every write sets them.
const V1_ITEM_COLUMNS: &str = r"
ALTER TABLE items ADD COLUMN uuid BLOB;
ALTER TABLE items ADD COLUMN rev_wall_ms INTEGER;
ALTER TABLE items ADD COLUMN rev_counter INTEGER;
ALTER TABLE items ADD COLUMN rev_device_id BLOB;
";

/// The tables version 1 adds. `sync_meta` follows the single-row `id = 1` pattern of `meta`
/// but is a separate table: it exists before the vault is initialized, while an empty `meta`
/// keeps meaning "not initialized".
const V1_TABLES: &str = r"
CREATE TABLE tombstones (
    uuid BLOB PRIMARY KEY NOT NULL CHECK (length(uuid) = 16)
);

CREATE TABLE sync_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_uuid BLOB NOT NULL CHECK (length(vault_uuid) = 16),
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    hwm_wall_ms INTEGER NOT NULL,
    hwm_counter INTEGER NOT NULL
);
";

/// The index changes of version 1: names are no longer unique, entry UUIDs are.
const V1_INDEXES: &str = r"
DROP INDEX IF EXISTS idx_items_name;
CREATE UNIQUE INDEX idx_items_uuid ON items(uuid);
";

#[derive(Debug)]
pub struct Db {
    conn: Connection,
}

/// The contents of the single `sync_meta` row.
pub(crate) struct SyncMeta {
    pub(crate) vault_uuid: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) hwm: HighWaterMark,
}

impl Db {
    /// Opens a vault database, creating or migrating it to [`SCHEMA_VERSION`] as needed.
    ///
    /// # Arguments
    /// * `path` - The path of the `SQLite` database file. A missing file is created.
    ///
    /// # Behavior
    /// 1. Reads `PRAGMA user_version` before changing anything.
    /// 2. Refuses a version greater than [`SCHEMA_VERSION`] (or a negative one) without
    ///    writing anything, not even the journal mode.
    /// 3. Sets `journal_mode=WAL` and `foreign_keys=ON`. The journal mode cannot change inside
    ///    a transaction, so this happens before, and outside, any migration.
    /// 4. At version 1 there is nothing more to do.
    /// 5. At version 0 (a brand-new file or a legacy vault) it migrates to version 1 in one
    ///    `IMMEDIATE` transaction, re-reading the version once it holds the write lock in case
    ///    another process migrated first. The migration creates any missing version 0 tables,
    ///    mints the vault UUID and this device's ID, gives every existing row a fresh entry UUID
    ///    and the revision `(updated_at in ms since the Unix epoch, 0, device ID)` (0 for a time
    ///    before the epoch), creates `tombstones` and `sync_meta`, sets the high-water mark to
    ///    the greatest seeded revision (`(0, 0)` with no rows), drops `idx_items_name`, adds the
    ///    unique index on `uuid`, and sets `user_version` to 1.
    ///
    /// The migration needs no key: it never touches ciphertexts. Row IDs, names, kinds,
    /// nonces, ciphertexts, and both timestamps of existing rows are left unchanged.
    ///
    /// # Errors
    /// This function will return an error if:
    /// * The database connection cannot be established (e.g., invalid path, file issues).
    /// * The schema version is newer than this build supports. The message names the version
    ///   found and says Chamber needs updating; the file is not modified.
    /// * The schema version is negative, which no Chamber writes.
    /// * The migration fails, for example because an existing row's `updated_at` is not an
    ///   RFC 3339 timestamp. The transaction is rolled back, so a legacy database is left
    ///   exactly as it was, still at version 0.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let version = read_user_version(&conn)?;
        check_supported_version(version)?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        if version < SCHEMA_VERSION {
            migrate_v0_to_v1(&conn)?;
        }
        Ok(Self { conn })
    }

    /// Begins a transaction that takes the write lock up front, for writes that read state
    /// (such as the high-water mark) before writing.
    pub(crate) fn write_transaction(&self) -> rusqlite::Result<Transaction<'_>> {
        Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
    }

    /// Begins a read transaction. In WAL mode every read inside it sees one snapshot of the
    /// database, taken at its first read, so a write committed by another connection meanwhile
    /// is either wholly visible or not at all.
    pub(crate) fn read_transaction(&self) -> rusqlite::Result<Transaction<'_>> {
        Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)
    }

    /// Returns this vault's UUID, minted when the database was created or migrated.
    ///
    /// # Errors
    /// Returns an error if the `sync_meta` row cannot be read.
    pub fn vault_uuid(&self) -> Result<Uuid> {
        Ok(read_sync_meta(&self.conn)?.vault_uuid)
    }

    /// Returns this device's ID, which every local revision carries.
    ///
    /// # Errors
    /// Returns an error if the `sync_meta` row cannot be read.
    pub fn device_id(&self) -> Result<Uuid> {
        Ok(read_sync_meta(&self.conn)?.device_id)
    }

    /// Returns the stored high-water mark: the greatest `(wall_ms, counter)` this vault has seen.
    ///
    /// # Errors
    /// Returns an error if the `sync_meta` row cannot be read.
    pub fn high_water_mark(&self) -> Result<HighWaterMark> {
        Ok(read_sync_meta(&self.conn)?.hwm)
    }

    /// Checks if the `meta` table in the database is empty.
    ///
    /// This function executes a SQL query to count the number of rows
    /// in the `meta` table. If the count is zero, it indicates that
    /// the table is empty, and the function returns `Ok(true)`. Otherwise,
    /// it returns `Ok(false)`.
    ///
    /// # Returns
    /// - `Ok(true)` if the `meta` table is empty.
    /// - `Ok(false)` if the `meta` table has one or more rows.
    /// - `Err` if an error occurs while querying the database.
    ///
    /// # Errors
    /// This function returns an error if there is an issue executing the SQL query,
    /// such as a database connection problem or an issue with the `meta` table.
    pub fn is_meta_empty(&self) -> Result<bool> {
        let count: i64 = self.conn.query_row("SELECT COUNT(*) FROM meta", [], |r| r.get(0))?;
        Ok(count == 0)
    }

    /// Writes metadata to the database for a secure vault system.
    ///
    /// This function performs the following operations:
    /// 1. Serializes the given KDF (Key Derivation Function) parameters to a JSON string.
    /// 2. Serializes the provided wrapped vault key to a byte vector (JSON format).
    /// 3. Deletes any existing data from the `meta` table in the database.
    /// 4. Inserts a new record into the `meta` table with the following fields:
    ///    - `id`: The primary key, hardcoded as `1`.
    ///    - `kdf_params`: The serialized KDF parameters.
    ///    - `wrapped_key`: The serialized wrapped vault key.
    ///    - `verifier`: A cryptographic verifier (byte slice).
    ///
    /// # Arguments
    /// * `kdf` - A reference to the `KdfParams` struct containing key derivation function parameters.
    /// * `wrapped` - A reference to a `WrappedVaultKey` struct representing the securely wrapped vault key.
    /// * `verifier` - A slice of bytes used as a cryptographic verifier to ensure integrity or authenticity.
    ///
    /// # Returns
    /// * `Result<()>` - Returns `Ok(())` if the metadata is successfully written to the database,
    ///   or an error (via `Result::Err`) if any operation fails (e.g., serialization or database access).
    ///
    /// # Errors
    /// Returns an error if:
    /// * Serialization of `kdf` or `wrapped` fails.
    /// * Any SQL operation (DELETE or INSERT) fails.
    ///
    /// # Notes
    /// * This function assumes that the `meta` table already exists and has the following schema:
    ///   - `meta (id INTEGER PRIMARY KEY, kdf_params TEXT, wrapped_key BLOB, verifier BLOB)`.
    /// * The `id` is fixed as `1` to allow for a single metadata record, effectively overriding any
    ///   existing metadata in the `meta` table.
    pub fn write_meta(&self, kdf: &KdfParams, wrapped: &WrappedVaultKey, verifier: &[u8]) -> Result<()> {
        let kdf_json = serde_json::to_string(kdf)?;
        let wrapped_json = serde_json::to_vec(wrapped)?;
        self.conn.execute("DELETE FROM meta", [])?;
        self.conn.execute(
            "INSERT INTO meta (id, kdf_params, wrapped_key, verifier) VALUES (1, ?, ?, ?)",
            params![kdf_json, wrapped_json, verifier],
        )?;
        Ok(())
    }

    /// Reads metadata from the database.
    ///
    /// This method retrieves metadata from the `meta` table in the database with the `id` of 1.
    /// Specifically, it fetches the Key Derivation Function (KDF) parameters, the wrapped key, and the verifier.
    /// It performs the following operations:
    /// 1. Executes a SQL query to fetch the `kdf_params`, `wrapped_key`, and `verifier` columns.
    /// 2. Maps the query result to raw JSON and binary blobs using a row-mapping closure.
    /// 3. Parses the JSON and binary data into strongly-typed Rust structures outside the closure.
    ///
    /// # Returns
    /// - An `Ok(Some((KdfParams, WrappedVaultKey, Vec<u8>)))` tuple if the record is found and successfully parsed:
    ///   - `KdfParams`: Deserialized KDF parameters from JSON.
    ///   - `WrappedVaultKey`: The deserialized wrapped key.
    ///   - `Vec<u8>`: A verifier used for integrity checks.
    /// - `Ok(None)` if no metadata record exists with `id = 1`.
    /// - An `Err` value if any error occurs during the operation, such as:
    ///   - Query errors from the `SQLite` database.
    ///   - JSON parsing errors for `KdfParams` and `WrappedVaultKey`.
    ///
    /// # Errors
    /// This method propagates errors in the following cases:
    /// - `SQLite` errors via `rusqlite::Error`, especially when querying the database.
    /// - Deserialization errors when converting `kdf_params` or `wrapped_key` into their respective types using `serde_json`.
    /// - Any other runtime errors are wrapped in `anyhow::Error`.
    ///
    /// # Dependencies
    /// - `rusqlite` for database interaction.
    /// - `serde_json` for JSON deserialization.
    /// - `anyhow` for error handling.
    pub fn read_meta(&self) -> Result<Option<(KdfParams, WrappedVaultKey, Vec<u8>)>> {
        // Fetch raw columns without JSON parsing inside the row-mapper
        let row = self
            .conn
            .query_row(
                "SELECT kdf_params, wrapped_key, verifier FROM meta WHERE id = 1",
                [],
                |r| {
                    let kdf_json: String = r.get(0)?;
                    let wrapped_blob: Vec<u8> = r.get(1)?;
                    let verifier: Vec<u8> = r.get(2)?;
                    Ok((kdf_json, wrapped_blob, verifier))
                },
            )
            .optional()?; // This is rusqlite::OptionalExtension; ok here

        // Parse JSON outside the closure so `?` produces anyhow::Error, not rusqlite::Error
        if let Some((kdf_json, wrapped_blob, verifier)) = row {
            let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
            let wrapped: WrappedVaultKey = serde_json::from_slice(&wrapped_blob)?;
            Ok(Some((kdf, wrapped, verifier)))
        } else {
            Ok(None)
        }
    }

    /// Inserts a new item, minting its entry UUID and assigning its first revision.
    ///
    /// # Parameters
    /// - `name`: The name of the item. No other item may have exactly this name.
    /// - `kind`: The type or category of the item.
    /// - `nonce`: A nonce (number used once) associated with the item, typically for cryptographic purposes.
    /// - `ciphertext`: The encrypted data associated with the item.
    /// - `now`: The time to record for the write, supplied by the caller (a `Vault` passes one
    ///   reading of its clock). This method does not read the system clock.
    ///
    /// # Returns
    /// - `Ok(())` if the item was inserted.
    ///
    /// # Behavior
    /// Everything happens in one `IMMEDIATE` transaction, which holds the write lock from the
    /// start because it reads the high-water mark before writing:
    /// 1. If an item with exactly this name exists (case-sensitive), the insert is refused and
    ///    nothing is written.
    /// 2. A random entry UUID is minted.
    /// 3. The revision is computed by [`next_local_revision`] from the stored high-water mark,
    ///    `now` in milliseconds since the Unix epoch, and this device's ID.
    /// 4. The row is inserted, and the high-water mark is set to the new revision's
    ///    `(wall_ms, counter)`.
    ///
    /// `now` is formatted as RFC 3339 and stored unchanged in both `created_at` and `updated_at`,
    /// so the two are equal on insert. They are display data; ordering uses the revision.
    ///
    /// # Errors
    /// - Returns an error if:
    ///   - `now` could not be formatted as RFC 3339.
    ///   - An item with the same name exists: the message is `An item named '{name}' already
    ///     exists`, and neither the items nor the high-water mark change. The check is made by
    ///     this method; names have no uniqueness constraint in the database.
    ///   - No revision is left after the high-water mark ([`crate::RevisionSpaceExhausted`]).
    ///   - Random bytes for the UUID cannot be obtained.
    ///   - Any database operation fails (e.g., I/O error, the database is locked).
    pub fn insert_item(
        &self,
        name: &str,
        kind: &str,
        nonce: &[u8],
        ciphertext: &[u8],
        now: OffsetDateTime,
    ) -> Result<()> {
        let stamp = now.format(&Rfc3339)?;
        let tx = self.write_transaction()?;

        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM items WHERE name = ?1)",
            params![name],
            |r| r.get(0),
        )?;
        if exists {
            return Err(eyre!("An item named '{}' already exists", name));
        }

        let sync = read_sync_meta(&tx)?;
        let revision = next_local_revision(sync.hwm, unix_millis(now), sync.device_id)?;
        let uuid = new_random_uuid()?;
        tx.execute(
            "INSERT INTO items (name, kind, nonce, ciphertext, created_at, updated_at, \
             uuid, rev_wall_ms, rev_counter, rev_device_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9)",
            params![
                name,
                kind,
                nonce,
                ciphertext,
                stamp,
                uuid.as_bytes(),
                wall_ms_to_sql(revision.wall_ms),
                revision.counter,
                revision.device_id.as_bytes(),
            ],
        )?;
        write_high_water_mark(&tx, revision.high_water_mark())?;
        tx.commit()?;
        Ok(())
    }

    /// Retrieves every item, ordered by name in ascending order.
    ///
    /// Each row becomes an [`ItemRow`] carrying the stored columns: `id`, `name`, `kind`,
    /// `nonce`, `ciphertext`, `created_at` and `updated_at` (parsed from RFC 3339), the entry
    /// `uuid`, and the `revision` built from `rev_wall_ms`, `rev_counter`, and `rev_device_id`.
    ///
    /// # Errors
    ///
    /// This method will return an error in the following cases:
    /// - If preparing the SQL statement fails.
    /// - If executing the query or mapping rows fails.
    /// - If the `created_at` or `updated_at` fields fail to parse from an RFC 3339 formatted string.
    /// - If a row's `uuid` or `rev_device_id` is not a 16-byte blob, or its `rev_counter` does
    ///   not fit in a `u32`.
    pub fn list_items(&self) -> Result<Vec<ItemRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, kind, nonce, ciphertext, created_at, updated_at, \
             uuid, rev_wall_ms, rev_counter, rev_device_id \
             FROM items ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ItemRow {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                nonce: r.get(3)?,
                ciphertext: r.get(4)?,
                created_at: parse_timestamp(5, &r.get::<_, String>(5)?)?,
                updated_at: parse_timestamp(6, &r.get::<_, String>(6)?)?,
                uuid: Uuid::from_bytes(r.get::<_, [u8; 16]>(7)?),
                revision: Revision {
                    wall_ms: wall_ms_from_sql(r.get(8)?),
                    counter: r.get(9)?,
                    device_id: Uuid::from_bytes(r.get::<_, [u8; 16]>(10)?),
                },
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Deletes the item with the local row ID `id` and records its entry UUID as a tombstone.
    ///
    /// # Arguments
    ///
    /// * `id` - The local row ID of the item to delete.
    ///
    /// # Returns
    ///
    /// * `Ok(())` when the item was deleted, and also when no item has this `id`.
    ///
    /// # Behavior
    /// Everything happens in one `IMMEDIATE` transaction:
    /// 1. The entry UUID of the row with this `id` is looked up. If there is no such row,
    ///    nothing is written and `Ok(())` is returned.
    /// 2. The UUID is added to `tombstones`.
    /// 3. The row is deleted from `items`.
    ///
    /// Recording the tombstone and deleting the row both happen or neither does: if either
    /// step fails, the transaction is rolled back and the row stays.
    ///
    /// A tombstone is the entry UUID alone. A delete assigns no revision and leaves the
    /// high-water mark unchanged. Tombstones are permanent: nothing removes them, and creating a
    /// new item under the deleted item's name mints a fresh UUID while the old tombstone stays.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The row's stored `uuid` is not a 16-byte blob.
    /// * Any database operation fails (e.g., I/O error, the database is locked, or a trigger
    ///   aborts the delete). Nothing is written in that case.
    pub fn delete_item(&self, id: u64) -> Result<()> {
        let tx = self.write_transaction()?;

        let uuid: Option<[u8; 16]> = tx
            .query_row("SELECT uuid FROM items WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        let Some(uuid) = uuid else {
            return Ok(());
        };

        // Entry UUIDs are unique, so the UUID is normally new to `tombstones`; OR IGNORE keeps
        // the table a set if it is already there.
        tx.execute("INSERT OR IGNORE INTO tombstones (uuid) VALUES (?1)", params![uuid])?;
        tx.execute("DELETE FROM items WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(())
    }

    /// Returns the entry UUID of every deleted item, ascending by bytes.
    ///
    /// Reads plain metadata and needs no key.
    ///
    /// # Errors
    /// Returns an error if the query fails or a stored tombstone is not a 16-byte blob.
    pub fn tombstones(&self) -> Result<Vec<Uuid>> {
        read_tombstones(&self.conn)
    }

    /// Updates an item with new encrypted data and assigns it a new revision.
    ///
    /// # Parameters
    /// - `id`: The local row ID of the item to update.
    /// - `nonce`: A reference to the byte slice representing the nonce used in encryption.
    /// - `ciphertext`: A reference to the byte slice containing the encrypted data.
    /// - `now`: The time to record for the write, supplied by the caller (a `Vault` passes one
    ///   reading of its clock). This method does not read the system clock.
    ///
    /// # Returns
    /// - `Ok(())` when the item was updated, and also when no item has this `id`.
    ///
    /// # Details
    /// In one `IMMEDIATE` transaction, this method computes the next revision with
    /// [`next_local_revision`] from the stored high-water mark, `now` in milliseconds since the
    /// Unix epoch, and this device's ID; updates the item's `nonce`, `ciphertext`,
    /// `updated_at` (`now` as RFC 3339), and revision columns; and stores the new revision's
    /// `(wall_ms, counter)` as the high-water mark. The new revision is strictly greater than
    /// every revision seen before, even if `now` is earlier than the previous write.
    /// `created_at` and the entry UUID are left untouched.
    ///
    /// If no row has this `id`, nothing changes, including the high-water mark.
    ///
    /// # Errors
    /// - Returns an error if `now` cannot be formatted as RFC 3339.
    /// - Returns an error if no revision is left after the high-water mark
    ///   ([`crate::RevisionSpaceExhausted`]).
    /// - Returns an error if any database operation fails.
    pub fn update_item(&self, id: u64, nonce: &[u8], ciphertext: &[u8], now: OffsetDateTime) -> Result<()> {
        let stamp = now.format(&Rfc3339)?;
        let tx = self.write_transaction()?;

        let exists: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM items WHERE id = ?1)", params![id], |r| {
            r.get(0)
        })?;
        if !exists {
            return Ok(());
        }

        let sync = read_sync_meta(&tx)?;
        let revision = next_local_revision(sync.hwm, unix_millis(now), sync.device_id)?;
        tx.execute(
            "UPDATE items SET nonce = ?1, ciphertext = ?2, updated_at = ?3, \
             rev_wall_ms = ?4, rev_counter = ?5, rev_device_id = ?6 WHERE id = ?7",
            params![
                nonce,
                ciphertext,
                stamp,
                wall_ms_to_sql(revision.wall_ms),
                revision.counter,
                revision.device_id.as_bytes(),
                id,
            ],
        )?;
        write_high_water_mark(&tx, revision.high_water_mark())?;
        tx.commit()?;
        Ok(())
    }
}

/// Reads `PRAGMA user_version`, the schema version.
fn read_user_version(conn: &Connection) -> rusqlite::Result<i32> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
}

/// Refuses a schema version this build cannot open.
fn check_supported_version(version: i32) -> Result<()> {
    if version > SCHEMA_VERSION {
        return Err(eyre!(
            "This vault has schema version {version}, which was written by a newer version of Chamber \
             (this version supports up to {SCHEMA_VERSION}). Update Chamber to open this vault."
        ));
    }
    if version < 0 {
        return Err(eyre!("This vault has an unrecognized schema version {version}"));
    }
    Ok(())
}

/// Migrates a version 0 database (or a brand-new, empty file) to version 1.
///
/// Runs in one `IMMEDIATE` transaction; any error drops the transaction, which rolls back
/// every change. See [`Db::open`] for the steps.
fn migrate_v0_to_v1(conn: &Connection) -> Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;

    // Another process may have migrated between our first read and taking the lock.
    let version = read_user_version(&tx)?;
    check_supported_version(version)?;
    if version >= SCHEMA_VERSION {
        return Ok(());
    }

    tx.execute_batch(V0_TABLES)?;
    tx.execute_batch(V1_ITEM_COLUMNS)?;

    let vault_uuid = new_random_uuid()?;
    let device_id = new_random_uuid()?;
    let hwm = seed_existing_items(&tx, device_id)?;

    tx.execute_batch(V1_TABLES)?;
    tx.execute(
        "INSERT INTO sync_meta (id, vault_uuid, device_id, hwm_wall_ms, hwm_counter) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            vault_uuid.as_bytes(),
            device_id.as_bytes(),
            wall_ms_to_sql(hwm.wall_ms),
            hwm.counter
        ],
    )?;
    tx.execute_batch(V1_INDEXES)?;
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    tx.commit()?;
    Ok(())
}

/// Gives every existing item a fresh entry UUID and the revision
/// `(updated_at in ms since the Unix epoch, 0, device_id)`, and returns the greatest seeded
/// `(wall_ms, counter)`, or `(0, 0)` when there are no items.
fn seed_existing_items(conn: &Connection, device_id: Uuid) -> Result<HighWaterMark> {
    let rows = {
        let mut stmt = conn.prepare("SELECT id, updated_at FROM items ORDER BY id")?;
        stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut hwm = HighWaterMark::default();
    let mut update = conn
        .prepare("UPDATE items SET uuid = ?1, rev_wall_ms = ?2, rev_counter = ?3, rev_device_id = ?4 WHERE id = ?5")?;
    for (id, updated_at) in rows {
        let parsed = OffsetDateTime::parse(&updated_at, &Rfc3339).wrap_err_with(|| {
            format!(
                "Cannot migrate the vault: item {id} has updated_at '{updated_at}', which is not an RFC 3339 timestamp"
            )
        })?;
        let revision = Revision {
            wall_ms: unix_millis(parsed),
            counter: 0,
            device_id,
        };
        update.execute(params![
            new_random_uuid()?.as_bytes(),
            wall_ms_to_sql(revision.wall_ms),
            revision.counter,
            revision.device_id.as_bytes(),
            id
        ])?;
        hwm = hwm.max(revision.high_water_mark());
    }
    Ok(hwm)
}

/// Reads every tombstone, ascending by bytes (`SQLite` compares blobs with `memcmp`).
pub(crate) fn read_tombstones(conn: &Connection) -> Result<Vec<Uuid>> {
    let mut stmt = conn.prepare("SELECT uuid FROM tombstones ORDER BY uuid ASC")?;
    let uuids = stmt
        .query_map([], |r| Ok(Uuid::from_bytes(r.get::<_, [u8; 16]>(0)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(uuids)
}

/// Reads the single `sync_meta` row.
pub(crate) fn read_sync_meta(conn: &Connection) -> Result<SyncMeta> {
    let meta = conn.query_row(
        "SELECT vault_uuid, device_id, hwm_wall_ms, hwm_counter FROM sync_meta WHERE id = 1",
        [],
        |r| {
            Ok(SyncMeta {
                vault_uuid: Uuid::from_bytes(r.get::<_, [u8; 16]>(0)?),
                device_id: Uuid::from_bytes(r.get::<_, [u8; 16]>(1)?),
                hwm: HighWaterMark {
                    wall_ms: wall_ms_from_sql(r.get(2)?),
                    counter: r.get(3)?,
                },
            })
        },
    )?;
    Ok(meta)
}

/// Stores `hwm` as the high-water mark.
pub(crate) fn write_high_water_mark(conn: &Connection, hwm: HighWaterMark) -> Result<()> {
    let changed = conn.execute(
        "UPDATE sync_meta SET hwm_wall_ms = ?1, hwm_counter = ?2 WHERE id = 1",
        params![wall_ms_to_sql(hwm.wall_ms), hwm.counter],
    )?;
    if changed != 1 {
        return Err(eyre!("The vault's sync_meta row is missing"));
    }
    Ok(())
}

/// Mints 16 random bytes as a UUID. All 128 bits are random: unlike `Uuid::new_v4`, no
/// version or variant bits are overwritten.
fn new_random_uuid() -> Result<Uuid> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| eyre!("Failed to get random bytes: {e}"))?;
    Ok(Uuid::from_bytes(bytes))
}

/// `SQLite` integers are signed, so a `u64` `wall_ms` is stored with its bits reinterpreted
/// as an `i64`. The full `u64` range round-trips; revisions are never compared in SQL.
pub(crate) const fn wall_ms_to_sql(wall_ms: u64) -> i64 {
    i64::from_ne_bytes(wall_ms.to_ne_bytes())
}

/// The inverse of [`wall_ms_to_sql`].
pub(crate) const fn wall_ms_from_sql(stored: i64) -> u64 {
    u64::from_ne_bytes(stored.to_ne_bytes())
}

/// Parses a stored RFC 3339 timestamp from column `idx`.
pub(crate) fn parse_timestamp(idx: usize, text: &str) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e)))
}

/// One stored item, still encrypted, as returned by [`Db::list_items`].
pub struct ItemRow {
    /// The local row ID. It is specific to this database file and never shared.
    pub id: u64,
    pub name: String,
    pub kind: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// When the item was created, as recorded by the writing device's clock. Display data only.
    pub created_at: OffsetDateTime,
    /// When the item was last written, as recorded by the writing device's clock. Display data
    /// only: it may go backward after a clock rollback, while `revision` never does.
    pub updated_at: OffsetDateTime,
    /// The entry's permanent UUID, minted when it was created (or when its vault was migrated
    /// to schema version 1).
    pub uuid: Uuid,
    /// The revision of the item's latest write.
    pub revision: Revision,
}

impl ItemRow {
    #[must_use]
    pub fn ad(&self) -> Vec<u8> {
        Self::ad_for_name_kind(&self.name, &self.kind)
    }
    #[must_use]
    pub fn ad_for_name_kind(name: &str, kind: &str) -> Vec<u8> {
        // Associated data binds the ciphertext to immutable fields.
        let mut v = Vec::with_capacity(name.len() + kind.len() + 2);
        v.extend_from_slice(name.as_bytes());
        v.push(0x1f);
        v.extend_from_slice(kind.as_bytes());
        v
    }
}

// Rust
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unwrap_in_result)]
    #![allow(clippy::panic)]
    #![allow(clippy::panic_in_result_fn)]
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{KdfParams, WrappedVaultKey};
    use std::fs;
    use time::macros::datetime;

    /// A fixed write time for tests that do not care about the exact value.
    const T0: OffsetDateTime = datetime!(2026-03-04 05:06:07.123_456_789 UTC);

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let pid = std::process::id();
        std::env::temp_dir().join(format!("chamber_db_{name}_{pid}_{now}.sqlite3"))
    }

    fn mk_wrapped(bytes: u8) -> WrappedVaultKey {
        WrappedVaultKey {
            nonce: vec![bytes; 24],
            ciphertext: vec![bytes ^ 0xAA; 32],
        }
    }

    fn small_kdf() -> KdfParams {
        KdfParams {
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn test_open_and_migrate_and_is_meta_empty() -> Result<()> {
        let path = tmp_path("open_migrate");
        let db = Db::open(&path)?;
        assert!(db.is_meta_empty()?);

        // Reopen should succeed (idempotent migration)
        let db2 = Db::open(&path)?;
        assert!(db2.is_meta_empty()?);

        // Cleanup
        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_read_meta_none_when_empty() -> Result<()> {
        let path = tmp_path("meta_none");
        let db = Db::open(&path)?;
        assert!(db.is_meta_empty()?);

        let meta = db.read_meta()?;
        assert!(meta.is_none());

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_write_and_read_meta_roundtrip() -> Result<()> {
        let path = tmp_path("meta_roundtrip");
        let db = Db::open(&path)?;

        let kdf = small_kdf();
        let wrapped = mk_wrapped(0x11);
        let verifier = vec![0xDE, 0xAD, 0xBE, 0xEF];

        db.write_meta(&kdf, &wrapped, &verifier)?;
        assert!(!db.is_meta_empty()?);

        let (kdf2, wrapped2, verifier2) = db.read_meta()?.expect("meta present");
        assert_eq!(kdf2.salt, kdf.salt);
        assert_eq!(kdf2.m_cost_kib, kdf.m_cost_kib);
        assert_eq!(kdf2.t_cost, kdf.t_cost);
        assert_eq!(kdf2.p_cost, kdf.p_cost);

        assert_eq!(wrapped2.nonce, wrapped.nonce);
        assert_eq!(wrapped2.ciphertext, wrapped.ciphertext);
        assert_eq!(verifier2, verifier);

        // Overwrite meta (DELETE + INSERT) should still work
        let kdf_new = KdfParams {
            salt: vec![9, 9, 9, 9, 9, 9, 9, 9],
            ..kdf
        };
        let wrapped_new = mk_wrapped(0x22);
        let verifier_new = vec![0xAA, 0xBB, 0xCC];
        db.write_meta(&kdf_new, &wrapped_new, &verifier_new)?;

        let (kdf3, wrapped3, verifier3) = db.read_meta()?.expect("meta present");
        assert_eq!(kdf3.salt, kdf_new.salt);
        assert_eq!(wrapped3.ciphertext, wrapped_new.ciphertext);
        assert_eq!(verifier3, verifier_new);

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_insert_and_list_items_and_ordering() -> Result<()> {
        let path = tmp_path("items_basic");
        let db = Db::open(&path)?;

        let t_a = datetime!(2026-03-04 05:06:08 UTC);
        db.insert_item("b-name", "password", b"nonce1", b"ct1", T0)?;
        db.insert_item("a-name", "env", b"nonce2", b"ct2", t_a)?;
        db.insert_item("c-name", "note", b"nonce3", b"ct3", T0)?;

        let rows = db.list_items()?;
        // list_items orders by name ASC
        let names: Vec<_> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["a-name", "b-name", "c-name"]);

        // Check fields present and timestamps parseable (already parsed in list_items)
        let row = &rows[0];
        assert_eq!(row.kind, "env");
        assert_eq!(row.nonce, b"nonce2");
        assert_eq!(row.ciphertext, b"ct2");
        // Both timestamps are the caller-supplied time, stored exactly.
        assert_eq!(row.created_at, t_a);
        assert_eq!(row.updated_at, t_a);
        assert_eq!(rows[1].created_at, T0);
        assert_eq!(rows[1].updated_at, T0);

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_unique_name_constraint() -> Result<()> {
        let path = tmp_path("unique_name");
        let db = Db::open(&path)?;

        db.insert_item("unique", "password", b"n", b"c", T0)?;
        let dup = db.insert_item("unique", "password", b"n2", b"c2", T0);

        assert!(dup.is_err(), "duplicate item with same name should fail");

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_update_item_changes_ciphertext_and_updated_at() -> Result<()> {
        let path = tmp_path("update_item");
        let db = Db::open(&path)?;

        let created = datetime!(2026-03-04 05:06:07 UTC);
        let updated = datetime!(2026-03-04 05:06:07.010 UTC);

        db.insert_item("item", "note", b"n0", b"c0", created)?;
        let before = db.list_items()?;
        assert_eq!(before.len(), 1);
        let id = before[0].id;
        assert_eq!(before[0].updated_at, created);

        db.update_item(id, b"n1", b"c1", updated)?;

        let after = db.list_items()?;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, id);
        assert_eq!(after[0].nonce, b"n1");
        assert_eq!(after[0].ciphertext, b"c1");
        assert_eq!(after[0].updated_at, updated);
        assert_eq!(after[0].created_at, created);

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_delete_item_removes_row() -> Result<()> {
        let path = tmp_path("delete_item");
        let db = Db::open(&path)?;

        db.insert_item("to-del-1", "note", b"n", b"c", T0)?;
        db.insert_item("to-del-2", "note", b"n2", b"c2", T0)?;
        let rows = db.list_items()?;
        assert_eq!(rows.len(), 2);
        let id = rows[0].id;

        db.delete_item(id)?;
        let rows2 = db.list_items()?;
        assert_eq!(rows2.len(), 1);
        assert_ne!(rows2[0].id, id);

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_itemrow_ad_helpers() {
        let name = "example";
        let kind = "password";
        let ad = ItemRow::ad_for_name_kind(name, kind);
        // Ensure it contains both fields with a separator 0x1f
        let expected = {
            let mut v = Vec::new();
            v.extend_from_slice(name.as_bytes());
            v.push(0x1f);
            v.extend_from_slice(kind.as_bytes());
            v
        };
        assert_eq!(ad, expected);

        // Construct a dummy row to test ad()
        let row = ItemRow {
            id: 1,
            name: name.to_string(),
            kind: kind.to_string(),
            nonce: vec![],
            ciphertext: vec![],
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            uuid: Uuid::nil(),
            revision: Revision::default(),
        };
        assert_eq!(row.ad(), expected);
    }

    // ---- Schema version 1 and migration ----

    /// The version 0 schema, exactly as the pre-versioning `migrate()` created it.
    const V0_DDL: &str = r"
        CREATE TABLE IF NOT EXISTS meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            kdf_params TEXT NOT NULL,
            wrapped_key BLOB NOT NULL,
            verifier BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_items_name ON items(name);
        ";

    const V0_ITEM_COLUMNS: [&str; 7] = ["id", "name", "kind", "nonce", "ciphertext", "created_at", "updated_at"];

    /// One raw `items` row: id, name, kind, nonce, ciphertext, `created_at`, `updated_at`.
    type RawRow = (i64, String, String, Vec<u8>, Vec<u8>, String, String);

    fn raw_row(id: i64, name: &str, kind: &str, created_at: &str, updated_at: &str) -> RawRow {
        (
            id,
            name.to_string(),
            kind.to_string(),
            format!("nonce-{id}").into_bytes(),
            format!("ct-{id}").into_bytes(),
            created_at.to_string(),
            updated_at.to_string(),
        )
    }

    /// Builds a version 0 database at `path` holding `rows`, with explicit row IDs.
    fn write_legacy_db(path: &std::path::Path, rows: &[RawRow]) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(V0_DDL).unwrap();
        for (id, name, kind, nonce, ct, created, updated) in rows {
            conn.execute(
                "INSERT INTO items (id, name, kind, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![id, name, kind, nonce, ct, created, updated],
            )
            .unwrap();
        }
        assert_eq!(read_user_version(&conn).unwrap(), 0);
        conn
    }

    fn raw_rows(conn: &Connection) -> Vec<RawRow> {
        let mut stmt = conn
            .prepare("SELECT id, name, kind, nonce, ciphertext, created_at, updated_at FROM items ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    fn schema_object_exists(conn: &Connection, kind: &str, name: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2)",
            params![kind, name],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// `PRAGMA table_info` rows: (name, declared type, not null, default, pk).
    fn table_info(conn: &Connection, table: &str) -> Vec<(String, String, bool, Option<String>, i64)> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).unwrap();
        stmt.query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    /// The structure of every table and index, comparable across databases whose CREATE
    /// statements differ only in whitespace.
    fn schema_shape(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap();
        let objects = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut out = Vec::new();
        for (kind, name, table) in objects {
            if kind == "table" {
                out.push(format!("table {name}: {:?}", table_info(conn, &name)));
            } else {
                let mut cols = conn.prepare(&format!("PRAGMA index_info({name})")).unwrap();
                let cols = cols
                    .query_map([], |r| r.get::<_, String>(2))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let unique: bool = conn
                    .query_row(
                        &format!("SELECT \"unique\" FROM pragma_index_list('{table}') WHERE name = ?1"),
                        params![name],
                        |r| r.get(0),
                    )
                    .unwrap();
                out.push(format!("{kind} {name} on {table}{cols:?} unique={unique}"));
            }
        }
        out
    }

    fn ms(rfc3339: &str) -> u64 {
        unix_millis(OffsetDateTime::parse(rfc3339, &Rfc3339).unwrap())
    }

    #[test]
    fn test_fresh_database_is_version_1() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("fresh.sqlite3");
        let db = Db::open(&path)?;

        let (vault_uuid, device_id) = {
            let conn = &db.conn;
            assert_eq!(read_user_version(conn)?, 1);
            let (rows, vault_len, device_len, wall, counter): (i64, i64, i64, i64, i64) = conn.query_row(
                "SELECT COUNT(*), length(vault_uuid), length(device_id), hwm_wall_ms, hwm_counter FROM sync_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            assert_eq!((rows, vault_len, device_len, wall, counter), (1, 16, 16, 0, 0));
            let tombstones: i64 = conn.query_row("SELECT COUNT(*) FROM tombstones", [], |r| r.get(0))?;
            assert_eq!(tombstones, 0);
            assert!(!schema_object_exists(conn, "index", "idx_items_name"));
            assert!(schema_object_exists(conn, "index", "idx_items_uuid"));
            assert!(db.is_meta_empty()?, "a fresh vault is still uninitialized");
            (db.vault_uuid()?, db.device_id()?)
        };
        assert_ne!(vault_uuid, Uuid::nil());
        assert_ne!(device_id, Uuid::nil());
        assert_ne!(vault_uuid, device_id);
        assert_eq!(db.high_water_mark()?, HighWaterMark::default());
        drop(db);

        let db = Db::open(&path)?;
        assert_eq!(db.vault_uuid()?, vault_uuid);
        assert_eq!(db.device_id()?, device_id);
        assert_eq!(read_user_version(&db.conn)?, 1);
        Ok(())
    }

    #[test]
    fn test_fresh_and_migrated_schemas_match() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let fresh = Db::open(&dir.path().join("fresh.sqlite3"))?;

        let legacy_path = dir.path().join("legacy.sqlite3");
        drop(write_legacy_db(&legacy_path, &[]));
        let migrated = Db::open(&legacy_path)?;

        assert_eq!(schema_shape(&fresh.conn), schema_shape(&migrated.conn));
        // An empty legacy vault seeds the high-water mark at (0, 0).
        assert_eq!(migrated.high_water_mark()?, HighWaterMark::default());
        Ok(())
    }

    #[test]
    fn test_migrate_legacy_rows() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("legacy.sqlite3");
        let original = vec![
            raw_row(
                3,
                "alpha",
                "password",
                "2025-01-01T00:00:00Z",
                "2025-06-01T12:00:00.250Z",
            ),
            raw_row(
                7,
                "beta",
                "note",
                "2025-01-02T00:00:00Z",
                "2026-02-03T04:05:06.789+02:00",
            ),
            raw_row(8, "gamma", "env", "2024-12-31T23:59:59Z", "2025-03-03T03:03:03Z"),
            raw_row(12, "delta", "apikey", "1969-01-01T00:00:00Z", "1969-06-01T00:00:00Z"),
        ];
        drop(write_legacy_db(&path, &original));

        let db = Db::open(&path)?;
        assert_eq!(read_user_version(&db.conn)?, 1);
        // Every stored column is byte-for-byte unchanged, including timestamp text.
        assert_eq!(raw_rows(&db.conn), original);

        let device_id = db.device_id()?;
        let rows = db.list_items()?;
        assert_eq!(rows.len(), original.len());
        let mut uuids = std::collections::HashSet::new();
        for row in &rows {
            let (_, _, _, _, _, _, updated) = original
                .iter()
                .find(|o| u64::try_from(o.0).unwrap() == row.id)
                .expect("row keeps its id");
            assert!(uuids.insert(row.uuid), "entry UUIDs are distinct");
            assert_ne!(row.uuid, Uuid::nil());
            assert_eq!(
                row.revision,
                Revision {
                    wall_ms: ms(updated),
                    counter: 0,
                    device_id
                }
            );
        }
        let delta = rows.iter().find(|r| r.name == "delta").unwrap();
        assert_eq!(delta.revision.wall_ms, 0, "a time before the epoch seeds 0");

        let greatest = rows.iter().map(|r| r.revision.high_water_mark()).max().unwrap();
        assert_eq!(greatest.wall_ms, ms("2026-02-03T04:05:06.789+02:00"));
        assert_eq!(db.high_water_mark()?, greatest);

        // Reopening changes nothing further.
        let vault_uuid = db.vault_uuid()?;
        let before: Vec<_> = rows.iter().map(|r| (r.id, r.uuid, r.revision)).collect();
        drop(db);
        let db = Db::open(&path)?;
        let after: Vec<_> = db.list_items()?.iter().map(|r| (r.id, r.uuid, r.revision)).collect();
        assert_eq!(after, before);
        assert_eq!(db.vault_uuid()?, vault_uuid);
        assert_eq!(db.device_id()?, device_id);
        assert_eq!(db.high_water_mark()?, greatest);
        assert_eq!(raw_rows(&db.conn), original);
        Ok(())
    }

    #[test]
    fn test_migrate_legacy_encrypted_vault_unlocks() -> Result<()> {
        use crate::{KeyMaterial, Vault, aead_encrypt, derive_key, wrap_vault_key};

        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("legacy.sqlite3");
        let master = "correct horse";
        let entries = [
            ("github", "password", "hunter2"),
            ("AWS_KEY", "env", "AKIA-123"),
            ("todo", "note", "line one\nline two"),
        ];

        {
            let conn = write_legacy_db(&path, &[]);
            let kdf = small_kdf();
            let master_key = derive_key(master, &kdf)?;
            let vault_key = KeyMaterial::random();
            let (wrapped, verifier) = wrap_vault_key(&master_key, &vault_key)?;
            conn.execute(
                "INSERT INTO meta (id, kdf_params, wrapped_key, verifier) VALUES (1, ?, ?, ?)",
                params![serde_json::to_string(&kdf)?, serde_json::to_vec(&wrapped)?, verifier],
            )?;
            for (i, (name, kind, value)) in entries.iter().enumerate() {
                let (nonce, ct) = aead_encrypt(&vault_key, value.as_bytes(), &ItemRow::ad_for_name_kind(name, kind))?;
                let stamp = format!("2025-0{}-01T00:00:00Z", i + 1);
                conn.execute(
                    "INSERT INTO items (name, kind, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    params![name, kind, nonce, ct, stamp, stamp],
                )?;
            }
        }

        let mut vault = Vault::open_or_create(Some(&path))?;
        assert!(vault.is_initialized());
        vault.unlock(master)?;
        let items = vault.list_items()?;
        assert_eq!(items.len(), entries.len());
        for (name, kind, value) in entries {
            let item = items.iter().find(|i| i.name == name).expect("entry survives migration");
            assert_eq!(item.kind.as_str(), kind);
            assert_eq!(item.value, value);
        }
        Ok(())
    }

    #[test]
    fn test_failed_migration_leaves_legacy_database_unchanged() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("legacy.sqlite3");
        let original = vec![
            raw_row(1, "good", "note", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"),
            raw_row(2, "bad", "note", "2025-01-01T00:00:00Z", "yesterday afternoon"),
            raw_row(3, "also-good", "note", "2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z"),
        ];
        drop(write_legacy_db(&path, &original));

        let err = Db::open(&path).expect_err("an unparseable updated_at fails the migration");
        assert!(format!("{err:#}").contains("RFC 3339"), "{err:#}");

        let conn = Connection::open(&path)?;
        assert_eq!(read_user_version(&conn)?, 0);
        let columns: Vec<String> = table_info(&conn, "items").into_iter().map(|c| c.0).collect();
        assert_eq!(columns, V0_ITEM_COLUMNS);
        assert!(schema_object_exists(&conn, "index", "idx_items_name"));
        assert!(!schema_object_exists(&conn, "index", "idx_items_uuid"));
        assert!(!schema_object_exists(&conn, "table", "tombstones"));
        assert!(!schema_object_exists(&conn, "table", "sync_meta"));
        assert_eq!(raw_rows(&conn), original);
        Ok(())
    }

    #[test]
    fn test_newer_schema_is_refused_and_not_modified() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("future.sqlite3");
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch("CREATE TABLE future_table (x INTEGER); PRAGMA user_version = 2;")?;
        }

        let err = Db::open(&path).expect_err("a newer schema is refused");
        let msg = err.to_string();
        assert!(msg.contains("Update Chamber"), "{msg}");
        assert!(msg.contains("newer version of Chamber"), "{msg}");
        assert!(msg.contains("schema version 2"), "{msg}");

        let conn = Connection::open(&path)?;
        assert_eq!(read_user_version(&conn)?, 2);
        let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        assert_eq!(journal, "delete", "not even the journal mode is written");
        assert!(!schema_object_exists(&conn, "table", "items"));
        assert!(!schema_object_exists(&conn, "table", "sync_meta"));
        Ok(())
    }

    #[test]
    fn test_migration_rechecks_version_under_lock() -> Result<()> {
        // Simulates losing the race to another process: the database is already at version 1
        // by the time the migration holds the write lock, so it must change nothing.
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("v1.sqlite3"))?;
        db.insert_item("a", "note", b"n", b"c", T0)?;
        let ids = (db.vault_uuid()?, db.device_id()?, db.high_water_mark()?);

        migrate_v0_to_v1(&db.conn)?;

        assert_eq!((db.vault_uuid()?, db.device_id()?, db.high_water_mark()?), ids);
        assert_eq!(db.list_items()?.len(), 1);
        Ok(())
    }

    #[test]
    fn test_wall_ms_round_trips_full_u64_range() -> Result<()> {
        for v in [0, 1, i64::MAX.unsigned_abs(), i64::MAX.unsigned_abs() + 1, u64::MAX] {
            assert_eq!(wall_ms_from_sql(wall_ms_to_sql(v)), v);
        }
        // Through SQLite too: a high-water mark above i64::MAX survives storage.
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("hwm.sqlite3"))?;
        let hwm = HighWaterMark {
            wall_ms: u64::MAX - 5,
            counter: u32::MAX,
        };
        write_high_water_mark(&db.conn, hwm)?;
        assert_eq!(db.high_water_mark()?, hwm);
        Ok(())
    }

    // ---- Local writes ----

    #[test]
    fn test_create_assigns_uuid_and_revision() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("create.sqlite3");
        let db = Db::open(&path)?;
        let device_id = db.device_id()?;
        let t0_ms = unix_millis(T0);

        db.insert_item("a", "note", b"n1", b"c1", T0)?;
        let a = db.list_items()?.into_iter().find(|r| r.name == "a").unwrap();
        assert_ne!(a.uuid, Uuid::nil());
        assert_eq!(
            a.revision,
            Revision {
                wall_ms: t0_ms,
                counter: 0,
                device_id
            }
        );
        assert_eq!(db.high_water_mark()?, a.revision.high_water_mark());

        // Same millisecond: the counter breaks the tie.
        db.insert_item("b", "note", b"n2", b"c2", T0)?;
        let b = db.list_items()?.into_iter().find(|r| r.name == "b").unwrap();
        assert_ne!(b.uuid, a.uuid);
        assert_eq!(
            b.revision,
            Revision {
                wall_ms: t0_ms,
                counter: 1,
                device_id
            }
        );
        assert!(b.revision > a.revision);
        assert_eq!(
            db.high_water_mark()?,
            HighWaterMark {
                wall_ms: t0_ms,
                counter: 1
            }
        );

        let blob_lengths: Vec<(i64, i64)> = db
            .conn
            .prepare("SELECT length(uuid), length(rev_device_id) FROM items")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(blob_lengths, vec![(16, 16), (16, 16)]);

        // The high-water mark and revisions survive reopening.
        drop(db);
        let db = Db::open(&path)?;
        assert_eq!(
            db.high_water_mark()?,
            HighWaterMark {
                wall_ms: t0_ms,
                counter: 1
            }
        );
        let revisions: Vec<_> = db.list_items()?.iter().map(|r| (r.uuid, r.revision)).collect();
        assert_eq!(revisions, vec![(a.uuid, a.revision), (b.uuid, b.revision)]);
        Ok(())
    }

    #[test]
    fn test_duplicate_name_writes_nothing() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("dup.sqlite3"))?;
        db.insert_item("dup", "note", b"n", b"c", T0)?;
        let hwm = db.high_water_mark()?;

        // A later time would move the high-water mark if anything were written.
        let later = T0 + time::Duration::hours(1);
        let err = db.insert_item("dup", "password", b"n2", b"c2", later).unwrap_err();
        assert_eq!(err.to_string(), "An item named 'dup' already exists");
        assert!(err.to_string().contains("already exists"));

        let rows = db.list_items()?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ciphertext, b"c");
        assert_eq!(db.high_water_mark()?, hwm);
        Ok(())
    }

    #[test]
    fn test_name_match_is_exact_and_case_sensitive() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("case.sqlite3"))?;
        db.insert_item("Name", "note", b"n", b"c", T0)?;
        db.insert_item("name", "note", b"n", b"c", T0)?;
        db.insert_item("name ", "note", b"n", b"c", T0)?;
        assert_eq!(db.list_items()?.len(), 3);
        assert!(db.insert_item("name", "note", b"n", b"c", T0).is_err());
        Ok(())
    }

    #[test]
    fn test_edit_assigns_greater_revision_and_keeps_uuid() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("edit.sqlite3"))?;
        let device_id = db.device_id()?;
        db.insert_item("item", "note", b"n0", b"c0", T0)?;
        let before = db.list_items()?.remove(0);

        // Same millisecond as the create.
        db.update_item(before.id, b"n1", b"c1", T0)?;
        let mid = db.list_items()?.remove(0);
        assert_eq!(mid.uuid, before.uuid);
        assert!(mid.revision > before.revision);
        assert_eq!((mid.revision.wall_ms, mid.revision.counter), (unix_millis(T0), 1));
        assert_eq!(mid.created_at, before.created_at);
        assert_eq!(db.high_water_mark()?, mid.revision.high_water_mark());

        // Later time.
        let later = T0 + time::Duration::seconds(5);
        db.update_item(before.id, b"n2", b"c2", later)?;
        let after = db.list_items()?.remove(0);
        assert_eq!(after.uuid, before.uuid);
        assert_eq!(
            after.revision,
            Revision {
                wall_ms: unix_millis(later),
                counter: 0,
                device_id
            }
        );
        assert!(after.revision > mid.revision);
        assert_eq!(after.created_at, T0);
        assert_eq!(after.updated_at, later);
        assert_eq!(after.ciphertext, b"c2");
        Ok(())
    }

    #[test]
    fn test_edit_missing_id_changes_nothing() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("edit_missing.sqlite3"))?;
        db.insert_item("item", "note", b"n0", b"c0", T0)?;
        let hwm = db.high_water_mark()?;
        let before = db.list_items()?.remove(0);

        db.update_item(before.id + 100, b"n1", b"c1", T0 + time::Duration::hours(1))?;

        assert_eq!(db.high_water_mark()?, hwm);
        let after = db.list_items()?.remove(0);
        assert_eq!((after.revision, after.ciphertext), (before.revision, before.ciphertext));
        Ok(())
    }

    // ---- Delete and tombstones ----

    /// `(id, uuid, revision)` of every row, in `list_items` order.
    fn identities(db: &Db) -> Vec<(u64, Uuid, Revision)> {
        db.list_items()
            .unwrap()
            .into_iter()
            .map(|r| (r.id, r.uuid, r.revision))
            .collect()
    }

    #[test]
    fn test_delete_records_tombstone_and_keeps_other_rows() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("tombstone.sqlite3"))?;
        db.insert_item("a", "note", b"n1", b"c1", T0)?;
        db.insert_item("b", "note", b"n2", b"c2", T0)?;
        db.insert_item("c", "note", b"n3", b"c3", T0)?;
        let before = identities(&db);
        let (doomed_id, doomed_uuid, _) = before[1];
        assert!(db.tombstones()?.is_empty());

        db.delete_item(doomed_id)?;

        let after = identities(&db);
        assert_eq!(
            after,
            vec![before[0], before[2]],
            "other rows keep id, UUID, and revision"
        );
        assert!(after.iter().all(|(id, _, _)| *id != doomed_id));
        assert_eq!(db.tombstones()?, vec![doomed_uuid]);
        Ok(())
    }

    #[test]
    fn test_delete_missing_id_records_nothing() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("tombstone_missing.sqlite3"))?;
        db.insert_item("a", "note", b"n", b"c", T0)?;
        let hwm = db.high_water_mark()?;
        let before = identities(&db);

        db.delete_item(before[0].0 + 100)?;

        assert!(db.tombstones()?.is_empty());
        assert_eq!(db.high_water_mark()?, hwm);
        assert_eq!(identities(&db), before);
        Ok(())
    }

    #[test]
    fn test_delete_leaves_high_water_mark_unchanged() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let db = Db::open(&dir.path().join("tombstone_hwm.sqlite3"))?;
        db.insert_item("a", "note", b"n1", b"c1", T0)?;
        db.insert_item("b", "note", b"n2", b"c2", T0 + time::Duration::seconds(1))?;
        let hwm = db.high_water_mark()?;
        assert_ne!(hwm, HighWaterMark::default());

        // Deleting the item that holds the high-water mark does not lower it.
        let b_id = db.list_items()?.into_iter().find(|r| r.name == "b").unwrap().id;
        db.delete_item(b_id)?;
        assert_eq!(db.high_water_mark()?, hwm);

        let a_id = db.list_items()?.remove(0).id;
        db.delete_item(a_id)?;
        assert_eq!(db.high_water_mark()?, hwm);
        assert!(db.list_items()?.is_empty());
        assert_eq!(db.tombstones()?.len(), 2);
        Ok(())
    }

    #[test]
    fn test_delete_is_atomic_when_row_deletion_fails() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("tombstone_atomic.sqlite3");
        let db = Db::open(&path)?;
        db.insert_item("a", "note", b"n", b"c", T0)?;
        let before = identities(&db);
        let hwm = db.high_water_mark()?;

        {
            let raw = Connection::open(&path)?;
            raw.execute_batch(
                "CREATE TRIGGER refuse_delete BEFORE DELETE ON items \
                 BEGIN SELECT RAISE(ABORT, 'delete refused by test'); END;",
            )?;
        }

        let err = db.delete_item(before[0].0).expect_err("the trigger aborts the delete");
        assert!(format!("{err:#}").contains("delete refused by test"), "{err:#}");
        assert_eq!(identities(&db), before, "the row is still present");
        assert!(db.tombstones()?.is_empty(), "no tombstone was written");
        assert_eq!(db.high_water_mark()?, hwm);

        // The failed delete left no transaction open: once the trigger is gone it succeeds.
        {
            let raw = Connection::open(&path)?;
            raw.execute_batch("DROP TRIGGER refuse_delete;")?;
        }
        db.delete_item(before[0].0)?;
        assert_eq!(db.tombstones()?, vec![before[0].1]);
        Ok(())
    }

    #[test]
    fn test_tombstones_are_ascending_by_bytes() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("tombstone_order.sqlite3");
        let db = Db::open(&path)?;
        // Fixed UUIDs, inserted in descending order, so the result order cannot come from
        // insertion order. The high bit of the first byte checks unsigned comparison.
        let high = Uuid::from_bytes([0xF0; 16]);
        let low = Uuid::from_bytes([0x01; 16]);
        let mid = Uuid::from_bytes([0x7F; 16]);
        for uuid in [high, low, mid] {
            db.conn
                .execute("INSERT INTO tombstones (uuid) VALUES (?1)", params![uuid.as_bytes()])?;
        }
        assert_eq!(db.tombstones()?, vec![low, mid, high]);

        drop(db);
        let db = Db::open(&path)?;
        assert_eq!(db.tombstones()?, vec![low, mid, high], "tombstones survive reopening");
        Ok(())
    }
}
