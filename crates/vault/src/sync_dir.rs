//! Sync directories: publishing this machine's snapshot and merging the snapshots of others.
//!
//! A sync directory is an ordinary directory that some transport (Syncthing, a shared drive,
//! `rsync`, a USB stick, anything that copies files) keeps in step between machines. Chamber only
//! reads and writes files in it; moving them between machines is the transport's job.
//!
//! The rules:
//!
//! * Each machine publishes exactly one file, `<device-id>.chsnap`, holding its complete state
//!   ([`Vault::publish_snapshot`]). The device ID is lowercase hyphenated hexadecimal. The file
//!   is written to `.<device-id>.chsnap.tmp` first, flushed to disk, and then renamed over the
//!   published name, so readers see either the previous snapshot or the new one, never a mix.
//! * A merge ([`Vault::merge_snapshots`]) reads every candidate file: a regular file directly in
//!   the directory whose name ends in `.chsnap` and does not start with a dot. Subdirectories are
//!   not searched and symbolic links are not followed. Transport conflict copies keep the
//!   `.chsnap` ending and are read; in-progress temporary files start with a dot and are not.
//! * File names decide only which files are read. The publisher is taken from the authenticated
//!   snapshot header, never from the name, and neither names, arrival order, nor modification
//!   times affect what a merge does.
//! * The working database is never inside the sync directory: both operations refuse a directory
//!   that contains the vault's database file at any depth, comparing resolved paths.
//! * The directory and the files get default permissions, so a transport running under another
//!   account can read and write them. Snapshots are encrypted, so nothing in them is readable
//!   without the vault key.
//!
//! A file missing from the directory means nothing: only authenticated tombstones delete entries.
//! Neither operation decrypts a secret value or writes plaintext to disk, and neither reads from
//! or writes to the terminal; they return a [`PublishReport`] or a [`MergeReport`] for the caller
//! to present.

use crate::Vault;
use crate::crypto::KeyMaterial;
use crate::merge::MergeCounts;
use crate::snapshot::{SnapshotRejection, derive_snapshot_key, encode_snapshot, read_snapshot_file};
use color_eyre::Result;
use color_eyre::eyre::{WrapErr as _, eyre};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The extension of a published snapshot file, without the dot.
pub const SNAPSHOT_EXTENSION: &str = "chsnap";

/// The environment variable a caller reads to pass to [`resolve_sync_dir`]. The library never
/// reads it itself.
pub const SYNC_DIR_ENV: &str = "CHAMBER_SYNC_DIR";

/// The candidate-file suffix: a dot followed by [`SNAPSHOT_EXTENSION`].
const SNAPSHOT_SUFFIX: &[u8] = b".chsnap";

// ---- Directory resolution ----

/// Returns the default sync directory: `chamber/sync` under the platform data directory
/// (`dirs::data_dir()`), which is `~/.local/share/chamber/sync` on Linux.
///
/// Computing the path creates nothing.
///
/// # Errors
/// Returns an error when the platform data directory cannot be determined (for example when no
/// home directory is known).
pub fn default_sync_dir() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        eyre!(
            "The default sync directory cannot be determined because the platform data directory is unknown. \
             Pass a sync directory explicitly or set {SYNC_DIR_ENV}."
        )
    })?;
    Ok(data_dir.join("chamber").join("sync"))
}

/// Resolves the sync directory: `explicit` when given, otherwise `env_value` when given and not
/// empty, otherwise [`default_sync_dir`].
///
/// The caller reads the environment (normally [`SYNC_DIR_ENV`]) and passes its value; an empty
/// value counts as unset. The directory is not stored as a setting, and nothing is created.
///
/// # Errors
/// Returns an error only when the default is needed and [`default_sync_dir`] fails.
pub fn resolve_sync_dir(explicit: Option<&Path>, env_value: Option<&OsStr>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(value) = env_value.filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(value));
    }
    default_sync_dir()
}

/// The name of the snapshot file a machine publishes: `<device-id>.chsnap`, with the device ID in
/// lowercase hyphenated hexadecimal.
#[must_use]
pub fn snapshot_file_name(device_id: Uuid) -> String {
    format!("{}.{SNAPSHOT_EXTENSION}", device_id.hyphenated())
}

/// The name of the temporary file a publication writes before renaming it into place:
/// `.<device-id>.chsnap.tmp`. The leading dot keeps merges from reading it.
fn temp_file_name(device_id: Uuid) -> String {
    format!(".{}.tmp", snapshot_file_name(device_id))
}

/// Whether a directory entry's name makes it a merge candidate: it ends in `.chsnap` and does not
/// start with a dot. The file type is checked separately.
fn is_candidate_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    !bytes.starts_with(b".") && bytes.ends_with(SNAPSHOT_SUFFIX)
}

// ---- Reports and errors ----

/// What [`Vault::publish_snapshot`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReport {
    /// The snapshot file written: `<sync dir>/<device-id>.chsnap`.
    pub path: PathBuf,
    /// The fresh snapshot ID in the file's header.
    pub snapshot_id: Uuid,
    /// How many entries the snapshot carries.
    pub entries: usize,
    /// How many tombstones the snapshot carries.
    pub tombstones: usize,
}

/// What happened to one candidate file during [`Vault::merge_snapshots`].
#[derive(Debug)]
pub enum FileOutcome {
    /// The file was valid and its state was merged in its own transaction.
    Merged(MergeCounts),
    /// The file was not merged, for the reason given. Nothing from it reached the vault.
    Skipped(SnapshotRejection),
}

/// One candidate file and its outcome.
#[derive(Debug)]
pub struct FileReport {
    /// The file's name within the sync directory (not a full path). A name that is not valid
    /// Unicode is shown with replacement characters.
    pub file_name: String,
    /// Whether the file was merged or skipped.
    pub outcome: FileOutcome,
}

/// What [`Vault::merge_snapshots`] did: one item per candidate file, ascending by file name.
///
/// It holds file names, merge counts, and rejection reasons only: never entry names, secret
/// values, keys, or payload contents.
#[derive(Debug, Default)]
pub struct MergeReport {
    /// Every candidate file, ascending by file name.
    pub files: Vec<FileReport>,
}

impl MergeReport {
    /// Whether no candidate file was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Whether any candidate file was skipped.
    #[must_use]
    pub fn any_skipped(&self) -> bool {
        self.files
            .iter()
            .any(|file| matches!(file.outcome, FileOutcome::Skipped(_)))
    }

    /// The merged files, by name, with their counts.
    pub fn merged(&self) -> impl Iterator<Item = (&str, MergeCounts)> {
        self.files.iter().filter_map(|file| match &file.outcome {
            FileOutcome::Merged(counts) => Some((file.file_name.as_str(), *counts)),
            FileOutcome::Skipped(_) => None,
        })
    }

    /// The skipped files, by name, with the reason each was rejected.
    pub fn skipped(&self) -> impl Iterator<Item = (&str, &SnapshotRejection)> {
        self.files.iter().filter_map(|file| match &file.outcome {
            FileOutcome::Skipped(rejection) => Some((file.file_name.as_str(), rejection)),
            FileOutcome::Merged(_) => None,
        })
    }
}

/// Why a sync directory was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncDirError {
    /// The sync directory contains the vault's working database file, directly or in a
    /// subdirectory. Both paths are resolved (absolute, symbolic links followed).
    ContainsDatabase {
        /// The resolved sync directory.
        sync_dir: PathBuf,
        /// The resolved database file.
        database: PathBuf,
    },
    /// The sync directory path exists but is not a directory.
    NotADirectory {
        /// The path as given.
        path: PathBuf,
    },
}

impl fmt::Display for SyncDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainsDatabase { sync_dir, database } => write!(
                f,
                "The sync directory {} contains this vault's database ({}). A transport would copy the working \
                 database between machines, so choose a sync directory outside the folder that holds it.",
                sync_dir.display(),
                database.display()
            ),
            Self::NotADirectory { path } => write!(
                f,
                "The sync directory {} exists but is not a directory. Choose a directory, or a path where one can \
                 be created.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for SyncDirError {}

// ---- Publication and merge ----

/// A publication that has written its temporary file but not yet renamed it into place. Dropping
/// it leaves the temporary file behind, exactly as an interrupted publication would; the next
/// publication removes it.
#[derive(Debug)]
struct PreparedPublication {
    temp_path: PathBuf,
    sync_dir: PathBuf,
    report: PublishReport,
}

impl PreparedPublication {
    /// Step 7: renames the temporary file over the published name. If the rename fails, the
    /// temporary file is removed on a best-effort basis and the previous snapshot stays.
    fn commit(self) -> Result<PublishReport> {
        if let Err(err) = fs::rename(&self.temp_path, &self.report.path) {
            // Best effort: the rename already failed, and that is the error worth reporting.
            let _ = fs::remove_file(&self.temp_path);
            return Err(err).wrap_err_with(|| {
                format!(
                    "The snapshot could not be moved into place at {}",
                    self.report.path.display()
                )
            });
        }
        sync_directory(&self.sync_dir);
        Ok(self.report)
    }
}

impl Vault {
    /// Publishes this machine's complete state into `sync_dir` as `<device-id>.chsnap`.
    ///
    /// Every entry exactly as stored (still encrypted) and every tombstone are read in one
    /// database transaction ([`Vault::export_sync_state`]) and encoded as a snapshot with a fresh
    /// snapshot ID and nonce. The directory is created, with any missing parents, when it does
    /// not exist. Any temporary file a previous interrupted publication of this machine left is
    /// removed; the encrypted bytes are written to `.<device-id>.chsnap.tmp`, flushed to disk,
    /// and renamed over `<device-id>.chsnap`, so the previous snapshot is replaced atomically.
    ///
    /// Only this machine's snapshot file and its temporary file are written, both with default
    /// permissions. No secret value is decrypted and no plaintext is written.
    ///
    /// # Errors
    /// Returns `eyre!("Locked")` on a locked vault, before anything else;
    /// [`SyncDirError::ContainsDatabase`] when `sync_dir` contains the vault's database file;
    /// [`SyncDirError::NotADirectory`] when `sync_dir` exists but is not a directory; and any
    /// error from reading the state, encoding the snapshot, creating the directory, or writing,
    /// flushing, or renaming the file. On failure the previously published snapshot, if any, is
    /// left as it was.
    pub fn publish_snapshot(&self, sync_dir: &Path) -> Result<PublishReport> {
        self.prepare_publication(sync_dir)?.commit()
    }

    /// Steps 1 to 6 of a publication: everything up to and including writing and flushing the
    /// temporary file, but not the rename. Kept separate from [`PreparedPublication::commit`] so
    /// tests can stop in between to simulate an interrupted publication.
    fn prepare_publication(&self, sync_dir: &Path) -> Result<PreparedPublication> {
        let (snapshot_key, vault_uuid) = self.snapshot_key()?;
        refuse_database_inside(sync_dir, &self.db_path)?;

        let state = self.export_sync_state()?;
        let device_id = self.device_id()?;
        let encoded = encode_snapshot(&snapshot_key, vault_uuid, device_id, &state)?;

        ensure_directory(sync_dir)?;
        let temp_path = sync_dir.join(temp_file_name(device_id));
        write_temp_file(&temp_path, &encoded.bytes)?;

        Ok(PreparedPublication {
            temp_path,
            sync_dir: sync_dir.to_path_buf(),
            report: PublishReport {
                path: sync_dir.join(snapshot_file_name(device_id)),
                snapshot_id: encoded.snapshot_id,
                entries: state.entries.len(),
                tombstones: state.tombstones.len(),
            },
        })
    }

    /// Merges every candidate snapshot file in `sync_dir` and reports one item per file.
    ///
    /// Candidates are the regular files directly in `sync_dir` whose names end in `.chsnap` and
    /// do not start with a dot; subdirectories are not searched and symbolic links are not
    /// followed. They are processed in ascending file-name order so the report is stable, but
    /// the resulting state does not depend on that order, on file names, or on modification
    /// times. Each file is read and fully validated with [`read_snapshot_file`] and then merged
    /// with [`Vault::merge_sync_state`] in its own transaction. A file that cannot be read or
    /// fails validation is recorded as skipped with its [`SnapshotRejection`], nothing from it is
    /// merged, and the remaining files are still processed. A machine's own file needs no special
    /// case: merging it changes nothing.
    ///
    /// When `sync_dir` does not exist or holds no candidate file, the report is empty and the
    /// directory is not created. The merge never writes to the sync directory and never deletes a
    /// file. No secret value is decrypted; each decrypted payload exists in memory only.
    ///
    /// # Errors
    /// Returns `eyre!("Locked")` on a locked vault, before anything else;
    /// [`SyncDirError::NotADirectory`] when `sync_dir` exists but is not a directory;
    /// [`SyncDirError::ContainsDatabase`] when it contains the vault's database file (checked
    /// before any file is read); an error when the directory cannot be listed; and the database
    /// error when merging a file's state fails locally. In that last case that file's
    /// transaction is rolled back, files merged before it stay merged, and later files are not
    /// processed.
    pub fn merge_snapshots(&mut self, sync_dir: &Path) -> Result<MergeReport> {
        let (snapshot_key, vault_uuid) = self.snapshot_key()?;
        match fs::metadata(sync_dir) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(SyncDirError::NotADirectory {
                    path: sync_dir.to_path_buf(),
                }
                .into());
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(MergeReport::default()),
            Err(err) => {
                return Err(err)
                    .wrap_err_with(|| format!("The sync directory {} could not be read", sync_dir.display()));
            }
        }
        refuse_database_inside(sync_dir, &self.db_path)?;

        let mut report = MergeReport::default();
        for candidate in list_candidates(sync_dir)? {
            let outcome = match candidate
                .path
                .and_then(|path| read_snapshot_file(&path, vault_uuid, &snapshot_key))
            {
                Ok(decoded) => {
                    let counts = self.merge_sync_state(&decoded.state).wrap_err_with(|| {
                        format!(
                            "Merging the snapshot file {} failed, so nothing from it was merged",
                            candidate.file_name
                        )
                    })?;
                    FileOutcome::Merged(counts)
                }
                Err(rejection) => FileOutcome::Skipped(rejection),
            };
            report.files.push(FileReport {
                file_name: candidate.file_name,
                outcome,
            });
        }
        Ok(report)
    }

    /// Step 1 of both operations: requires an unlocked vault and derives the snapshot key.
    /// Returns the key with the vault UUID it was derived from.
    fn snapshot_key(&self) -> Result<(KeyMaterial, Uuid)> {
        let vault_key = self.key.as_ref().ok_or_else(|| eyre!("Locked"))?;
        let vault_uuid = self.vault_uuid()?;
        Ok((derive_snapshot_key(vault_key, vault_uuid), vault_uuid))
    }
}

// ---- Filesystem helpers ----

/// Refuses `sync_dir` when it contains the database file at `db_path`, at any depth, comparing
/// resolved paths. A directory that does not exist cannot contain it.
fn refuse_database_inside(sync_dir: &Path, db_path: &Path) -> Result<()> {
    let resolved_dir = match fs::canonicalize(sync_dir) {
        Ok(path) => path,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err)
                .wrap_err_with(|| format!("The sync directory {} could not be resolved", sync_dir.display()));
        }
    };
    let resolved_db = fs::canonicalize(db_path)
        .wrap_err_with(|| format!("The vault database path {} could not be resolved", db_path.display()))?;
    if resolved_db.starts_with(&resolved_dir) {
        return Err(SyncDirError::ContainsDatabase {
            sync_dir: resolved_dir,
            database: resolved_db,
        }
        .into());
    }
    Ok(())
}

/// Step 5: creates `dir`, with any missing parents and default permissions, unless it exists.
fn ensure_directory(dir: &Path) -> Result<()> {
    match fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(SyncDirError::NotADirectory {
            path: dir.to_path_buf(),
        }
        .into()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => fs::create_dir_all(dir)
            .wrap_err_with(|| format!("The sync directory {} could not be created", dir.display())),
        Err(err) => Err(err).wrap_err_with(|| format!("The sync directory {} could not be read", dir.display())),
    }
}

/// Step 6: removes any leftover file at `path`, then creates it with default permissions, writes
/// `bytes`, and flushes it to disk. A partial file left by a failed write is removed on a
/// best-effort basis.
fn write_temp_file(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).wrap_err_with(|| {
                format!(
                    "The leftover temporary snapshot file {} could not be removed",
                    path.display()
                )
            });
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .wrap_err_with(|| format!("The temporary snapshot file {} could not be created", path.display()))?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        // Best effort: the write already failed, and that is the error worth reporting.
        let _ = fs::remove_file(path);
        return Err(err)
            .wrap_err_with(|| format!("The temporary snapshot file {} could not be written", path.display()));
    }
    Ok(())
}

/// Flushes a directory's entries to disk so a completed rename survives a crash. Best effort: the
/// snapshot is already in place, and some platforms and filesystems do not support this.
#[cfg(unix)]
fn sync_directory(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Directories cannot be opened for flushing on this platform; the rename stands as it is.
#[cfg(not(unix))]
const fn sync_directory(_dir: &Path) {}

/// One candidate file found by [`list_candidates`]. `path` is the error when the entry's type
/// could not be determined, which makes the file unreadable.
struct Candidate {
    file_name: String,
    path: Result<PathBuf, SnapshotRejection>,
}

/// Lists the candidate files directly in `dir`, ascending by file name: regular files (symbolic
/// links are not followed) whose names end in `.chsnap` and do not start with a dot.
fn list_candidates(dir: &Path) -> Result<Vec<Candidate>> {
    let listing_error = || format!("The sync directory {} could not be listed", dir.display());
    let mut found: Vec<(OsString, Result<PathBuf, SnapshotRejection>)> = Vec::new();
    for entry in fs::read_dir(dir).wrap_err_with(listing_error)? {
        let entry = entry.wrap_err_with(listing_error)?;
        let name = entry.file_name();
        if !is_candidate_name(&name) {
            continue;
        }
        // `DirEntry::file_type` describes the entry itself, without following a symbolic link.
        match entry.file_type() {
            Ok(file_type) if file_type.is_file() => found.push((name, Ok(entry.path()))),
            Ok(_) => {}
            Err(err) => found.push((name, Err(SnapshotRejection::Unreadable(err)))),
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found
        .into_iter()
        .map(|(name, path)| Candidate {
            file_name: name.to_string_lossy().into_owned(),
            path,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    use super::*;
    use crate::clock::ManualClock;
    use crate::enroll::{ENROLLMENT_EXTENSION, EnrollmentPackage};
    use crate::merge::SyncState;
    use crate::revision::Revision;
    use crate::snapshot::{FORMAT_VERSION, MAX_FILE_LEN, PACKAGE_TYPE_ENROLLMENT};
    use crate::{Item, ItemKind, NewItem};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tempfile::TempDir;
    use time::macros::datetime;
    use time::{Duration, OffsetDateTime};

    const PASSWORD: &str = "sync-master";
    const START: OffsetDateTime = datetime!(2026-11-17 09:00:00 UTC);

    /// The entries machine 0 holds before the others join.
    const BASE: [(&str, &str); 4] = [
        ("github", "gh-token-1"),
        ("aws", "aws-key-1"),
        ("notes", "note-1"),
        ("wifi", "wifi-pass-1"),
    ];

    // ---- Machines ----

    /// One simulated machine: a vault with its own clock and its own sync directory. Files move
    /// between machines only by copying them from one sync directory to another.
    #[derive(Debug)]
    struct Machine {
        vault: Vault,
        clock: Arc<ManualClock>,
        sync: PathBuf,
    }

    impl Machine {
        fn device_id(&self) -> Uuid {
            self.vault.device_id().unwrap()
        }

        fn add(&mut self, name: &str, value: &str) {
            self.vault
                .create_item(&NewItem {
                    name: name.into(),
                    kind: ItemKind::Password,
                    value: value.into(),
                })
                .unwrap();
        }

        fn item(&self, name: &str) -> Item {
            self.vault
                .get_item_by_name(name)
                .unwrap()
                .unwrap_or_else(|| panic!("no item named {name}"))
        }

        fn edit(&mut self, name: &str, value: &str) {
            let id = self.item(name).id;
            self.vault.update_item(id, value).unwrap();
        }

        fn delete(&mut self, name: &str) {
            let id = self.item(name).id;
            self.vault.delete_item(id).unwrap();
        }

        fn value(&self, name: &str) -> Option<String> {
            self.vault.get_item_by_name(name).unwrap().map(|item| item.value)
        }

        fn publish(&self) -> PublishReport {
            self.vault.publish_snapshot(&self.sync).unwrap()
        }

        fn merge(&mut self) -> MergeReport {
            self.vault.merge_snapshots(&self.sync).unwrap()
        }

        fn state(&self) -> SyncState {
            self.vault.export_sync_state().unwrap()
        }

        fn snapshot_path(&self) -> PathBuf {
            self.sync.join(snapshot_file_name(self.device_id()))
        }
    }

    fn clocked_vault(path: &Path) -> (Vault, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(START));
        let vault = Vault::open_or_create_with_clock(Some(path), clock.clone()).unwrap();
        (vault, clock)
    }

    /// Builds `N` machines sharing one vault: machine 0 is created and given the [`BASE`]
    /// entries, and the others join it through one enrollment package. Machine `i` keeps its
    /// database in `<root>/vault-i/` and syncs through `<root>/sync-i/`, which does not exist yet.
    fn network<const N: usize>() -> (TempDir, [Machine; N]) {
        let root = TempDir::new().unwrap();
        let mut machines = Vec::with_capacity(N);
        for index in 0..N {
            let (mut vault, clock) = clocked_vault(&root.path().join(format!("vault-{index}")).join("vault.sqlite3"));
            if index == 0 {
                vault.initialize(PASSWORD).unwrap();
                vault.unlock(PASSWORD).unwrap();
            }
            machines.push(Machine {
                vault,
                clock,
                sync: root.path().join(format!("sync-{index}")),
            });
        }
        for (name, value) in BASE {
            machines[0].add(name, value);
        }

        let package = root.path().join(format!("join.{ENROLLMENT_EXTENSION}"));
        let secret = machines[0].vault.write_enrollment_package(&package).unwrap();
        let opened = EnrollmentPackage::read_file(&package).unwrap().open(&secret).unwrap();
        for machine in &mut machines[1..] {
            machine.vault.join_enrollment(&opened, PASSWORD).unwrap();
            machine.vault.unlock(PASSWORD).unwrap();
        }
        (root, machines.try_into().unwrap())
    }

    /// Copies `from`'s published snapshot into `to`'s sync directory under `name`.
    fn deliver_as(from: &Machine, to: &Machine, name: &str) {
        fs::create_dir_all(&to.sync).unwrap();
        fs::copy(from.snapshot_path(), to.sync.join(name)).unwrap();
    }

    /// Copies `from`'s published snapshot into `to`'s sync directory under its own name.
    fn deliver(from: &Machine, to: &Machine) {
        deliver_as(from, to, &snapshot_file_name(from.device_id()));
    }

    /// Both machines publish, each receives the other's file, and both merge.
    fn exchange(a: &mut Machine, b: &mut Machine) {
        a.publish();
        b.publish();
        deliver(a, b);
        deliver(b, a);
        a.merge();
        b.merge();
    }

    /// Every item, decrypted, with its identity, ascending by UUID.
    fn items(machine: &Machine) -> Vec<(Uuid, String, ItemKind, String, Revision)> {
        let mut items: Vec<_> = machine
            .vault
            .list_items()
            .unwrap()
            .into_iter()
            .map(|item| (item.uuid, item.name, item.kind, item.value, item.revision))
            .collect();
        items.sort_by_key(|item| item.0);
        items
    }

    /// Asserts that every machine has the same synchronization state and the same decrypted
    /// items as the first.
    fn assert_converged(machines: &[&Machine]) {
        let (first, rest) = machines.split_first().unwrap();
        for (index, other) in rest.iter().enumerate() {
            assert_eq!(
                first.state(),
                other.state(),
                "machine {} differs from the first",
                index + 1
            );
            assert_eq!(items(first), items(other), "machine {} decrypts differently", index + 1);
        }
    }

    /// Every name in `dir`, dot files included, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Every path under `dir`, recursively, relative to it.
    fn tree(dir: &Path) -> BTreeSet<PathBuf> {
        let mut found = BTreeSet::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).unwrap() {
                let path = entry.unwrap().path();
                if fs::symlink_metadata(&path).unwrap().is_dir() {
                    pending.push(path.clone());
                }
                found.insert(path.strip_prefix(dir).unwrap().to_path_buf());
            }
        }
        found
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    fn sync_dir_error(err: &color_eyre::Report) -> &SyncDirError {
        err.downcast_ref::<SyncDirError>()
            .unwrap_or_else(|| panic!("expected a SyncDirError, got {err:#}"))
    }

    fn counts(added: usize, replaced: usize, removed: usize, unchanged: usize) -> MergeCounts {
        MergeCounts {
            added,
            replaced,
            removed,
            unchanged,
        }
    }

    // ---- Convergence ----

    #[test]
    fn disconnected_edits_converge_after_exchanging_both_ways() {
        let (_root, [mut a, mut b]) = network::<2>();
        a.add("a-only", "from a");
        a.edit("github", "gh-token-a");
        a.delete("aws");
        b.clock.advance(Duration::seconds(5));
        b.add("b-only", "from b");
        b.edit("notes", "note-b");
        b.delete("wifi");

        exchange(&mut a, &mut b);

        assert_converged(&[&a, &b]);
        for machine in [&a, &b] {
            assert_eq!(machine.value("a-only").as_deref(), Some("from a"));
            assert_eq!(machine.value("b-only").as_deref(), Some("from b"));
            assert_eq!(machine.value("github").as_deref(), Some("gh-token-a"));
            assert_eq!(machine.value("notes").as_deref(), Some("note-b"));
            assert_eq!(machine.value("aws"), None);
            assert_eq!(machine.value("wifi"), None);
            assert_eq!(machine.vault.tombstones().unwrap().len(), 2);
        }
    }

    #[test]
    fn duplicate_deliveries_and_delivery_order_do_not_change_the_outcome() {
        let (_root, [mut a, mut b, mut x, mut y]) = network::<4>();
        a.edit("github", "gh-token-a");
        a.delete("notes");
        b.clock.advance(Duration::milliseconds(1));
        b.edit("github", "gh-token-b");
        b.edit("notes", "note-b");
        b.add("b-only", "from b");
        a.publish();
        b.publish();

        // X receives each file once, both at the same time.
        deliver(&a, &x);
        deliver(&b, &x);
        let report = x.merge();
        assert_eq!(report.files.len(), 2);
        assert!(!report.any_skipped());

        // Y receives B's file first, then A's file twice: under its own name and as a
        // transport conflict copy. B's file is still there and is read a second time.
        deliver(&b, &y);
        y.merge();
        let a_name = snapshot_file_name(a.device_id());
        let b_name = snapshot_file_name(b.device_id());
        let conflict = format!("{}.sync-conflict-20261117-090000-ABCDEFG.chsnap", a.device_id());
        deliver(&a, &y);
        deliver_as(&a, &y, &conflict);
        let report = y.merge();
        let names: Vec<&str> = report.merged().map(|(name, _)| name).collect();
        let mut expected = vec![a_name.as_str(), b_name.as_str(), conflict.as_str()];
        expected.sort_unstable();
        assert_eq!(names, expected);
        let conflict_counts = report.merged().find(|(name, _)| *name == conflict).unwrap().1;
        assert_eq!(
            conflict_counts.added + conflict_counts.replaced + conflict_counts.removed,
            0
        );

        assert_converged(&[&x, &y]);
        assert_eq!(x.value("github").as_deref(), Some("gh-token-b"));
        assert_eq!(x.value("notes"), None);
        assert_eq!(x.value("b-only").as_deref(), Some("from b"));

        // Merging everything again, in yet another state, changes nothing.
        let before = x.state();
        deliver_as(&a, &x, "zz-late-copy.chsnap");
        x.merge();
        assert_eq!(x.state(), before);
    }

    #[test]
    fn received_entries_keep_the_senders_revision_and_device_id() {
        let (_root, [mut a, mut b]) = network::<2>();
        a.clock.advance(Duration::seconds(1));
        a.add("fresh", "new on a");
        a.edit("github", "gh-token-a");
        a.publish();
        deliver(&a, &b);
        let report = b.merge();
        assert_eq!(report.merged().next().unwrap().1, counts(1, 1, 0, 3));

        for name in ["fresh", "github"] {
            let sent = a.item(name);
            let received = b.item(name);
            assert_eq!(received.uuid, sent.uuid);
            assert_eq!(received.revision, sent.revision);
            assert_eq!(received.revision.device_id, a.device_id());
            assert_ne!(received.revision.device_id, b.device_id());
            assert_eq!(received.value, sent.value);
        }
    }

    #[test]
    fn three_machines_converge_including_changes_relayed_through_a_third() {
        let (_root, [mut a, mut b, mut c]) = network::<3>();
        a.edit("github", "gh-token-a");
        b.add("b-only", "from b");
        c.delete("wifi");
        c.add("c-only", "from c");

        // Relay: A and C never exchange files directly; B carries each one's changes.
        a.publish();
        c.publish();
        deliver(&a, &b);
        deliver(&c, &b);
        b.merge();
        b.publish();
        deliver(&b, &a);
        deliver(&b, &c);
        a.merge();
        c.merge();

        assert!(!names_in(&a.sync).contains(&snapshot_file_name(c.device_id())));
        assert!(!names_in(&c.sync).contains(&snapshot_file_name(a.device_id())));
        assert_converged(&[&a, &b, &c]);
        assert_eq!(a.value("c-only").as_deref(), Some("from c"));
        assert_eq!(a.value("wifi"), None);
        assert_eq!(c.value("github").as_deref(), Some("gh-token-a"));

        // Full exchange, delivered in a different order on every machine.
        a.edit("notes", "note-a");
        b.clock.advance(Duration::seconds(1));
        b.edit("notes", "note-b");
        c.add("c-second", "again from c");
        a.publish();
        b.publish();
        c.publish();

        deliver(&c, &a);
        a.merge();
        deliver(&b, &a);
        a.merge();

        deliver(&a, &b);
        b.merge();
        deliver(&c, &b);
        b.merge();

        deliver(&b, &c);
        deliver(&a, &c);
        c.merge();

        assert_converged(&[&a, &b, &c]);
        assert_eq!(c.value("notes").as_deref(), Some("note-b"));
        assert_eq!(a.value("c-second").as_deref(), Some("again from c"));
    }

    #[test]
    fn concurrent_edits_in_the_same_millisecond_pick_the_same_winner_everywhere() {
        let (_root, [mut a, mut b]) = network::<2>();
        let instant = START + Duration::hours(1);
        a.clock.set(instant);
        b.clock.set(instant);
        a.edit("github", "edited on a");
        b.edit("github", "edited on b");
        assert_eq!(a.item("github").revision.wall_ms, b.item("github").revision.wall_ms);
        assert_eq!(a.item("github").revision.counter, b.item("github").revision.counter);

        exchange(&mut a, &mut b);

        // Equal (wall_ms, counter): the greater device ID wins.
        let expected = if a.device_id() > b.device_id() {
            "edited on a"
        } else {
            "edited on b"
        };
        assert_eq!(a.value("github").as_deref(), Some(expected));
        assert_eq!(b.value("github").as_deref(), Some(expected));
        assert_converged(&[&a, &b]);
    }

    #[test]
    fn a_later_edit_beats_an_edit_from_a_clock_far_in_the_future() {
        let (_root, [mut a, mut b]) = network::<2>();
        a.clock.set(datetime!(2199-01-01 00:00:00 UTC));
        a.edit("github", "from the future");
        exchange(&mut a, &mut b);
        assert_eq!(b.value("github").as_deref(), Some("from the future"));

        b.clock.advance(Duration::minutes(1));
        b.edit("github", "later, normal clock");
        assert!(b.item("github").revision > a.item("github").revision);
        exchange(&mut a, &mut b);

        assert_eq!(a.value("github").as_deref(), Some("later, normal clock"));
        assert_eq!(b.value("github").as_deref(), Some("later, normal clock"));
        assert_converged(&[&a, &b]);
    }

    #[test]
    fn a_delete_beats_a_later_edit_and_replaying_an_old_snapshot_does_not_revive_it() {
        let (root, [mut a, mut b]) = network::<2>();
        let deleted = a.item("aws").uuid;
        a.delete("aws");
        b.clock.advance(Duration::hours(1));
        b.edit("aws", "edited after the delete");

        // Keep B's snapshot that still holds the entry, as a stale copy would linger.
        b.publish();
        let stale = root.path().join("stale.chsnap");
        fs::copy(b.snapshot_path(), &stale).unwrap();

        exchange(&mut a, &mut b);
        for machine in [&a, &b] {
            assert_eq!(machine.value("aws"), None);
            assert!(machine.vault.tombstones().unwrap().contains(&deleted));
        }

        for machine in [&mut a, &mut b] {
            fs::copy(&stale, machine.sync.join("replayed.chsnap")).unwrap();
            machine.merge();
            assert_eq!(machine.value("aws"), None);
        }
        assert_converged(&[&a, &b]);
    }

    #[test]
    fn an_entry_recreated_after_deletion_survives_with_a_new_uuid() {
        let (_root, [mut a, mut b]) = network::<2>();
        let old = a.item("notes").uuid;
        a.delete("notes");
        a.add("notes", "recreated");
        let new = a.item("notes").uuid;
        assert_ne!(old, new);

        exchange(&mut a, &mut b);

        for machine in [&a, &b] {
            let item = machine.item("notes");
            assert_eq!(item.uuid, new);
            assert_eq!(item.value, "recreated");
            assert!(machine.vault.tombstones().unwrap().contains(&old));
        }
        assert_converged(&[&a, &b]);
    }

    #[test]
    fn entries_created_under_the_same_name_on_two_machines_are_both_kept() {
        let (_root, [mut a, mut b]) = network::<2>();
        a.add("shared-name", "from a");
        b.add("shared-name", "from b");

        exchange(&mut a, &mut b);

        for machine in [&a, &b] {
            let values: BTreeSet<String> = machine
                .vault
                .items_by_name("shared-name")
                .unwrap()
                .into_iter()
                .map(|item| item.value)
                .collect();
            assert_eq!(values, BTreeSet::from(["from a".to_owned(), "from b".to_owned()]));
        }
        assert_converged(&[&a, &b]);
    }

    #[test]
    fn a_machine_that_missed_every_intermediate_snapshot_catches_up_from_the_latest() {
        let (_root, [mut a, mut b]) = network::<2>();
        let wifi = a.item("wifi").uuid;
        a.add("round-1", "one");
        a.publish();
        a.clock.advance(Duration::seconds(1));
        a.edit("round-1", "one, edited");
        a.publish();
        a.delete("wifi");
        a.add("round-3", "three");
        a.publish();
        assert_eq!(names_in(&a.sync), [snapshot_file_name(a.device_id())]);

        deliver(&a, &b);
        b.merge();

        assert_converged(&[&a, &b]);
        assert_eq!(b.value("wifi"), None);
        assert!(b.vault.tombstones().unwrap().contains(&wifi));
        assert_eq!(b.value("round-1").as_deref(), Some("one, edited"));
    }

    // ---- Files and directory ----

    #[test]
    fn publishing_creates_a_missing_nested_directory_and_keeps_one_file() {
        let (root, [mut a]) = network::<1>();
        a.sync = root.path().join("deep").join("nested").join("sync");
        a.delete("wifi");

        let report = a.publish();
        let name = snapshot_file_name(a.device_id());
        assert_eq!(report.path, a.sync.join(&name));
        assert_eq!(report.entries, 3);
        assert_eq!(report.tombstones, 1);
        assert_eq!(names_in(&a.sync), std::slice::from_ref(&name));

        // The name is the lowercase hyphenated device ID.
        assert_eq!(name, format!("{}.chsnap", a.device_id().hyphenated()));
        assert_eq!(name, name.to_lowercase());
        assert_eq!(name.len(), 36 + ".chsnap".len());

        let mut ids = BTreeSet::from([report.snapshot_id]);
        for _ in 0..3 {
            ids.insert(a.publish().snapshot_id);
            assert_eq!(names_in(&a.sync), std::slice::from_ref(&name));
        }
        assert_eq!(ids.len(), 4, "every publication has a fresh snapshot ID");
    }

    #[test]
    fn a_snapshot_copied_under_another_machines_name_merges_identically() {
        let (_root, [mut a, mut b, mut c]) = network::<3>();
        a.add("from-a", "value");
        a.publish();
        let wrong_name = snapshot_file_name(c.device_id());
        deliver_as(&a, &b, &wrong_name);
        deliver(&a, &c);

        let report_b = b.merge();
        let report_c = c.merge();
        let (name, counts_b) = report_b.merged().next().unwrap();
        assert_eq!(name, wrong_name);
        assert_eq!(counts_b, report_c.merged().next().unwrap().1);
        assert_eq!(b.item("from-a").revision.device_id, a.device_id());
        assert_converged(&[&a, &b, &c]);
    }

    #[test]
    fn merging_a_machines_own_file_changes_nothing() {
        let (_root, [mut a]) = network::<1>();
        a.delete("wifi");
        a.publish();
        let before = a.state();
        let hwm = a.vault.high_water_mark().unwrap();

        let report = a.merge();

        assert_eq!(report.files.len(), 1);
        assert_eq!(
            report.merged().next().unwrap(),
            (snapshot_file_name(a.device_id()).as_str(), counts(0, 0, 0, 3))
        );
        assert_eq!(a.state(), before);
        assert_eq!(a.vault.high_water_mark().unwrap(), hwm);
    }

    #[test]
    fn a_missing_or_empty_directory_gives_an_empty_report() {
        let (_root, [mut a]) = network::<1>();
        assert!(!a.sync.exists());
        let report = a.merge();
        assert!(report.is_empty());
        assert!(!report.any_skipped());
        assert!(!a.sync.exists(), "merging must not create the directory");

        fs::create_dir(&a.sync).unwrap();
        let report = a.merge();
        assert!(report.is_empty());
        assert!(names_in(&a.sync).is_empty());
    }

    #[test]
    fn files_that_are_not_candidates_are_ignored() {
        let (root, [mut a, mut b]) = network::<2>();
        a.add("only-in-a", "value");
        a.publish();
        let bytes = fs::read(a.snapshot_path()).unwrap();
        let a_name = snapshot_file_name(a.device_id());

        fs::create_dir_all(b.sync.join("sub")).unwrap();
        fs::create_dir_all(b.sync.join("folder.chsnap")).unwrap();
        for name in [
            "readme.txt".to_owned(),
            format!("{a_name}.bak"),
            ".hidden.chsnap".to_owned(),
            format!(".{a_name}.tmp"),
            format!("{a_name}.tmp"),
            format!("sub/{a_name}"),
            format!("folder.chsnap/{a_name}"),
        ] {
            fs::write(b.sync.join(name), &bytes).unwrap();
        }
        a.vault
            .write_enrollment_package(&b.sync.join(format!("pkg.{ENROLLMENT_EXTENSION}")))
            .unwrap();
        #[cfg(unix)]
        {
            let outside = root.path().join("outside.chsnap");
            fs::write(&outside, &bytes).unwrap();
            std::os::unix::fs::symlink(&outside, b.sync.join("link.chsnap")).unwrap();
            std::os::unix::fs::symlink(b.sync.join("sub"), b.sync.join("dirlink.chsnap")).unwrap();
        }
        #[cfg(not(unix))]
        let _ = &root;
        let before = b.state();
        let listing = tree(&b.sync);

        let report = b.merge();

        assert!(report.is_empty(), "unexpected candidates: {report:?}");
        assert_eq!(b.state(), before);
        assert_eq!(b.value("only-in-a"), None);
        assert_eq!(tree(&b.sync), listing, "merging must not touch the directory");
    }

    #[test]
    fn an_enrollment_package_renamed_to_chsnap_is_skipped() {
        let (root, [mut a, mut b]) = network::<2>();
        a.add("only-in-package", "value");
        let package = root.path().join(format!("pkg.{ENROLLMENT_EXTENSION}"));
        a.vault.write_enrollment_package(&package).unwrap();
        fs::create_dir_all(&b.sync).unwrap();
        fs::copy(&package, b.sync.join("pkg.chsnap")).unwrap();
        let before = b.state();

        let report = b.merge();

        assert!(report.any_skipped());
        let skipped: Vec<_> = report.skipped().collect();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "pkg.chsnap");
        assert!(matches!(
            skipped[0].1,
            SnapshotRejection::WrongPackageType { package_type } if *package_type == PACKAGE_TYPE_ENROLLMENT
        ));
        assert!(skipped[0].1.to_string().contains("enrollment package"));
        assert_eq!(b.state(), before);
        assert_eq!(b.value("only-in-package"), None);
    }

    #[test]
    fn a_sync_directory_containing_the_database_is_refused() {
        let (root, [mut a, b]) = network::<2>();
        b.publish();
        let vault_dir = root.path().join("vault-0");
        fs::create_dir_all(root.path().join("sync-0")).unwrap();
        let mut refused = vec![
            // Directly.
            vault_dir.clone(),
            // In a subdirectory.
            root.path().to_path_buf(),
            // Through `..`.
            root.path().join("sync-0").join("..").join("vault-0"),
        ];
        #[cfg(unix)]
        {
            let link = root.path().join("link-to-vault");
            std::os::unix::fs::symlink(&vault_dir, &link).unwrap();
            refused.push(link);
        }

        for sync in refused {
            // A valid file from another machine sits in the directory, and still is not merged.
            let planted = sync.join("planted.chsnap");
            fs::copy(b.snapshot_path(), &planted).unwrap();
            let listing = tree(root.path());
            let state = a.state();

            let err = a.vault.publish_snapshot(&sync).unwrap_err();
            assert!(
                matches!(sync_dir_error(&err), SyncDirError::ContainsDatabase { .. }),
                "{}: {err:#}",
                sync.display()
            );
            let err = a.vault.merge_snapshots(&sync).unwrap_err();
            assert!(
                matches!(sync_dir_error(&err), SyncDirError::ContainsDatabase { .. }),
                "{}: {err:#}",
                sync.display()
            );

            assert_eq!(tree(root.path()), listing, "nothing may be written");
            assert_eq!(a.state(), state);
            fs::remove_file(planted).unwrap();
        }
        assert!(
            !root
                .path()
                .join("vault-0")
                .join(snapshot_file_name(a.device_id()))
                .exists()
        );
    }

    #[test]
    fn a_path_that_is_not_a_directory_is_an_error() {
        let (root, [mut a]) = network::<1>();
        let file = root.path().join("plain-file");
        fs::write(&file, b"not a directory").unwrap();
        for err in [
            a.vault.publish_snapshot(&file).unwrap_err(),
            a.vault.merge_snapshots(&file).unwrap_err(),
        ] {
            assert!(
                matches!(sync_dir_error(&err), SyncDirError::NotADirectory { .. }),
                "{err:#}"
            );
        }
        assert_eq!(fs::read(&file).unwrap(), b"not a directory");
    }

    #[test]
    fn both_operations_refuse_a_locked_vault_and_write_nothing() {
        let (_root, [mut a, b]) = network::<2>();
        a.vault.lock();
        let err = a.vault.publish_snapshot(&a.sync).unwrap_err();
        assert_eq!(err.to_string(), "Locked");
        assert!(!a.sync.exists());

        b.publish();
        deliver(&b, &a);
        let listing = tree(&a.sync);
        let err = a.vault.merge_snapshots(&a.sync).unwrap_err();
        assert_eq!(err.to_string(), "Locked");
        assert_eq!(tree(&a.sync), listing);

        a.vault.unlock(PASSWORD).unwrap();
        assert_eq!(a.state(), b.state());
    }

    // ---- Rejections ----

    /// A bad file placed next to a valid one, and the rejection it must get.
    #[derive(Debug, Clone, Copy)]
    enum Damage {
        ForeignVault,
        RandomBytes,
        FlippedBit,
        Truncated,
        TruncatedBelowHeader,
        Oversized,
        FormatVersion2,
    }

    /// Deterministic bytes that do not start with the snapshot signature.
    fn noise(len: usize) -> Vec<u8> {
        let mut state: u32 = 0x9e37_79b9;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_be_bytes()[0]
            })
            .collect()
    }

    /// Writes the damaged file at `path`. `source` is a valid snapshot holding an entry the
    /// receiver must never see.
    fn write_damaged(damage: Damage, path: &Path, source: &[u8], root: &Path) {
        match damage {
            Damage::ForeignVault => {
                let (mut unrelated, _clock) = clocked_vault(&root.join("unrelated").join("vault.sqlite3"));
                unrelated.initialize("unrelated-master").unwrap();
                unrelated.unlock("unrelated-master").unwrap();
                unrelated
                    .create_item(&NewItem {
                        name: "only-in-damaged".into(),
                        kind: ItemKind::Password,
                        value: "foreign".into(),
                    })
                    .unwrap();
                let report = unrelated.publish_snapshot(&root.join("unrelated-sync")).unwrap();
                fs::copy(report.path, path).unwrap();
            }
            Damage::RandomBytes => fs::write(path, noise(4096)).unwrap(),
            Damage::FlippedBit => {
                let mut bytes = source.to_vec();
                let middle = bytes.len() / 2;
                bytes[middle] ^= 0x01;
                fs::write(path, bytes).unwrap();
            }
            Damage::Truncated => fs::write(path, &source[..source.len() / 2]).unwrap(),
            Damage::TruncatedBelowHeader => fs::write(path, &source[..40]).unwrap(),
            Damage::Oversized => {
                let file = fs::File::create(path).unwrap();
                file.set_len(MAX_FILE_LEN + 1).unwrap();
            }
            Damage::FormatVersion2 => {
                let mut bytes = source.to_vec();
                bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
                fs::write(path, bytes).unwrap();
            }
        }
    }

    fn assert_rejection(damage: Damage, rejection: &SnapshotRejection) {
        let expected = match damage {
            Damage::ForeignVault => matches!(rejection, SnapshotRejection::ForeignVault),
            Damage::RandomBytes => matches!(rejection, SnapshotRejection::BadMagic),
            Damage::FlippedBit | Damage::Truncated => matches!(rejection, SnapshotRejection::AuthenticationFailed),
            Damage::TruncatedBelowHeader => matches!(rejection, SnapshotRejection::TooSmall { len: 40 }),
            Damage::Oversized => {
                matches!(rejection, SnapshotRejection::TooLarge { len } if *len == MAX_FILE_LEN + 1)
            }
            Damage::FormatVersion2 => {
                matches!(rejection, SnapshotRejection::UnsupportedVersion { version: 2 })
                    && rejection.to_string().contains("Update Chamber")
            }
        };
        assert!(expected, "{damage:?} was rejected as {rejection:?}");
    }

    #[test]
    fn damaged_and_foreign_files_are_skipped_and_valid_files_still_merge() {
        assert_eq!(FORMAT_VERSION, 1);
        for damage in [
            Damage::ForeignVault,
            Damage::RandomBytes,
            Damage::FlippedBit,
            Damage::Truncated,
            Damage::TruncatedBelowHeader,
            Damage::Oversized,
            Damage::FormatVersion2,
        ] {
            let (root, [mut a, mut r]) = network::<2>();
            a.add("valid-from-a", "value");
            a.publish();
            deliver(&a, &r);
            let expected_state = a.state();

            // The damaged file starts from a later snapshot holding an entry R must never see.
            a.add("only-in-damaged", "secret");
            a.publish();
            let source = fs::read(a.snapshot_path()).unwrap();
            write_damaged(damage, &r.sync.join("damaged.chsnap"), &source, root.path());

            let report = r.merge();

            assert!(report.any_skipped(), "{damage:?}");
            assert_eq!(report.files.len(), 2, "{damage:?}");
            let merged: Vec<_> = report.merged().collect();
            assert_eq!(
                merged,
                [(snapshot_file_name(a.device_id()).as_str(), counts(1, 0, 0, 4))],
                "{damage:?}"
            );
            let skipped: Vec<_> = report.skipped().collect();
            assert_eq!(skipped.len(), 1);
            assert_eq!(skipped[0].0, "damaged.chsnap");
            assert_rejection(damage, skipped[0].1);
            assert!(!skipped[0].1.to_string().contains("only-in-damaged"));

            assert_eq!(r.state(), expected_state, "{damage:?}");
            assert_eq!(r.value("only-in-damaged"), None);
            assert_eq!(r.value("valid-from-a").as_deref(), Some("value"));
        }
    }

    #[test]
    fn a_local_database_failure_rolls_back_that_file_and_keeps_earlier_ones() {
        let (_root, [mut a, mut b, mut r]) = network::<3>();
        a.add("from-first", "first");
        a.publish();
        deliver_as(&a, &r, "1-first.chsnap");
        b.clock.advance(Duration::seconds(1));
        b.edit("github", "edited on b");
        b.add("poison", "refused");
        b.publish();
        deliver_as(&b, &r, "2-second.chsnap");

        let raw = rusqlite::Connection::open(r.vault.db_path()).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER poison BEFORE INSERT ON items WHEN NEW.name = 'poison' \
             BEGIN SELECT RAISE(ABORT, 'insert refused by test'); END;",
        )
        .unwrap();

        let err = r.vault.merge_snapshots(&r.sync).unwrap_err();
        assert!(err.to_string().contains("2-second.chsnap"), "{err:#}");
        assert_eq!(r.value("from-first").as_deref(), Some("first"));
        assert_eq!(r.value("poison"), None);
        assert_eq!(r.value("github").as_deref(), Some("gh-token-1"));

        raw.execute_batch("DROP TRIGGER poison;").unwrap();
        let report = r.merge();
        assert!(!report.any_skipped());
        assert_eq!(r.value("poison").as_deref(), Some("refused"));
        assert_eq!(r.value("github").as_deref(), Some("edited on b"));
    }

    // ---- Publication safety ----

    #[test]
    fn an_interrupted_publication_leaves_the_previous_snapshot_intact() {
        let (_root, [mut a, mut b]) = network::<2>();
        a.publish();
        let earlier = fs::read(a.snapshot_path()).unwrap();
        let temp = a.sync.join(temp_file_name(a.device_id()));

        a.add("after-interruption", "late");
        let prepared = a.vault.prepare_publication(&a.sync).unwrap();
        drop(prepared);

        assert!(temp.exists());
        assert_eq!(fs::read(a.snapshot_path()).unwrap(), earlier);

        // The earlier snapshot still merges elsewhere, and the temporary file is never read,
        // not even when a transport copies it along.
        deliver(&a, &b);
        fs::copy(&temp, b.sync.join(temp_file_name(a.device_id()))).unwrap();
        let report = b.merge();
        assert_eq!(report.files.len(), 1);
        assert!(!report.any_skipped());
        assert_eq!(b.value("after-interruption"), None);
        let report = a.merge();
        let names: Vec<&str> = report.merged().map(|(name, _)| name).collect();
        assert_eq!(names, [snapshot_file_name(a.device_id())]);

        // A second interrupted attempt replaces the leftover temporary file.
        a.vault.prepare_publication(&a.sync).unwrap();
        assert_eq!(names_in(&a.sync).len(), 2);

        a.publish();
        assert!(!temp.exists());
        assert_eq!(names_in(&a.sync), [snapshot_file_name(a.device_id())]);
        deliver(&a, &b);
        b.merge();
        assert_eq!(b.value("after-interruption").as_deref(), Some("late"));
    }

    #[test]
    fn published_files_hold_no_names_or_values_in_the_clear() {
        let (_root, [mut a]) = network::<1>();
        let published = [("Pelican-Marmalade-8812", "correct-horse-battery-9931")];
        let interrupted = [("Narwhal-Teacup-5520", "zircon-lantern-7741")];
        for (name, value) in published {
            a.add(name, value);
        }
        a.publish();
        for (name, value) in interrupted {
            a.add(name, value);
        }
        a.vault.prepare_publication(&a.sync).unwrap();
        assert!(a.sync.join(temp_file_name(a.device_id())).exists());

        let files = names_in(&a.sync);
        assert_eq!(files.len(), 2);
        for file in files {
            let bytes = fs::read(a.sync.join(&file)).unwrap();
            for (name, value) in published.iter().chain(&interrupted).chain(&BASE) {
                assert!(!contains(&bytes, name.as_bytes()), "{file} holds the name {name}");
                assert!(!contains(&bytes, value.as_bytes()), "{file} holds the value of {name}");
            }
        }
    }

    // ---- Resolution ----

    #[test]
    fn resolution_prefers_explicit_then_environment_then_default() {
        let explicit = Path::new("/explicit/sync");
        let env = OsStr::new("/from/env");
        let default = default_sync_dir().unwrap();

        assert_eq!(resolve_sync_dir(Some(explicit), Some(env)).unwrap(), explicit);
        assert_eq!(resolve_sync_dir(Some(explicit), None).unwrap(), explicit);
        assert_eq!(resolve_sync_dir(None, Some(env)).unwrap(), Path::new("/from/env"));
        assert_eq!(resolve_sync_dir(None, Some(OsStr::new(""))).unwrap(), default);
        assert_eq!(resolve_sync_dir(None, None).unwrap(), default);
        assert_eq!(
            resolve_sync_dir(Some(explicit), Some(OsStr::new(""))).unwrap(),
            explicit
        );
    }

    #[test]
    fn the_default_sync_directory_is_chamber_sync_under_the_data_directory() {
        let existed = default_sync_dir().unwrap().exists();
        let default = default_sync_dir().unwrap();
        assert!(
            default.ends_with(Path::new("chamber").join("sync")),
            "{}",
            default.display()
        );
        assert_eq!(default, dirs::data_dir().unwrap().join("chamber").join("sync"));
        assert_eq!(default.exists(), existed, "computing the default creates nothing");
    }

    #[test]
    fn candidate_names_end_in_chsnap_and_do_not_start_with_a_dot() {
        for name in ["a.chsnap", "x.sync-conflict-1.chsnap", "chsnap.chsnap"] {
            assert!(is_candidate_name(OsStr::new(name)), "{name}");
        }
        for name in [
            ".a.chsnap",
            ".chsnap",
            "a.chsnap.tmp",
            "a.chsnapx",
            "a.chenroll",
            "chsnap",
            "a.CHSNAP",
        ] {
            assert!(!is_candidate_name(OsStr::new(name)), "{name}");
        }
        let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        assert_eq!(snapshot_file_name(id), "01234567-89ab-cdef-0123-456789abcdef.chsnap");
        assert_eq!(temp_file_name(id), ".01234567-89ab-cdef-0123-456789abcdef.chsnap.tmp");
    }
}
