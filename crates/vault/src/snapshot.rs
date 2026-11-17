//! Snapshot files: a vault's synchronization state as one encrypted file.
//!
//! A snapshot is a fixed 83-byte binary header followed by the encrypted payload and its 16-byte
//! authentication tag:
//!
//! ```text
//! header:  magic "CHMBSNAP" (8) | format version (u16, big-endian) | package type (u8)
//!          | vault UUID (16) | publisher device ID (16) | snapshot ID (16) | nonce (24)
//! key:     HKDF-SHA-256(ikm = vault key, salt = vault UUID, info = "chamber/snapshot/v1"), 32 bytes
//! cipher:  XChaCha20-Poly1305 over the payload, with the whole header as associated data
//! payload: JSON, UTF-8
//! ```
//!
//! Only the magic and the format version have a guaranteed position; a reader checks them first
//! and interprets nothing after them until it knows it supports the version. The payload carries
//! every entry exactly as stored (still encrypted) and every tombstone. Encoding never decrypts a
//! secret value, and decoding never decrypts or re-encrypts one.
//!
//! [`decode_snapshot`] validates a file completely before returning anything: any failed check
//! rejects the whole file with a [`SnapshotRejection`] naming the first rule it broke.
//!
//! The pieces that do not depend on the snapshot header layout or key input (the size bounds
//! check, the magic and version check, sealing and opening with the header as associated data,
//! and payload validation) are kept separate so that other package types built on this format can
//! share them.

use crate::ItemKind;
use crate::crypto::{KeyMaterial, hkdf_sha256};
use crate::merge::{SyncEntry, SyncState};
use crate::revision::Revision;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use color_eyre::Result;
use color_eyre::eyre::eyre;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

/// The first eight bytes of every snapshot file.
pub const MAGIC: [u8; 8] = *b"CHMBSNAP";

/// The only format version this binary writes or reads.
pub const FORMAT_VERSION: u16 = 1;

/// The only payload schema number this binary writes or reads.
pub const PAYLOAD_SCHEMA: u64 = 1;

/// The package type of a snapshot, which carries a vault's synchronization state to be merged.
pub const PACKAGE_TYPE_SNAPSHOT: u8 = 1;

/// The package type of an enrollment package, which shares this file format but is used only to
/// join a device to a vault and is never merged. Snapshot decoding recognizes and rejects it.
pub const PACKAGE_TYPE_ENROLLMENT: u8 = 2;

/// The length of a snapshot header in bytes.
pub const HEADER_LEN: usize = MAGIC.len() + 2 + 1 + 16 + 16 + 16 + NONCE_LEN;

/// The length of the XChaCha20-Poly1305 authentication tag that ends every file.
pub const TAG_LEN: usize = 16;

/// The length of the XChaCha20-Poly1305 nonce in the header.
pub const NONCE_LEN: usize = 24;

/// The largest file accepted, in bytes: 64 MiB.
///
/// This is a heuristic, not a derived value. The vault was about 20 KB when it was chosen, so the
/// cap leaves several thousand times that for growth while keeping a stray or hostile file from
/// being read into memory whole.
pub const MAX_FILE_LEN: u64 = 64 * 1024 * 1024;

/// The HKDF `info` input of the snapshot key.
pub const SNAPSHOT_KEY_INFO: &[u8] = b"chamber/snapshot/v1";

/// The length of the item nonce every entry carries (the nonce of its stored ciphertext).
const ITEM_NONCE_LEN: usize = 24;

// Header field offsets. Only the magic and the version are guaranteed for every version.
const VERSION_OFFSET: usize = MAGIC.len();
const PACKAGE_TYPE_OFFSET: usize = VERSION_OFFSET + 2;
const VAULT_UUID_OFFSET: usize = PACKAGE_TYPE_OFFSET + 1;
const DEVICE_ID_OFFSET: usize = VAULT_UUID_OFFSET + 16;
const SNAPSHOT_ID_OFFSET: usize = DEVICE_ID_OFFSET + 16;
const NONCE_OFFSET: usize = SNAPSHOT_ID_OFFSET + 16;

/// Derives the snapshot key from the vault key and the vault UUID:
/// HKDF-SHA-256 with the vault key as input keying material, the vault UUID's 16 bytes as salt,
/// and [`SNAPSHOT_KEY_INFO`] as info, producing 32 bytes.
///
/// # Panics
/// Never in practice: HMAC-SHA-256 accepts keys of any length and 32 bytes is far below the HKDF
/// output limit, so the derivation cannot fail.
#[must_use]
pub fn derive_snapshot_key(vault_key: &KeyMaterial, vault_uuid: Uuid) -> KeyMaterial {
    let mut key = KeyMaterial([0u8; 32]);
    hkdf_sha256(vault_uuid.as_bytes(), &vault_key.0, SNAPSHOT_KEY_INFO, &mut key.0)
        .expect("a 32-byte HKDF-SHA-256 output is within the output limit");
    key
}

/// The result of [`encode_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSnapshot {
    /// The complete file image: header, encrypted payload, and tag.
    pub bytes: Vec<u8>,
    /// The fresh random snapshot ID written into the header.
    pub snapshot_id: Uuid,
}

/// A snapshot file that passed every check, as returned by [`decode_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSnapshot {
    /// The device that published the snapshot, from the authenticated header.
    pub publisher_device_id: Uuid,
    /// The snapshot's ID, from the authenticated header.
    pub snapshot_id: Uuid,
    /// The synchronization state the snapshot carries.
    pub state: SyncState,
}

/// Encodes `state` as a complete snapshot file image.
///
/// The snapshot ID and the nonce are fresh random bytes for every call, so two encodings of the
/// same state differ. Item nonces and ciphertexts are copied as stored; nothing is decrypted.
///
/// # Errors
/// Returns an error when the system random number generator fails, when a timestamp cannot be
/// written as RFC 3339 (a year outside 0 to 9999), when the file would be larger than
/// [`MAX_FILE_LEN`] (readers would reject it), or when encryption fails.
pub fn encode_snapshot(
    snapshot_key: &KeyMaterial,
    vault_uuid: Uuid,
    publisher_device_id: Uuid,
    state: &SyncState,
) -> Result<EncodedSnapshot> {
    let payload = serde_json::to_vec(&PayloadJson::from_state(state)?)?;
    let file_len = HEADER_LEN + payload.len() + TAG_LEN;
    if u64::try_from(file_len).unwrap_or(u64::MAX) > MAX_FILE_LEN {
        return Err(eyre!(
            "The snapshot would be {file_len} bytes, larger than the {MAX_FILE_LEN}-byte limit readers accept"
        ));
    }

    let mut snapshot_id = [0u8; 16];
    getrandom::fill(&mut snapshot_id)?;
    let snapshot_id = Uuid::from_bytes(snapshot_id);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)?;

    let header = snapshot_header(vault_uuid, publisher_device_id, snapshot_id, &nonce);
    let bytes = seal_file(snapshot_key, &header, &nonce, &payload)?;
    Ok(EncodedSnapshot { bytes, snapshot_id })
}

/// Decodes and validates a snapshot file image.
///
/// The checks run in the order of the [`SnapshotRejection`] cases: size, magic, format version,
/// package type, and vault UUID before decryption; authentication; then payload shape and
/// content. Nothing from a rejected file is returned.
///
/// # Errors
/// Returns the [`SnapshotRejection`] for the first check the file fails.
pub fn decode_snapshot(
    bytes: &[u8],
    local_vault_uuid: Uuid,
    snapshot_key: &KeyMaterial,
) -> Result<DecodedSnapshot, SnapshotRejection> {
    check_size_bounds(u64::try_from(bytes.len()).unwrap_or(u64::MAX), HEADER_LEN)?;
    check_magic_and_version(bytes)?;

    let package_type = bytes[PACKAGE_TYPE_OFFSET];
    if package_type != PACKAGE_TYPE_SNAPSHOT {
        return Err(SnapshotRejection::WrongPackageType { package_type });
    }
    if uuid_at(bytes, VAULT_UUID_OFFSET) != local_vault_uuid {
        return Err(SnapshotRejection::ForeignVault);
    }

    let (header, sealed) = bytes.split_at(HEADER_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&header[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]);
    let plaintext = open(snapshot_key, header, &nonce, sealed)?;

    // serde_json error text can quote the input, so none of it reaches the rejection.
    let payload: PayloadJson = serde_json::from_slice(&plaintext).map_err(|_| SnapshotRejection::InvalidPayload)?;
    let state = validate_payload(payload.schema, payload.entries, payload.tombstones)?;

    Ok(DecodedSnapshot {
        publisher_device_id: uuid_at(header, DEVICE_ID_OFFSET),
        snapshot_id: uuid_at(header, SNAPSHOT_ID_OFFSET),
        state,
    })
}

/// Reads and decodes the snapshot file at `path`.
///
/// The file's size is checked from its metadata before anything is read, so an oversized file is
/// never loaded. The read itself stops one byte past [`MAX_FILE_LEN`], so a file that grew after
/// the size check is still rejected by size instead of being read whole.
///
/// # Errors
/// Returns [`SnapshotRejection::Unreadable`] when the file cannot be opened or read, and
/// otherwise the rejection [`decode_snapshot`] gives.
pub fn read_snapshot_file(
    path: &Path,
    local_vault_uuid: Uuid,
    snapshot_key: &KeyMaterial,
) -> Result<DecodedSnapshot, SnapshotRejection> {
    let file = File::open(path).map_err(SnapshotRejection::Unreadable)?;
    let len = file.metadata().map_err(SnapshotRejection::Unreadable)?.len();
    check_size_bounds(len, HEADER_LEN)?;
    let bytes = read_bounded(file, len).map_err(SnapshotRejection::Unreadable)?;
    decode_snapshot(&bytes, local_vault_uuid, snapshot_key)
}

/// Reads `reader` to its end, but never more than [`MAX_FILE_LEN`] plus one byte, which is enough
/// for the size check that follows to see that the input is too large. `expected_len` is the size
/// the caller already checked, used only to size the buffer.
fn read_bounded(reader: impl Read, expected_len: u64) -> io::Result<Vec<u8>> {
    let capacity = usize::try_from(expected_len.min(MAX_FILE_LEN)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    reader.take(MAX_FILE_LEN + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Rule 1: a file of `len` bytes must be no larger than [`MAX_FILE_LEN`] and at least
/// `header_len` plus [`TAG_LEN`] bytes.
///
/// # Errors
/// Returns [`SnapshotRejection::TooLarge`] or [`SnapshotRejection::TooSmall`].
pub(crate) const fn check_size_bounds(len: u64, header_len: usize) -> Result<(), SnapshotRejection> {
    if len > MAX_FILE_LEN {
        return Err(SnapshotRejection::TooLarge { len });
    }
    if len < (header_len + TAG_LEN) as u64 {
        return Err(SnapshotRejection::TooSmall { len });
    }
    Ok(())
}

/// Rules 2 and 3: the file starts with [`MAGIC`] followed by [`FORMAT_VERSION`]. Nothing after
/// the version is looked at.
///
/// # Errors
/// Returns [`SnapshotRejection::BadMagic`] or [`SnapshotRejection::UnsupportedVersion`]. A file
/// too short to hold the magic and version is [`SnapshotRejection::TooSmall`], although the size
/// check normally rules that out first.
pub(crate) fn check_magic_and_version(bytes: &[u8]) -> Result<(), SnapshotRejection> {
    let too_small = || SnapshotRejection::TooSmall {
        len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    };
    let magic = bytes.get(..MAGIC.len()).ok_or_else(too_small)?;
    if magic != MAGIC {
        return Err(SnapshotRejection::BadMagic);
    }
    let version = bytes.get(VERSION_OFFSET..VERSION_OFFSET + 2).ok_or_else(too_small)?;
    let version = u16::from_be_bytes([version[0], version[1]]);
    if version != FORMAT_VERSION {
        return Err(SnapshotRejection::UnsupportedVersion { version });
    }
    Ok(())
}

/// Builds a snapshot header.
fn snapshot_header(
    vault_uuid: Uuid,
    publisher_device_id: Uuid,
    snapshot_id: Uuid,
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..VERSION_OFFSET].copy_from_slice(&MAGIC);
    header[VERSION_OFFSET..PACKAGE_TYPE_OFFSET].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    header[PACKAGE_TYPE_OFFSET] = PACKAGE_TYPE_SNAPSHOT;
    header[VAULT_UUID_OFFSET..DEVICE_ID_OFFSET].copy_from_slice(vault_uuid.as_bytes());
    header[DEVICE_ID_OFFSET..SNAPSHOT_ID_OFFSET].copy_from_slice(publisher_device_id.as_bytes());
    header[SNAPSHOT_ID_OFFSET..NONCE_OFFSET].copy_from_slice(snapshot_id.as_bytes());
    header[NONCE_OFFSET..].copy_from_slice(nonce);
    header
}

/// The UUID stored in the 16 bytes at `offset`. The caller has checked the length.
fn uuid_at(bytes: &[u8], offset: usize) -> Uuid {
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[offset..offset + 16]);
    Uuid::from_bytes(uuid)
}

/// Encrypts `payload` with `header` as associated data and returns the whole file: the header
/// followed by the ciphertext and tag. `nonce` is the nonce the header carries.
fn seal_file(key: &KeyMaterial, header: &[u8], nonce: &[u8; NONCE_LEN], payload: &[u8]) -> Result<Vec<u8>> {
    let sealed = seal(key, header, nonce, payload)?;
    let mut bytes = Vec::with_capacity(header.len() + sealed.len());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&sealed);
    Ok(bytes)
}

/// Encrypts `payload` with XChaCha20-Poly1305 under `key` and `nonce`, authenticating `header` as
/// associated data. Returns the ciphertext followed by the tag.
///
/// # Errors
/// Returns an error when encryption fails (a payload too long for the cipher).
pub(crate) fn seal(key: &KeyMaterial, header: &[u8], nonce: &[u8; NONCE_LEN], payload: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new((&key.0).into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: payload,
                aad: header,
            },
        )
        .map_err(|_| eyre!("Snapshot encryption failed"))
}

/// Rule 6: decrypts `sealed` (ciphertext followed by tag) under `key` and `nonce`, authenticating
/// `header` as associated data.
///
/// # Errors
/// Returns [`SnapshotRejection::AuthenticationFailed`] when authentication fails.
pub(crate) fn open(
    key: &KeyMaterial,
    header: &[u8],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
) -> Result<Vec<u8>, SnapshotRejection> {
    XChaCha20Poly1305::new((&key.0).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: header,
            },
        )
        .map_err(|_| SnapshotRejection::AuthenticationFailed)
}

/// The JSON payload of a snapshot.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadJson {
    schema: u64,
    entries: Vec<EntryJson>,
    tombstones: Vec<String>,
}

/// One entry in a payload. Identifier, binary, and timestamp fields are plain strings here and are
/// converted by [`validate_payload`], which keeps shape errors (rule 7) apart from malformed
/// values (rule 8).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntryJson {
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) nonce: String,
    pub(crate) ciphertext: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) revision: RevisionJson,
}

/// An entry's revision in a payload.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevisionJson {
    pub(crate) wall_ms: u64,
    pub(crate) counter: u32,
    pub(crate) device_id: String,
}

impl PayloadJson {
    fn from_state(state: &SyncState) -> Result<Self> {
        let entries = state.entries.iter().map(EntryJson::from_entry).collect::<Result<_>>()?;
        Ok(Self {
            schema: PAYLOAD_SCHEMA,
            entries,
            tombstones: state.tombstones.iter().map(ToString::to_string).collect(),
        })
    }
}

impl EntryJson {
    fn from_entry(entry: &SyncEntry) -> Result<Self> {
        Ok(Self {
            uuid: entry.uuid.to_string(),
            name: entry.name.clone(),
            kind: entry.kind.clone(),
            nonce: BASE64.encode(&entry.nonce),
            ciphertext: BASE64.encode(&entry.ciphertext),
            created_at: format_timestamp(entry.created_at)?,
            updated_at: format_timestamp(entry.updated_at)?,
            revision: RevisionJson {
                wall_ms: entry.revision.wall_ms,
                counter: entry.revision.counter,
                device_id: entry.revision.device_id.to_string(),
            },
        })
    }
}

/// RFC 3339 in UTC, which `time` writes with a `Z` suffix and as many fractional digits as needed.
fn format_timestamp(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| eyre!("An entry timestamp cannot be written as RFC 3339"))
}

/// Rules 7 (schema number) to 13: validates a parsed payload and converts it to a [`SyncState`].
///
/// Each rule is checked across the whole payload before the next, so a payload that breaks
/// several rules reports the lowest-numbered one, whichever entry it occurs in. Entry order is
/// kept. The tombstone list is a set: repeats are dropped, keeping the first occurrence.
///
/// # Errors
/// Returns the [`SnapshotRejection`] for the lowest-numbered rule the payload breaks.
pub(crate) fn validate_payload(
    schema: u64,
    entries: Vec<EntryJson>,
    tombstones: Vec<String>,
) -> Result<SyncState, SnapshotRejection> {
    // Rule 7: the schema number.
    if schema != PAYLOAD_SCHEMA {
        return Err(SnapshotRejection::InvalidPayload);
    }

    // Rule 8: identifiers, base64, and timestamps.
    let entries = entries.into_iter().map(convert_entry).collect::<Result<Vec<_>, _>>()?;
    let mut seen_tombstones = HashSet::with_capacity(tombstones.len());
    let mut unique_tombstones = Vec::with_capacity(tombstones.len());
    for tombstone in tombstones {
        let uuid = parse_canonical_uuid(&tombstone, PayloadField::Tombstone)?;
        if seen_tombstones.insert(uuid) {
            unique_tombstones.push(uuid);
        }
    }

    // Rule 9: each entry UUID appears once.
    let mut seen_entries = HashSet::with_capacity(entries.len());
    if !entries.iter().all(|entry| seen_entries.insert(entry.uuid)) {
        return Err(SnapshotRejection::DuplicateEntry);
    }

    // Rule 10: no UUID is both live and deleted.
    if entries.iter().any(|entry| seen_tombstones.contains(&entry.uuid)) {
        return Err(SnapshotRejection::EntryAndTombstone);
    }

    // Rule 11: item nonces are 24 bytes.
    if let Some(entry) = entries.iter().find(|entry| entry.nonce.len() != ITEM_NONCE_LEN) {
        return Err(SnapshotRejection::BadNonceLength { len: entry.nonce.len() });
    }

    // Rule 12: names are not empty.
    if entries.iter().any(|entry| entry.name.is_empty()) {
        return Err(SnapshotRejection::EmptyName);
    }

    // Rule 13: kinds are ones this binary stores.
    if !entries.iter().all(|entry| is_recognized_kind(&entry.kind)) {
        return Err(SnapshotRejection::UnknownKind);
    }

    Ok(SyncState {
        entries,
        tombstones: unique_tombstones,
    })
}

/// Rule 8 for one entry: converts its string fields.
fn convert_entry(entry: EntryJson) -> Result<SyncEntry, SnapshotRejection> {
    Ok(SyncEntry {
        uuid: parse_canonical_uuid(&entry.uuid, PayloadField::EntryUuid)?,
        name: entry.name,
        kind: entry.kind,
        nonce: decode_base64(&entry.nonce, PayloadField::Nonce)?,
        ciphertext: decode_base64(&entry.ciphertext, PayloadField::Ciphertext)?,
        created_at: parse_utc_timestamp(&entry.created_at, PayloadField::CreatedAt)?,
        updated_at: parse_utc_timestamp(&entry.updated_at, PayloadField::UpdatedAt)?,
        revision: Revision {
            wall_ms: entry.revision.wall_ms,
            counter: entry.revision.counter,
            device_id: parse_canonical_uuid(&entry.revision.device_id, PayloadField::DeviceId)?,
        },
    })
}

/// Parses a UUID that must be exactly in canonical lowercase hyphenated form. Uppercase,
/// unhyphenated, braced, and URN forms, all of which `Uuid::parse_str` accepts, are malformed.
fn parse_canonical_uuid(text: &str, field: PayloadField) -> Result<Uuid, SnapshotRejection> {
    match Uuid::parse_str(text) {
        Ok(uuid) if uuid.hyphenated().to_string() == text => Ok(uuid),
        _ => Err(SnapshotRejection::MalformedField { field }),
    }
}

/// Decodes standard base64 with canonical padding.
fn decode_base64(text: &str, field: PayloadField) -> Result<Vec<u8>, SnapshotRejection> {
    BASE64
        .decode(text)
        .map_err(|_| SnapshotRejection::MalformedField { field })
}

/// Parses an RFC 3339 timestamp whose UTC offset is zero.
fn parse_utc_timestamp(text: &str, field: PayloadField) -> Result<OffsetDateTime, SnapshotRejection> {
    match OffsetDateTime::parse(text, &Rfc3339) {
        Ok(timestamp) if timestamp.offset() == UtcOffset::UTC => Ok(timestamp),
        _ => Err(SnapshotRejection::MalformedField { field }),
    }
}

/// Whether `kind` is exactly the stored kind string of some [`ItemKind`]. Aliases and other letter
/// cases, which `ItemKind::from_str` accepts, are not recognized.
fn is_recognized_kind(kind: &str) -> bool {
    ItemKind::all().iter().any(|known| known.as_str() == kind)
}

/// A payload field whose value can be malformed (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadField {
    /// An entry's UUID.
    EntryUuid,
    /// An entry's item nonce.
    Nonce,
    /// An entry's item ciphertext.
    Ciphertext,
    /// An entry's creation time.
    CreatedAt,
    /// An entry's last update time.
    UpdatedAt,
    /// The device ID in an entry's revision.
    DeviceId,
    /// A tombstone UUID.
    Tombstone,
}

impl PayloadField {
    /// How the field is named in a rejection message.
    const fn description(self) -> &'static str {
        match self {
            Self::EntryUuid => "an entry UUID",
            Self::Nonce => "an entry nonce",
            Self::Ciphertext => "an entry ciphertext",
            Self::CreatedAt => "an entry creation time",
            Self::UpdatedAt => "an entry update time",
            Self::DeviceId => "a revision device ID",
            Self::Tombstone => "a tombstone UUID",
        }
    }

    /// The form the field must take, as stated in a rejection message.
    const fn requirement(self) -> &'static str {
        match self {
            Self::EntryUuid | Self::DeviceId | Self::Tombstone => "a lowercase hyphenated UUID",
            Self::Nonce | Self::Ciphertext => "standard base64 with padding",
            Self::CreatedAt | Self::UpdatedAt => "an RFC 3339 time in UTC",
        }
    }
}

/// Why a snapshot file was rejected. Each case is one validation rule, listed in the order the
/// rules are checked.
///
/// Messages are written for users. They name the reason and what to do about it, and never
/// contain entry names, payload contents, or key material.
#[derive(Debug)]
pub enum SnapshotRejection {
    /// The file could not be opened or read.
    Unreadable(io::Error),
    /// Rule 1: the file is larger than [`MAX_FILE_LEN`].
    TooLarge {
        /// The file's size in bytes.
        len: u64,
    },
    /// Rule 1: the file is smaller than the header plus the tag.
    TooSmall {
        /// The file's size in bytes.
        len: u64,
    },
    /// Rule 2: the file does not start with [`MAGIC`].
    BadMagic,
    /// Rule 3: the format version is not [`FORMAT_VERSION`].
    UnsupportedVersion {
        /// The version the file declares.
        version: u16,
    },
    /// Rule 4: the package type is not [`PACKAGE_TYPE_SNAPSHOT`].
    WrongPackageType {
        /// The package type the file declares.
        package_type: u8,
    },
    /// Rule 5: the file's vault UUID is not the local vault's.
    ForeignVault,
    /// Rule 6: decryption failed authentication.
    AuthenticationFailed,
    /// Rule 7: the payload is not JSON of the snapshot shape, or its schema is not
    /// [`PAYLOAD_SCHEMA`].
    InvalidPayload,
    /// Rule 8: an identifier, base64 field, or timestamp is malformed.
    MalformedField {
        /// Which kind of field.
        field: PayloadField,
    },
    /// Rule 9: an entry UUID appears more than once among the entries.
    DuplicateEntry,
    /// Rule 10: a UUID appears both as an entry and as a tombstone.
    EntryAndTombstone,
    /// Rule 11: an entry's item nonce is not 24 bytes.
    BadNonceLength {
        /// The nonce's length in bytes.
        len: usize,
    },
    /// Rule 12: an entry's name is empty.
    EmptyName,
    /// Rule 13: an entry's kind is not one this binary recognizes.
    UnknownKind,
}

/// The advice for a file that decrypted correctly but carries content Chamber never writes.
const AUTHENTIC_BUT_INVALID: &str = "The file came from a device that holds this vault's key, so make sure every device runs the same version \
     of Chamber and publish the snapshot again.";

impl fmt::Display for SnapshotRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(err) => write!(
                f,
                "The snapshot file could not be read ({err}). Check that it exists and that you have permission to read it."
            ),
            Self::TooLarge { len } => write!(
                f,
                "The snapshot file is {len} bytes, larger than the {MAX_FILE_LEN}-byte (64 MiB) limit, so it was \
                 rejected without being merged. It is not a Chamber snapshot or it is damaged."
            ),
            Self::TooSmall { len } => write!(
                f,
                "The snapshot file is {len} bytes, too small to be a snapshot (at least {} bytes). It is incomplete \
                 or not a Chamber snapshot; if it is still being copied, try again once the copy finishes.",
                HEADER_LEN + TAG_LEN
            ),
            Self::BadMagic => f.write_str(
                "The file is not a Chamber snapshot: it does not start with the snapshot signature. Check that the \
                 right file was chosen.",
            ),
            Self::UnsupportedVersion { version } if *version > FORMAT_VERSION => write!(
                f,
                "The snapshot uses format version {version}, which is newer than this version of Chamber reads \
                 (version {FORMAT_VERSION}). Update Chamber on this device to read it."
            ),
            Self::UnsupportedVersion { version } => write!(
                f,
                "The snapshot declares format version {version}, which Chamber has never written. The file is \
                 damaged or was not made by Chamber."
            ),
            Self::WrongPackageType { package_type } if *package_type == PACKAGE_TYPE_ENROLLMENT => f.write_str(
                "The file is an enrollment package, not a snapshot. Enrollment packages are used once with \
                 `chamber sync join` to add a device to a vault and are never merged.",
            ),
            Self::WrongPackageType { package_type } => write!(
                f,
                "The file has package type {package_type}, which this version of Chamber does not recognize. It may \
                 come from a newer version of Chamber; update Chamber, or check that the file is a snapshot."
            ),
            Self::ForeignVault => f.write_str(
                "The snapshot belongs to another vault, so it was not merged. Check that it comes from a device that \
                 shares this vault.",
            ),
            Self::AuthenticationFailed => f.write_str(
                "The snapshot could not be decrypted: the key is wrong, or the file is damaged or incomplete. If it \
                 is still being copied, try again once the copy finishes; otherwise publish it again from the \
                 device that made it.",
            ),
            Self::InvalidPayload => write!(
                f,
                "The snapshot decrypted, but its contents are not in the snapshot format this version of Chamber \
                 reads (schema {PAYLOAD_SCHEMA}). {AUTHENTIC_BUT_INVALID}"
            ),
            Self::MalformedField { field } => write!(
                f,
                "The snapshot contains {} that is not {}, so the whole file was rejected. {AUTHENTIC_BUT_INVALID}",
                field.description(),
                field.requirement()
            ),
            Self::DuplicateEntry => write!(
                f,
                "The snapshot lists the same entry more than once, so the whole file was rejected. \
                 {AUTHENTIC_BUT_INVALID}"
            ),
            Self::EntryAndTombstone => write!(
                f,
                "The snapshot lists an entry as both present and deleted, so the whole file was rejected. \
                 {AUTHENTIC_BUT_INVALID}"
            ),
            Self::BadNonceLength { len } => write!(
                f,
                "The snapshot contains an entry whose nonce is {len} bytes instead of {ITEM_NONCE_LEN}, so the \
                 whole file was rejected. {AUTHENTIC_BUT_INVALID}"
            ),
            Self::EmptyName => write!(
                f,
                "The snapshot contains an entry with an empty name, so the whole file was rejected. \
                 {AUTHENTIC_BUT_INVALID}"
            ),
            Self::UnknownKind => f.write_str(
                "The snapshot contains an entry of a kind this version of Chamber does not recognize, so the whole \
                 file was rejected. Update Chamber on this device to read it.",
            ),
        }
    }
}

impl std::error::Error for SnapshotRejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]
    use super::*;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use serde_json::{Value, json};
    use std::error::Error as _;
    use time::macros::datetime;

    /// A distinctive entry name that must never appear in a rejection message.
    const SECRET_NAME: &str = "Zebra-Quokka-4417";

    fn vault_key() -> KeyMaterial {
        KeyMaterial([7u8; 32])
    }

    fn vault_uuid() -> Uuid {
        Uuid::from_bytes([0x11; 16])
    }

    fn device_id() -> Uuid {
        Uuid::parse_str("0d3c2f6a-91b4-4e0e-8a57-6c1f2b9d4e33").unwrap()
    }

    fn snapshot_key() -> KeyMaterial {
        derive_snapshot_key(&vault_key(), vault_uuid())
    }

    fn entry(uuid_byte: u8, name: &str, kind: &str) -> SyncEntry {
        SyncEntry {
            uuid: Uuid::from_bytes([uuid_byte; 16]),
            name: name.to_string(),
            kind: kind.to_string(),
            nonce: vec![uuid_byte; ITEM_NONCE_LEN],
            // Five bytes, so the base64 needs padding.
            ciphertext: vec![uuid_byte, 1, 2, 3, 4],
            created_at: datetime!(2026-11-17 08:00:00.123456789 UTC),
            updated_at: datetime!(2026-11-17 09:30:15.000000001 UTC),
            revision: Revision {
                wall_ms: u64::MAX - u64::from(uuid_byte),
                counter: u32::MAX - 1,
                device_id: device_id(),
            },
        }
    }

    fn sample_state() -> SyncState {
        SyncState {
            entries: vec![
                entry(0x21, "github", "password"),
                entry(0x22, "aws", "apikey"),
                entry(0x23, "server notes", "securenote"),
            ],
            tombstones: vec![Uuid::from_bytes([0x31; 16]), Uuid::from_bytes([0x32; 16])],
        }
    }

    fn encode(state: &SyncState) -> EncodedSnapshot {
        encode_snapshot(&snapshot_key(), vault_uuid(), device_id(), state).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<DecodedSnapshot, SnapshotRejection> {
        decode_snapshot(bytes, vault_uuid(), &snapshot_key())
    }

    fn reject(bytes: &[u8]) -> SnapshotRejection {
        decode(bytes).unwrap_err()
    }

    /// Seals a hand-written payload into an otherwise valid snapshot file.
    fn seal_payload(payload: &[u8]) -> Vec<u8> {
        let nonce = [9u8; NONCE_LEN];
        let header = snapshot_header(vault_uuid(), device_id(), Uuid::from_bytes([0x44; 16]), &nonce);
        seal_file(&snapshot_key(), &header, &nonce, payload).unwrap()
    }

    /// A valid entry in JSON form.
    fn entry_json(uuid: &str, name: &str) -> Value {
        json!({
            "uuid": uuid,
            "name": name,
            "kind": "password",
            "nonce": BASE64.encode([5u8; ITEM_NONCE_LEN]),
            "ciphertext": BASE64.encode([1u8, 2, 3]),
            "created_at": "2026-11-17T08:00:00Z",
            "updated_at": "2026-11-17T08:00:00.5Z",
            "revision": {
                "wall_ms": 1_794_902_400_000u64,
                "counter": 0,
                "device_id": "0d3c2f6a-91b4-4e0e-8a57-6c1f2b9d4e33"
            }
        })
    }

    const UUID_A: &str = "7b0e6c1e-3f5a-4a52-9c0d-2f6d3b1a9e10";
    const UUID_B: &str = "c2a4e8f0-5b6d-4c1a-9e3f-7a8b9c0d1e2f";

    fn payload(entries: &[Value], tombstones: &[&str]) -> Value {
        json!({ "schema": 1, "entries": entries, "tombstones": tombstones })
    }

    /// Seals `value` as a payload and decodes the result.
    fn decode_json(value: &Value) -> Result<DecodedSnapshot, SnapshotRejection> {
        decode(&seal_payload(&serde_json::to_vec(value).unwrap()))
    }

    fn reject_json(value: &Value) -> SnapshotRejection {
        decode_json(value).unwrap_err()
    }

    /// A payload with one entry whose field `key` is replaced by `value`.
    fn with_entry_field(key: &str, value: Value) -> Value {
        let mut e = entry_json(UUID_A, SECRET_NAME);
        e[key] = value;
        payload(&[e], &[])
    }

    fn assert_malformed(value: &Value, expected: PayloadField) {
        match reject_json(value) {
            SnapshotRejection::MalformedField { field } => assert_eq!(field, expected),
            other => panic!("expected MalformedField({expected:?}), got {other:?}"),
        }
    }

    fn flip_bit(bytes: &mut [u8], index: usize) {
        bytes[index] ^= 0x01;
    }

    // ---- Key derivation ----

    #[test]
    fn snapshot_key_is_deterministic_and_input_sensitive() {
        let key = snapshot_key();
        assert_eq!(key.0, snapshot_key().0, "same inputs give the same key");
        assert_ne!(
            key.0,
            derive_snapshot_key(&vault_key(), Uuid::from_bytes([0x12; 16])).0,
            "changes with the vault UUID"
        );
        assert_ne!(
            key.0,
            derive_snapshot_key(&KeyMaterial([8u8; 32]), vault_uuid()).0,
            "changes with the vault key"
        );
        assert_ne!(key.0, vault_key().0, "differs from the vault key");
    }

    #[test]
    fn snapshot_key_matches_hkdf_definition() {
        let mut expected = [0u8; 32];
        hkdf_sha256(
            vault_uuid().as_bytes(),
            &vault_key().0,
            b"chamber/snapshot/v1",
            &mut expected,
        )
        .unwrap();
        assert_eq!(snapshot_key().0, expected);
    }

    // ---- Layout ----

    #[test]
    fn header_constants() {
        assert_eq!(HEADER_LEN, 83);
        assert_eq!(HEADER_LEN + TAG_LEN, 99);
        assert_eq!(MAX_FILE_LEN, 67_108_864);
    }

    #[test]
    fn encoded_layout() {
        let state = sample_state();
        let encoded = encode(&state);
        let bytes = &encoded.bytes;
        assert_eq!(&bytes[0..8], b"CHMBSNAP");
        assert_eq!(&bytes[8..10], &[0x00, 0x01]);
        assert_eq!(bytes[10], 0x01);
        assert_eq!(&bytes[11..27], vault_uuid().as_bytes());
        assert_eq!(&bytes[27..43], device_id().as_bytes());
        assert_eq!(&bytes[43..59], encoded.snapshot_id.as_bytes());

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[59..83]);
        let plaintext = open(&snapshot_key(), &bytes[..83], &nonce, &bytes[83..]).unwrap();
        assert_eq!(bytes.len(), 83 + plaintext.len() + 16);
    }

    #[test]
    fn two_encodings_differ_in_snapshot_id_and_nonce() {
        let state = sample_state();
        let first = encode(&state);
        let second = encode(&state);
        assert_ne!(first.snapshot_id, second.snapshot_id);
        assert_ne!(first.bytes[43..59], second.bytes[43..59]);
        assert_ne!(first.bytes[59..83], second.bytes[59..83]);
    }

    #[test]
    fn payload_json_has_documented_shape() {
        let state = sample_state();
        let bytes = encode(&state).bytes;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[59..83]);
        let plaintext = open(&snapshot_key(), &bytes[..83], &nonce, &bytes[83..]).unwrap();
        let value: Value = serde_json::from_slice(&plaintext).unwrap();

        let top: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(top.len(), 3);
        for key in ["schema", "entries", "tombstones"] {
            assert!(top.contains(&key), "missing top-level {key}");
        }
        assert_eq!(value["schema"], json!(1));

        let first = &value["entries"][0];
        let mut entry_keys: Vec<&str> = first.as_object().unwrap().keys().map(String::as_str).collect();
        entry_keys.sort_unstable();
        assert_eq!(
            entry_keys,
            [
                "ciphertext",
                "created_at",
                "kind",
                "name",
                "nonce",
                "revision",
                "updated_at",
                "uuid"
            ]
        );
        let source = &state.entries[0];
        let uuid = first["uuid"].as_str().unwrap();
        assert_eq!(uuid, "21212121-2121-2121-2121-212121212121");
        assert_eq!(first["name"], json!("github"));
        assert_eq!(first["kind"], json!("password"));
        assert_eq!(first["nonce"].as_str().unwrap(), BASE64.encode(&source.nonce));
        let ciphertext = first["ciphertext"].as_str().unwrap();
        assert!(ciphertext.ends_with('='), "base64 is padded: {ciphertext}");
        assert_eq!(BASE64.decode(ciphertext).unwrap(), source.ciphertext);
        let created = first["created_at"].as_str().unwrap();
        assert!(created.ends_with('Z'), "{created}");
        assert!(created.starts_with("2026-11-17T08:00:00.123456789"), "{created}");
        assert!(first["updated_at"].as_str().unwrap().ends_with('Z'));

        let revision = first["revision"].as_object().unwrap();
        assert_eq!(revision.len(), 3);
        assert_eq!(revision["wall_ms"].as_u64().unwrap(), source.revision.wall_ms);
        assert_eq!(
            revision["counter"].as_u64().unwrap(),
            u64::from(source.revision.counter)
        );
        assert_eq!(revision["device_id"], json!("0d3c2f6a-91b4-4e0e-8a57-6c1f2b9d4e33"));

        let tombstones = value["tombstones"].as_array().unwrap();
        assert_eq!(
            tombstones,
            &[
                json!("31313131-3131-3131-3131-313131313131"),
                json!("32323232-3232-3232-3232-323232323232")
            ]
        );
        for text in std::iter::once(uuid).chain(tombstones.iter().map(|t| t.as_str().unwrap())) {
            assert_eq!(text, text.to_lowercase());
            assert_eq!(text.matches('-').count(), 4);
        }
    }

    #[test]
    fn round_trip_preserves_state_and_header_fields() {
        let state = sample_state();
        let encoded = encode(&state);
        let decoded = decode(&encoded.bytes).unwrap();
        assert_eq!(decoded.state, state);
        assert_eq!(decoded.publisher_device_id, device_id());
        assert_eq!(decoded.snapshot_id, encoded.snapshot_id);
        assert_eq!(decoded.state.entries[0].created_at.nanosecond(), 123_456_789);
        assert_eq!(decoded.state.entries[0].revision.wall_ms, u64::MAX - 0x21);
    }

    #[test]
    fn round_trip_empty_state() {
        let state = SyncState::default();
        let decoded = decode(&encode(&state).bytes).unwrap();
        assert_eq!(decoded.state, state);
    }

    #[test]
    fn round_trip_converts_non_utc_timestamps_to_the_same_instant() {
        let mut state = SyncState::default();
        let mut e = entry(0x21, "github", "password");
        e.created_at = datetime!(2026-11-17 10:00:00 +02:00);
        state.entries.push(e);
        let decoded = decode(&encode(&state).bytes).unwrap();
        assert_eq!(decoded.state.entries[0].created_at, datetime!(2026-11-17 08:00:00 UTC));
        assert_eq!(decoded.state.entries[0].created_at.offset(), UtcOffset::UTC);
    }

    #[test]
    fn every_item_kind_is_accepted() {
        let entries: Vec<SyncEntry> = ItemKind::all()
            .iter()
            .zip(1u8..)
            .map(|(kind, byte)| entry(byte, "item", kind.as_str()))
            .collect();
        let state = SyncState {
            entries,
            tombstones: Vec::new(),
        };
        assert_eq!(decode(&encode(&state).bytes).unwrap().state, state);
    }

    #[test]
    fn read_snapshot_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.chmb");
        let state = sample_state();
        std::fs::write(&path, encode(&state).bytes).unwrap();
        let decoded = read_snapshot_file(&path, vault_uuid(), &snapshot_key()).unwrap();
        assert_eq!(decoded.state, state);
    }

    #[test]
    fn encoding_refuses_a_file_over_the_cap() {
        let mut e = entry(0x21, "big", "document");
        // Base64 grows this by a third, past the 64 MiB cap.
        e.ciphertext = vec![0u8; 49 * 1024 * 1024];
        let state = SyncState {
            entries: vec![e],
            tombstones: Vec::new(),
        };
        assert!(encode_snapshot(&snapshot_key(), vault_uuid(), device_id(), &state).is_err());
    }

    // ---- Rule 1: size ----

    #[test]
    fn rule1_file_over_cap_is_rejected_by_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_FILE_LEN + 1).unwrap();
        drop(file);
        let rejection = read_snapshot_file(&path, vault_uuid(), &snapshot_key()).unwrap_err();
        assert!(
            matches!(rejection, SnapshotRejection::TooLarge { len } if len == MAX_FILE_LEN + 1),
            "{rejection:?}"
        );
    }

    #[test]
    fn rule1_98_byte_file_is_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small");
        let mut bytes = encode(&SyncState::default()).bytes;
        bytes.truncate(98);
        std::fs::write(&path, &bytes).unwrap();
        let rejection = read_snapshot_file(&path, vault_uuid(), &snapshot_key()).unwrap_err();
        assert!(
            matches!(rejection, SnapshotRejection::TooSmall { len: 98 }),
            "{rejection:?}"
        );
        assert!(matches!(reject(&bytes), SnapshotRejection::TooSmall { len: 98 }));
    }

    #[test]
    fn rule1_99_byte_file_passes_the_size_check() {
        // A header and a tag with no ciphertext: the right size, but it fails authentication.
        let nonce = [3u8; NONCE_LEN];
        let mut bytes = snapshot_header(vault_uuid(), device_id(), Uuid::nil(), &nonce).to_vec();
        bytes.extend_from_slice(&[0u8; TAG_LEN]);
        assert_eq!(bytes.len(), 99);
        assert!(matches!(reject(&bytes), SnapshotRejection::AuthenticationFailed));
    }

    #[test]
    fn rule1_read_is_bounded_when_the_file_grows() {
        // An endless reader stands in for a file that grew after its size was checked.
        let bytes = read_bounded(io::repeat(0), 100).unwrap();
        assert_eq!(u64::try_from(bytes.len()).unwrap(), MAX_FILE_LEN + 1);
        assert!(matches!(reject(&bytes), SnapshotRejection::TooLarge { .. }));
    }

    // ---- Rules 2 to 5: header ----

    #[test]
    fn rule2_altered_magic() {
        let mut bytes = encode(&sample_state()).bytes;
        flip_bit(&mut bytes, 3);
        assert!(matches!(reject(&bytes), SnapshotRejection::BadMagic));
        // The magic is checked before the version.
        bytes[9] = 9;
        assert!(matches!(reject(&bytes), SnapshotRejection::BadMagic));
    }

    #[test]
    fn rule3_newer_version_asks_for_an_update() {
        let mut bytes = encode(&sample_state()).bytes;
        bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
        // The version is checked before anything after it, including the package type.
        bytes[10] = 9;
        let rejection = reject(&bytes);
        assert!(
            matches!(rejection, SnapshotRejection::UnsupportedVersion { version: 2 }),
            "{rejection:?}"
        );
        assert!(rejection.to_string().contains("Update Chamber"), "{rejection}");
    }

    #[test]
    fn rule3_version_zero() {
        let mut bytes = encode(&sample_state()).bytes;
        bytes[8..10].copy_from_slice(&0u16.to_be_bytes());
        let rejection = reject(&bytes);
        assert!(
            matches!(rejection, SnapshotRejection::UnsupportedVersion { version: 0 }),
            "{rejection:?}"
        );
        assert!(!rejection.to_string().contains("Update Chamber"), "{rejection}");
    }

    #[test]
    fn rule4_enrollment_package() {
        let mut bytes = encode(&sample_state()).bytes;
        bytes[10] = PACKAGE_TYPE_ENROLLMENT;
        let rejection = reject(&bytes);
        assert!(
            matches!(rejection, SnapshotRejection::WrongPackageType { package_type: 2 }),
            "{rejection:?}"
        );
        let message = rejection.to_string();
        assert!(message.contains("enrollment package"), "{message}");
        assert!(message.contains("chamber sync join"), "{message}");
        assert!(message.contains("never merged"), "{message}");
    }

    #[test]
    fn rule4_unknown_package_type() {
        let mut bytes = encode(&sample_state()).bytes;
        bytes[10] = 7;
        let rejection = reject(&bytes);
        assert!(
            matches!(rejection, SnapshotRejection::WrongPackageType { package_type: 7 }),
            "{rejection:?}"
        );
        assert!(!rejection.to_string().contains("enrollment"), "{rejection}");
    }

    #[test]
    fn rule5_other_vault() {
        let bytes = encode(&sample_state()).bytes;
        let rejection = decode_snapshot(&bytes, Uuid::from_bytes([0x12; 16]), &snapshot_key()).unwrap_err();
        assert!(matches!(rejection, SnapshotRejection::ForeignVault), "{rejection:?}");
        assert!(rejection.to_string().contains("another vault"), "{rejection}");
    }

    // ---- Rule 6: authentication ----

    fn assert_auth_failed(bytes: &[u8]) {
        let rejection = reject(bytes);
        assert!(
            matches!(rejection, SnapshotRejection::AuthenticationFailed),
            "{rejection:?}"
        );
        let message = rejection.to_string();
        assert!(message.contains("key is wrong"), "{message}");
        assert!(message.contains("damaged or incomplete"), "{message}");
    }

    #[test]
    fn rule6_wrong_key() {
        let bytes = encode(&sample_state()).bytes;
        let wrong = derive_snapshot_key(&KeyMaterial([8u8; 32]), vault_uuid());
        let rejection = decode_snapshot(&bytes, vault_uuid(), &wrong).unwrap_err();
        assert!(
            matches!(rejection, SnapshotRejection::AuthenticationFailed),
            "{rejection:?}"
        );
    }

    #[test]
    fn rule6_flipped_ciphertext_bit() {
        let mut bytes = encode(&sample_state()).bytes;
        flip_bit(&mut bytes, HEADER_LEN + 5);
        assert_auth_failed(&bytes);
    }

    #[test]
    fn rule6_flipped_tag_bit() {
        let mut bytes = encode(&sample_state()).bytes;
        let last = bytes.len() - 1;
        flip_bit(&mut bytes, last - 3);
        assert_auth_failed(&bytes);
    }

    #[test]
    fn rule6_flipped_header_bit_after_vault_uuid() {
        let original = encode(&sample_state()).bytes;
        for index in [
            DEVICE_ID_OFFSET,
            DEVICE_ID_OFFSET + 15,
            SNAPSHOT_ID_OFFSET + 4,
            NONCE_OFFSET,
            HEADER_LEN - 1,
        ] {
            let mut bytes = original.clone();
            flip_bit(&mut bytes, index);
            assert_auth_failed(&bytes);
        }
    }

    #[test]
    fn rule6_truncated_by_one_byte() {
        let mut bytes = encode(&sample_state()).bytes;
        bytes.pop();
        assert_auth_failed(&bytes);
    }

    // ---- Rule 7: shape ----

    fn assert_invalid_payload(rejection: &SnapshotRejection) {
        assert!(matches!(rejection, SnapshotRejection::InvalidPayload), "{rejection:?}");
    }

    #[test]
    fn rule7_not_json() {
        assert_invalid_payload(&reject(&seal_payload(b"not json at all")));
        assert_invalid_payload(&reject(&seal_payload(&[0xff, 0xfe, 0x00])));
    }

    #[test]
    fn rule7_missing_field() {
        let mut e = entry_json(UUID_A, "github");
        e.as_object_mut().unwrap().remove("kind");
        assert_invalid_payload(&reject_json(&payload(&[e], &[])));

        let mut top = payload(&[entry_json(UUID_A, "github")], &[]);
        top.as_object_mut().unwrap().remove("tombstones");
        assert_invalid_payload(&reject_json(&top));

        let mut e = entry_json(UUID_A, "github");
        e["revision"].as_object_mut().unwrap().remove("counter");
        assert_invalid_payload(&reject_json(&payload(&[e], &[])));
    }

    #[test]
    fn rule7_unknown_top_level_field() {
        let mut top = payload(&[entry_json(UUID_A, "github")], &[]);
        top["extra"] = json!(1);
        assert_invalid_payload(&reject_json(&top));
    }

    #[test]
    fn rule7_unknown_entry_field() {
        assert_invalid_payload(&reject_json(&with_entry_field("colour", json!("blue"))));
        let mut e = entry_json(UUID_A, "github");
        e["revision"]["extra"] = json!(0);
        assert_invalid_payload(&reject_json(&payload(&[e], &[])));
    }

    #[test]
    fn rule7_wrong_type() {
        let mut e = entry_json(UUID_A, "github");
        e["revision"]["counter"] = json!("zero");
        assert_invalid_payload(&reject_json(&payload(&[e], &[])));
        assert_invalid_payload(&reject_json(&with_entry_field("name", json!(42))));
        let mut top = payload(&[], &[]);
        top["tombstones"] = json!("not a list");
        assert_invalid_payload(&reject_json(&top));
        let mut e = entry_json(UUID_A, "github");
        e["revision"]["counter"] = json!(u64::from(u32::MAX) + 1);
        assert_invalid_payload(&reject_json(&payload(&[e], &[])));
    }

    #[test]
    fn rule7_schema_2() {
        let mut top = payload(&[entry_json(UUID_A, "github")], &[]);
        top["schema"] = json!(2);
        assert_invalid_payload(&reject_json(&top));
    }

    // ---- Rule 8: malformed values ----

    #[test]
    fn rule8_uppercase_uuid() {
        assert_malformed(
            &with_entry_field("uuid", json!(UUID_A.to_uppercase())),
            PayloadField::EntryUuid,
        );
    }

    #[test]
    fn rule8_unhyphenated_uuid() {
        assert_malformed(
            &with_entry_field("uuid", json!(UUID_A.replace('-', ""))),
            PayloadField::EntryUuid,
        );
    }

    #[test]
    fn rule8_braced_and_urn_uuid() {
        assert_malformed(
            &with_entry_field("uuid", json!(format!("{{{UUID_A}}}"))),
            PayloadField::EntryUuid,
        );
        assert_malformed(
            &with_entry_field("uuid", json!(format!("urn:uuid:{UUID_A}"))),
            PayloadField::EntryUuid,
        );
    }

    #[test]
    fn rule8_malformed_device_id() {
        let mut e = entry_json(UUID_A, "github");
        e["revision"]["device_id"] = json!("not-a-device");
        assert_malformed(&payload(&[e], &[]), PayloadField::DeviceId);
    }

    #[test]
    fn rule8_malformed_tombstone() {
        let upper = UUID_B.to_uppercase();
        assert_malformed(&payload(&[], &[upper.as_str()]), PayloadField::Tombstone);
        assert_malformed(&payload(&[], &["c2a4e8f0"]), PayloadField::Tombstone);
    }

    #[test]
    fn rule8_invalid_base64() {
        assert_malformed(
            &with_entry_field("nonce", json!("!!!not base64!!!")),
            PayloadField::Nonce,
        );
        assert_malformed(&with_entry_field("ciphertext", json!("abc$")), PayloadField::Ciphertext);
    }

    #[test]
    fn rule8_unpadded_base64() {
        let unpadded = STANDARD_NO_PAD.encode([1u8, 2, 3, 4, 5]);
        assert!(!unpadded.ends_with('='));
        assert_malformed(
            &with_entry_field("ciphertext", json!(unpadded)),
            PayloadField::Ciphertext,
        );
    }

    #[test]
    fn rule8_timestamp_not_rfc3339() {
        assert_malformed(
            &with_entry_field("created_at", json!("17 November 2026")),
            PayloadField::CreatedAt,
        );
        assert_malformed(
            &with_entry_field("updated_at", json!("2026-11-17 08:00:00")),
            PayloadField::UpdatedAt,
        );
    }

    #[test]
    fn rule8_timestamp_with_nonzero_offset() {
        assert_malformed(
            &with_entry_field("created_at", json!("2026-11-17T09:00:00+01:00")),
            PayloadField::CreatedAt,
        );
    }

    #[test]
    fn rule8_zero_offset_written_numerically_is_accepted() {
        let decoded = decode_json(&with_entry_field("created_at", json!("2026-11-17T08:00:00+00:00"))).unwrap();
        assert_eq!(decoded.state.entries[0].created_at, datetime!(2026-11-17 08:00:00 UTC));
    }

    // ---- Rules 9 to 13 ----

    #[test]
    fn rule9_duplicate_entry_uuid() {
        let rejection = reject_json(&payload(&[entry_json(UUID_A, "one"), entry_json(UUID_A, "two")], &[]));
        assert!(matches!(rejection, SnapshotRejection::DuplicateEntry), "{rejection:?}");
    }

    #[test]
    fn rule10_uuid_in_both_lists() {
        let rejection = reject_json(&payload(&[entry_json(UUID_A, "one")], &[UUID_B, UUID_A]));
        assert!(
            matches!(rejection, SnapshotRejection::EntryAndTombstone),
            "{rejection:?}"
        );
    }

    #[test]
    fn rule11_short_nonce() {
        let rejection = reject_json(&with_entry_field("nonce", json!(BASE64.encode([0u8; 12]))));
        assert!(
            matches!(rejection, SnapshotRejection::BadNonceLength { len: 12 }),
            "{rejection:?}"
        );
    }

    #[test]
    fn rule12_empty_name() {
        let rejection = reject_json(&payload(&[entry_json(UUID_A, "")], &[]));
        assert!(matches!(rejection, SnapshotRejection::EmptyName), "{rejection:?}");
    }

    #[test]
    fn rule13_unrecognized_kinds() {
        for kind in ["pass", "Password", "PASSWORD", "spaceship", ""] {
            let rejection = reject_json(&with_entry_field("kind", json!(kind)));
            assert!(
                matches!(rejection, SnapshotRejection::UnknownKind),
                "{kind}: {rejection:?}"
            );
        }
    }

    // ---- Ordering ----

    #[test]
    fn lowest_numbered_rule_wins_across_entries() {
        let mut empty_name = entry_json(UUID_A, "");
        let mut upper_uuid = entry_json(&UUID_B.to_uppercase(), "two");
        let rejection = reject_json(&payload(&[empty_name.clone(), upper_uuid.clone()], &[]));
        assert!(
            matches!(
                rejection,
                SnapshotRejection::MalformedField {
                    field: PayloadField::EntryUuid
                }
            ),
            "rule 12 in the first entry, rule 8 in the second: {rejection:?}"
        );

        upper_uuid["uuid"] = json!(UUID_B);
        upper_uuid["nonce"] = json!(BASE64.encode([0u8; 12]));
        let rejection = reject_json(&payload(&[empty_name.clone(), upper_uuid], &[]));
        assert!(
            matches!(rejection, SnapshotRejection::BadNonceLength { len: 12 }),
            "rule 12 in the first entry, rule 11 in the second: {rejection:?}"
        );

        empty_name["name"] = json!("one");
        empty_name["kind"] = json!("pass");
        let rejection = reject_json(&payload(&[empty_name, entry_json(UUID_B, "two")], &[UUID_B]));
        assert!(
            matches!(rejection, SnapshotRejection::EntryAndTombstone),
            "rule 13 in the first entry, rule 10 in the second: {rejection:?}"
        );
    }

    // ---- Other cases ----

    #[test]
    fn missing_path_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let rejection = read_snapshot_file(&dir.path().join("absent"), vault_uuid(), &snapshot_key()).unwrap_err();
        assert!(matches!(rejection, SnapshotRejection::Unreadable(_)), "{rejection:?}");
        assert!(rejection.source().is_some());
        assert!(rejection.to_string().contains("could not be read"), "{rejection}");
    }

    #[test]
    fn repeated_tombstone_is_accepted() {
        let decoded = decode_json(&payload(&[entry_json(UUID_A, "github")], &[UUID_B, UUID_B])).unwrap();
        assert_eq!(decoded.state.tombstones, vec![Uuid::parse_str(UUID_B).unwrap()]);
    }

    #[test]
    fn hand_written_payload_matches_documented_example() {
        let decoded = decode_json(&payload(&[entry_json(UUID_A, "github")], &[UUID_B])).unwrap();
        let entry = &decoded.state.entries[0];
        assert_eq!(entry.uuid, Uuid::parse_str(UUID_A).unwrap());
        assert_eq!(entry.name, "github");
        assert_eq!(entry.kind, "password");
        assert_eq!(entry.nonce, vec![5u8; ITEM_NONCE_LEN]);
        assert_eq!(entry.ciphertext, vec![1u8, 2, 3]);
        assert_eq!(entry.updated_at, datetime!(2026-11-17 08:00:00.5 UTC));
        assert_eq!(entry.revision.wall_ms, 1_794_902_400_000);
        assert_eq!(entry.revision.device_id, device_id());
    }

    // ---- Reports ----

    #[test]
    fn post_decryption_messages_never_contain_entry_names() {
        let mut wrongly_typed = entry_json(UUID_A, "github");
        wrongly_typed["revision"]["counter"] = json!(SECRET_NAME);
        let mut schema_as_name = payload(&[entry_json(UUID_A, SECRET_NAME)], &[]);
        schema_as_name["schema"] = json!(SECRET_NAME);
        let mut unknown_field = entry_json(UUID_A, SECRET_NAME);
        unknown_field[SECRET_NAME] = json!(SECRET_NAME);

        let cases = [
            payload(&[wrongly_typed], &[]),
            schema_as_name,
            payload(&[unknown_field], &[]),
            with_entry_field("uuid", json!(SECRET_NAME)),
            with_entry_field("nonce", json!(SECRET_NAME)),
            with_entry_field("created_at", json!(SECRET_NAME)),
            payload(&[entry_json(UUID_A, SECRET_NAME), entry_json(UUID_A, SECRET_NAME)], &[]),
            payload(&[entry_json(UUID_A, SECRET_NAME)], &[UUID_A]),
            with_entry_field("nonce", json!(BASE64.encode([0u8; 12]))),
            payload(&[entry_json(UUID_A, SECRET_NAME), entry_json(UUID_B, "")], &[]),
            with_entry_field("kind", json!(SECRET_NAME)),
        ];
        for case in &cases {
            let rejection = reject_json(case);
            let message = rejection.to_string();
            assert!(!message.contains(SECRET_NAME), "{message}");
            assert!(!format!("{rejection:?}").contains(SECRET_NAME), "{rejection:?}");
        }
    }

    #[test]
    fn every_case_has_a_distinct_message() {
        let cases = [
            SnapshotRejection::Unreadable(io::Error::from(io::ErrorKind::NotFound)),
            SnapshotRejection::TooLarge { len: MAX_FILE_LEN + 1 },
            SnapshotRejection::TooSmall { len: 98 },
            SnapshotRejection::BadMagic,
            SnapshotRejection::UnsupportedVersion { version: 2 },
            SnapshotRejection::UnsupportedVersion { version: 0 },
            SnapshotRejection::WrongPackageType { package_type: 2 },
            SnapshotRejection::WrongPackageType { package_type: 3 },
            SnapshotRejection::ForeignVault,
            SnapshotRejection::AuthenticationFailed,
            SnapshotRejection::InvalidPayload,
            SnapshotRejection::MalformedField {
                field: PayloadField::EntryUuid,
            },
            SnapshotRejection::MalformedField {
                field: PayloadField::Nonce,
            },
            SnapshotRejection::MalformedField {
                field: PayloadField::CreatedAt,
            },
            SnapshotRejection::DuplicateEntry,
            SnapshotRejection::EntryAndTombstone,
            SnapshotRejection::BadNonceLength { len: 12 },
            SnapshotRejection::EmptyName,
            SnapshotRejection::UnknownKind,
        ];
        let messages: HashSet<String> = cases.iter().map(ToString::to_string).collect();
        assert_eq!(messages.len(), cases.len());
        for message in &messages {
            assert!(!message.contains('\u{2014}'), "no em dashes: {message}");
        }
    }
}
