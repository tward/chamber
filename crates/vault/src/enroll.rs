//! Enrollment: adding a machine to an existing vault with one encrypted package file.
//!
//! An unlocked vault writes an enrollment package ([`Vault::write_enrollment_package`]): the
//! vault key, the vault UUID, and the complete synchronization state, sealed under a one-time
//! [`TransferSecret`] that is shown to the user and never written to disk. A machine whose vault
//! has never been initialized reads the package in two stages that a caller can separate with
//! prompts ([`EnrollmentPackage::read_file`], then [`EnrollmentPackage::open`] with the secret)
//! and joins the vault ([`Vault::join_enrollment`]) under its own master password and a new
//! device ID.
//!
//! The package shares the snapshot file format's magic, format version, size cap, cipher, and
//! payload rules (see [`crate::snapshot`]), with its own header and key:
//!
//! ```text
//! header:  magic "CHMBSNAP" (8) | format version (u16, big-endian) | package type = 2 (u8)
//!          | salt (16) | nonce (24)
//! key:     HKDF-SHA-256(ikm = transfer secret, salt = header salt, info = "chamber/enroll/v1"),
//!          32 bytes
//! cipher:  XChaCha20-Poly1305 over the payload, with the whole header as associated data
//! payload: JSON, UTF-8: the snapshot payload plus `vault_uuid` (lowercase hyphenated) and
//!          `vault_key` (standard padded base64 of the 32-byte vault key)
//! ```
//!
//! The salt and the nonce are fresh random bytes for every package. Snapshot decoding rejects
//! this package type, so an enrollment package is never merged and an ordinary snapshot never
//! carries the vault key.

use crate::Vault;
use crate::crypto::{KdfParams, KeyMaterial, WrappedVaultKey, derive_key, hkdf_sha256, wrap_vault_key};
use crate::db::{Db, new_random_uuid, read_sync_meta, wall_ms_to_sql, write_meta_row};
use crate::merge::{SyncState, insert_entry, read_sync_state};
use crate::revision::HighWaterMark;
use crate::snapshot::{
    EntryJson, FORMAT_VERSION, MAGIC, MAX_FILE_LEN, NONCE_LEN, PACKAGE_TYPE_ENROLLMENT, PACKAGE_TYPE_SNAPSHOT,
    PayloadJson, SnapshotRejection, TAG_LEN, check_magic_and_version, check_size_bounds, open, read_bounded, seal,
    validate_payload,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use color_eyre::Result;
use color_eyre::eyre::eyre;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// The file extension every enrollment package must have, without the dot.
pub const ENROLLMENT_EXTENSION: &str = "chenroll";

/// The length of the random HKDF salt in an enrollment package header.
pub const ENROLLMENT_SALT_LEN: usize = 16;

/// The length of an enrollment package header in bytes: magic, format version, package type,
/// salt, and nonce.
pub const ENROLLMENT_HEADER_LEN: usize = MAGIC.len() + 2 + 1 + ENROLLMENT_SALT_LEN + NONCE_LEN;

/// The HKDF `info` input of the enrollment key.
pub const ENROLLMENT_KEY_INFO: &[u8] = b"chamber/enroll/v1";

/// The length of a transfer secret in bytes: 128 random bits.
pub const TRANSFER_SECRET_LEN: usize = 16;

/// The number of base32 characters in a transfer secret's display form, without hyphens.
pub const TRANSFER_SECRET_CHARS: usize = 26;

/// The size of each hyphen-separated group in a transfer secret's display form. The last group
/// holds whatever is left (two characters).
const TRANSFER_SECRET_GROUP: usize = 4;

// Header field offsets.
const PACKAGE_TYPE_OFFSET: usize = MAGIC.len() + 2;
const SALT_OFFSET: usize = PACKAGE_TYPE_OFFSET + 1;
const NONCE_OFFSET: usize = SALT_OFFSET + ENROLLMENT_SALT_LEN;

/// The length of the vault key carried in the payload.
const VAULT_KEY_LEN: usize = 32;

// ---- Base32 ----

/// The RFC 4648 base32 alphabet.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes `bytes` as RFC 4648 base32 (uppercase alphabet) without padding.
///
/// The last character carries zero bits wherever the input runs out, so the result is the
/// canonical encoding that [`base32_decode`] accepts.
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    // Fewer than 5 bits are left over after each byte, so 12 bits always hold the buffer.
    let mut buffer: usize = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = ((buffer << 8) | usize::from(byte)) & 0xFFF;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32_ALPHABET[(buffer >> bits) & 0x1F]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1F]));
    }
    out
}

/// Decodes unpadded RFC 4648 base32.
///
/// Only the uppercase alphabet is accepted, with no padding, spaces, or other characters.
/// Returns `None` for a character outside the alphabet, for a length no unpadded encoding has
/// (1, 3, or 6 characters past a multiple of 8), and for non-zero unused bits in the last
/// character, so every byte string has exactly one accepted encoding.
#[must_use]
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    // Fewer than 8 bits are left over after each character, so 13 bits always hold the buffer.
    let mut buffer: usize = 0;
    let mut bits = 0;
    for character in text.bytes() {
        buffer = ((buffer << 5) | usize::from(base32_value(character)?)) & 0x1FFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xFF).ok()?);
        }
    }
    if buffer & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// The value of one base32 character, or `None` outside the uppercase alphabet.
const fn base32_value(character: u8) -> Option<u8> {
    match character {
        b'A'..=b'Z' => Some(character - b'A'),
        b'2'..=b'7' => Some(character - b'2' + 26),
        _ => None,
    }
}

// ---- Transfer secret ----

/// The one-time secret that protects an enrollment package: 128 random bits, used raw as the
/// HKDF input keying material.
///
/// It is shown to the user as 26 base32 characters in groups of four, with a final group of
/// two ([`TransferSecret::display_form`]), and is never written to disk. The bytes are zeroized
/// on drop, and `Debug` is redacted.
#[derive(PartialEq, Eq)]
pub struct TransferSecret([u8; TRANSFER_SECRET_LEN]);

impl TransferSecret {
    /// Generates a fresh secret from the system random number generator.
    ///
    /// # Errors
    /// Returns an error when the system random number generator fails.
    pub fn generate() -> Result<Self> {
        let mut secret = Self([0u8; TRANSFER_SECRET_LEN]);
        getrandom::fill(&mut secret.0).map_err(|err| eyre!("Failed to get random bytes: {err}"))?;
        Ok(secret)
    }

    /// Parses a secret as a user typed it.
    ///
    /// Letter case, spaces, and hyphens are ignored. What remains must be exactly
    /// [`TRANSFER_SECRET_CHARS`] base32 characters that decode to 16 bytes with the two unused
    /// trailing bits zero.
    ///
    /// # Errors
    /// Returns [`EnrollmentError::InvalidTransferSecret`] for anything else. The error never
    /// contains the input.
    pub fn parse(text: &str) -> Result<Self, EnrollmentError> {
        let mut normalized = Zeroizing::new(String::with_capacity(TRANSFER_SECRET_CHARS));
        for character in text.chars().filter(|c| !matches!(c, ' ' | '-')) {
            if normalized.len() == TRANSFER_SECRET_CHARS {
                return Err(EnrollmentError::InvalidTransferSecret);
            }
            normalized.push(character.to_ascii_uppercase());
        }
        if normalized.len() != TRANSFER_SECRET_CHARS {
            return Err(EnrollmentError::InvalidTransferSecret);
        }
        let decoded = Zeroizing::new(base32_decode(&normalized).ok_or(EnrollmentError::InvalidTransferSecret)?);
        if decoded.len() != TRANSFER_SECRET_LEN {
            return Err(EnrollmentError::InvalidTransferSecret);
        }
        let mut secret = Self([0u8; TRANSFER_SECRET_LEN]);
        secret.0.copy_from_slice(&decoded);
        Ok(secret)
    }

    /// The form shown to the user: 26 uppercase base32 characters as six groups of four and a
    /// final group of two, joined by hyphens, for example `ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ`.
    ///
    /// The returned string is the secret itself; the caller should show it and drop it.
    #[must_use]
    pub fn display_form(&self) -> String {
        let encoded = Zeroizing::new(base32_encode(&self.0));
        let mut display = String::with_capacity(TRANSFER_SECRET_CHARS + TRANSFER_SECRET_CHARS / TRANSFER_SECRET_GROUP);
        for (index, character) in encoded.chars().enumerate() {
            if index > 0 && index % TRANSFER_SECRET_GROUP == 0 {
                display.push('-');
            }
            display.push(character);
        }
        display
    }
}

impl fmt::Debug for TransferSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransferSecret(<redacted>)")
    }
}

impl Drop for TransferSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Derives the enrollment key: HKDF-SHA-256 with the transfer secret's 16 bytes as input keying
/// material, the header salt as salt, and [`ENROLLMENT_KEY_INFO`] as info, producing 32 bytes.
///
/// # Panics
/// Never in practice: HMAC-SHA-256 accepts keys of any length and 32 bytes is far below the HKDF
/// output limit, so the derivation cannot fail.
#[must_use]
pub fn derive_enrollment_key(secret: &TransferSecret, salt: &[u8]) -> KeyMaterial {
    let mut key = KeyMaterial([0u8; 32]);
    hkdf_sha256(salt, &secret.0, ENROLLMENT_KEY_INFO, &mut key.0)
        .expect("a 32-byte HKDF-SHA-256 output is within the output limit");
    key
}

// ---- Package codec ----

/// The JSON payload of an enrollment package: the snapshot payload's fields plus the vault UUID
/// and the vault key. Unknown fields are rejected, as for snapshots.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentPayloadJson {
    schema: u64,
    entries: Vec<EntryJson>,
    tombstones: Vec<String>,
    vault_uuid: String,
    vault_key: String,
}

/// Builds an enrollment package header.
fn enrollment_header(salt: &[u8; ENROLLMENT_SALT_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; ENROLLMENT_HEADER_LEN] {
    let mut header = [0u8; ENROLLMENT_HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(&MAGIC);
    header[MAGIC.len()..PACKAGE_TYPE_OFFSET].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    header[PACKAGE_TYPE_OFFSET] = PACKAGE_TYPE_ENROLLMENT;
    header[SALT_OFFSET..NONCE_OFFSET].copy_from_slice(salt);
    header[NONCE_OFFSET..].copy_from_slice(nonce);
    header
}

/// Encodes a complete enrollment package file image carrying `vault_uuid`, `vault_key`, and
/// `state`, sealed under `secret`.
///
/// The salt and the nonce are fresh random bytes for every call. Item nonces and ciphertexts
/// are copied as stored; nothing is decrypted. The serialized payload and the base64 text of the
/// vault key are zeroized once sealed.
///
/// # Errors
/// Returns an error when the system random number generator fails, when an entry timestamp
/// cannot be written as RFC 3339, when the payload cannot be serialized, when the file would be
/// larger than [`MAX_FILE_LEN`] (readers would reject it), or when encryption fails.
pub fn encode_enrollment_package(
    secret: &TransferSecret,
    vault_uuid: Uuid,
    vault_key: &KeyMaterial,
    state: &SyncState,
) -> Result<Vec<u8>> {
    let base = PayloadJson::from_state(state)?;
    let mut payload = EnrollmentPayloadJson {
        schema: base.schema,
        entries: base.entries,
        tombstones: base.tombstones,
        vault_uuid: vault_uuid.hyphenated().to_string(),
        vault_key: BASE64.encode(vault_key.0),
    };
    let serialized = serde_json::to_vec(&payload).map(Zeroizing::new);
    payload.vault_key.zeroize();
    // serde_json error text could quote the payload, so none of it reaches the error.
    let plaintext = serialized.map_err(|_| eyre!("The enrollment package payload could not be serialized"))?;

    let file_len = ENROLLMENT_HEADER_LEN + plaintext.len() + TAG_LEN;
    if u64::try_from(file_len).unwrap_or(u64::MAX) > MAX_FILE_LEN {
        return Err(eyre!(
            "The enrollment package would be {file_len} bytes, larger than the {MAX_FILE_LEN}-byte limit readers accept"
        ));
    }

    let mut salt = [0u8; ENROLLMENT_SALT_LEN];
    getrandom::fill(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)?;
    let header = enrollment_header(&salt, &nonce);
    let key = derive_enrollment_key(secret, &salt);
    let sealed = seal(&key, &header, &nonce, &plaintext)?;

    let mut bytes = Vec::with_capacity(header.len() + sealed.len());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&sealed);
    Ok(bytes)
}

/// An enrollment package whose header passed stage one: its size, magic, format version, and
/// package type are right. Nothing has been decrypted yet; [`EnrollmentPackage::open`] does that
/// with the transfer secret, and can be retried with another secret.
pub struct EnrollmentPackage {
    bytes: Vec<u8>,
}

impl EnrollmentPackage {
    /// Stage one from a file: reads the package at `path` and checks its header.
    ///
    /// The size is checked from the file's metadata before anything is read, so an oversized
    /// file is never loaded, and the read stops one byte past [`MAX_FILE_LEN`] in case the file
    /// grew meanwhile. The file is never modified or deleted.
    ///
    /// # Errors
    /// Returns [`EnrollmentError::Unreadable`] when the file cannot be opened or read, and
    /// otherwise the error [`EnrollmentPackage::from_bytes`] gives.
    pub fn read_file(path: &Path) -> Result<Self, EnrollmentError> {
        let file = File::open(path).map_err(EnrollmentError::Unreadable)?;
        let len = file.metadata().map_err(EnrollmentError::Unreadable)?.len();
        check_size_bounds(len, ENROLLMENT_HEADER_LEN).map_err(EnrollmentError::from_header_rejection)?;
        let bytes = read_bounded(file, len).map_err(EnrollmentError::Unreadable)?;
        Self::from_bytes(bytes)
    }

    /// Stage one from a file image: checks the size, then the magic and the format version,
    /// then the package type.
    ///
    /// # Errors
    /// Returns [`EnrollmentError::TooLarge`] or [`EnrollmentError::TooSmall`] for a file outside
    /// the size bounds (at least [`ENROLLMENT_HEADER_LEN`] plus the 16-byte tag, at most
    /// [`MAX_FILE_LEN`]), [`EnrollmentError::BadMagic`],
    /// [`EnrollmentError::UnsupportedVersion`], [`EnrollmentError::IsSnapshot`] for a snapshot
    /// file, and [`EnrollmentError::UnknownPackageType`] for any other package type.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EnrollmentError> {
        check_size_bounds(u64::try_from(bytes.len()).unwrap_or(u64::MAX), ENROLLMENT_HEADER_LEN)
            .map_err(EnrollmentError::from_header_rejection)?;
        check_magic_and_version(&bytes).map_err(EnrollmentError::from_header_rejection)?;
        match bytes[PACKAGE_TYPE_OFFSET] {
            PACKAGE_TYPE_ENROLLMENT => Ok(Self { bytes }),
            PACKAGE_TYPE_SNAPSHOT => Err(EnrollmentError::IsSnapshot),
            package_type => Err(EnrollmentError::UnknownPackageType { package_type }),
        }
    }

    /// Stage two: derives the key from `secret` and the header salt, authenticates and decrypts
    /// the payload, and validates it.
    ///
    /// The payload must satisfy every snapshot payload rule (see [`crate::snapshot`]), its
    /// `vault_uuid` must be a lowercase hyphenated UUID, and its `vault_key` must be standard
    /// padded base64 of exactly 32 bytes. The decrypted payload and the vault key's base64 text
    /// are zeroized once read.
    ///
    /// # Errors
    /// Returns [`EnrollmentError::WrongSecretOrDamaged`] when authentication fails,
    /// [`EnrollmentError::Payload`] carrying the [`SnapshotRejection`] for a broken snapshot
    /// payload rule (including JSON of the wrong shape or with unknown fields),
    /// [`EnrollmentError::MalformedVaultUuid`], or [`EnrollmentError::MalformedVaultKey`].
    pub fn open(&self, secret: &TransferSecret) -> Result<OpenedEnrollment, EnrollmentError> {
        let (header, sealed) = self.bytes.split_at(ENROLLMENT_HEADER_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&header[NONCE_OFFSET..]);
        let key = derive_enrollment_key(secret, &header[SALT_OFFSET..NONCE_OFFSET]);
        let plaintext =
            Zeroizing::new(open(&key, header, &nonce, sealed).map_err(|_| EnrollmentError::WrongSecretOrDamaged)?);

        // serde_json error text can quote the input, so none of it reaches the error.
        let payload: EnrollmentPayloadJson = serde_json::from_slice(&plaintext)
            .map_err(|_| EnrollmentError::Payload(SnapshotRejection::InvalidPayload))?;
        let EnrollmentPayloadJson {
            schema,
            entries,
            tombstones,
            vault_uuid,
            vault_key,
        } = payload;
        let vault_key = Zeroizing::new(vault_key);

        let state = validate_payload(schema, entries, tombstones).map_err(EnrollmentError::Payload)?;
        let vault_uuid = match Uuid::parse_str(&vault_uuid) {
            Ok(uuid) if uuid.hyphenated().to_string() == vault_uuid => uuid,
            _ => return Err(EnrollmentError::MalformedVaultUuid),
        };
        let decoded = Zeroizing::new(
            BASE64
                .decode(vault_key.as_bytes())
                .map_err(|_| EnrollmentError::MalformedVaultKey)?,
        );
        if decoded.len() != VAULT_KEY_LEN {
            return Err(EnrollmentError::MalformedVaultKey);
        }
        let mut vault_key = KeyMaterial([0u8; VAULT_KEY_LEN]);
        vault_key.0.copy_from_slice(&decoded);

        Ok(OpenedEnrollment {
            vault_uuid,
            vault_key,
            state,
        })
    }
}

impl fmt::Debug for EnrollmentPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentPackage")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A decrypted and validated enrollment package, ready for [`Vault::join_enrollment`].
///
/// A caller can show [`OpenedEnrollment::vault_uuid`] and [`OpenedEnrollment::entry_count`]
/// before committing to the join. The vault key is held as [`KeyMaterial`], zeroized on drop,
/// and `Debug` shows only counts and the vault UUID.
pub struct OpenedEnrollment {
    vault_uuid: Uuid,
    vault_key: KeyMaterial,
    state: SyncState,
}

impl OpenedEnrollment {
    /// The UUID of the vault the package joins.
    #[must_use]
    pub const fn vault_uuid(&self) -> Uuid {
        self.vault_uuid
    }

    /// The number of entries the package carries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.state.entries.len()
    }

    /// The number of tombstones the package carries.
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.state.tombstones.len()
    }
}

impl fmt::Debug for OpenedEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedEnrollment")
            .field("vault_uuid", &self.vault_uuid)
            .field("entries", &self.state.entries.len())
            .field("tombstones", &self.state.tombstones.len())
            .field("vault_key", &self.vault_key)
            .finish()
    }
}

// ---- Writing and joining ----

impl Vault {
    /// Writes an enrollment package to `path` and returns the transfer secret that opens it.
    ///
    /// The vault UUID, every entry exactly as stored (still encrypted), and every tombstone are
    /// read in one read transaction, so a write committed meanwhile by another process is either
    /// wholly included or not at all. The package is sealed in memory, then written to a newly
    /// created file and flushed to disk. The file is created so that an existing file is never
    /// overwritten, even when one appears between the check and the creation, and readable and
    /// writable by its owner only where the platform supports it (mode `0600` on Unix); failing
    /// to apply the permission does not fail the write. If writing fails after the file was
    /// created, the partial file is removed on a best-effort basis.
    ///
    /// The transfer secret is never written to disk: the caller shows
    /// [`TransferSecret::display_form`] to the user.
    ///
    /// # Errors
    /// Returns `eyre!("Locked")` on a locked vault, before anything else;
    /// [`EnrollmentError::WrongExtension`] unless the path's extension is exactly
    /// [`ENROLLMENT_EXTENSION`]; [`EnrollmentError::OutputExists`] when anything exists at the
    /// path; [`EnrollmentError::WriteFailed`] when the file cannot be created, written, or
    /// flushed; and any error from reading the state or [`encode_enrollment_package`].
    pub fn write_enrollment_package(&self, path: &Path) -> Result<TransferSecret> {
        let vault_key = self.key.as_ref().ok_or_else(|| eyre!("Locked"))?;
        if path.extension() != Some(OsStr::new(ENROLLMENT_EXTENSION)) {
            return Err(EnrollmentError::WrongExtension.into());
        }
        if fs::symlink_metadata(path).is_ok() {
            return Err(EnrollmentError::OutputExists.into());
        }

        let (vault_uuid, state) = self.db.read_enrollment_state()?;
        let secret = TransferSecret::generate()?;
        let bytes = encode_enrollment_package(&secret, vault_uuid, vault_key, &state)?;
        write_new_file(path, &bytes)?;
        Ok(secret)
    }

    /// Joins this vault to the vault an enrollment package carries, protected by `master`.
    ///
    /// The vault must never have been initialized and must hold no entry and no tombstone. The
    /// carried vault key is wrapped under `master` exactly as [`Vault::initialize`] wraps a new
    /// one (fresh `KdfParams::default_secure`, `derive_key`, `wrap_vault_key`). Then, in one
    /// database transaction, the wrapped key is stored, the vault UUID is replaced by the
    /// carried one, a new device ID is minted and stored, the entries and tombstones are written
    /// exactly as carried (UUID, name, kind, nonce, ciphertext, timestamps, and revision), and
    /// the high-water mark is set to the greatest `(wall_ms, counter)` among the carried
    /// revisions, or `(0, 0)` when there are none. No secret value is decrypted.
    ///
    /// On any failure the vault is left exactly as it was: uninitialized, empty, with its
    /// previous vault UUID, device ID, and high-water mark. After a successful join the vault is
    /// locked and unlocks with `master`.
    ///
    /// # Errors
    /// Returns [`EnrollmentError::AlreadyInitialized`] when the vault is initialized (unlike
    /// [`Vault::initialize`], which then succeeds without doing anything); the error "Master
    /// password cannot be empty" for an empty `master`; [`EnrollmentError::VaultNotEmpty`] when
    /// the database holds an entry or a tombstone; and any error from key derivation, key
    /// wrapping, or the database, in which case nothing was changed.
    pub fn join_enrollment(&mut self, enrollment: &OpenedEnrollment, master: &str) -> Result<()> {
        if !self.db.is_meta_empty()? {
            return Err(EnrollmentError::AlreadyInitialized.into());
        }
        if master.is_empty() {
            return Err(eyre!("Master password cannot be empty"));
        }
        if self.db.holds_entries_or_tombstones()? {
            return Err(EnrollmentError::VaultNotEmpty.into());
        }

        let kdf = KdfParams::default_secure();
        let master_derived = derive_key(master, &kdf)?;
        let (wrapped, verifier) = wrap_vault_key(&master_derived, &enrollment.vault_key)?;
        self.db
            .install_enrollment(&kdf, &wrapped, &verifier, enrollment.vault_uuid, &enrollment.state)?;
        self.key = None;
        Ok(())
    }
}

/// Creates `path` (which must not exist) and writes `bytes` to it, flushed to disk. A partial
/// file left by a failed write is removed on a best-effort basis.
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), EnrollmentError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        if err.kind() == io::ErrorKind::AlreadyExists {
            EnrollmentError::OutputExists
        } else {
            EnrollmentError::WriteFailed(err)
        }
    })?;
    restrict_to_owner(&file);

    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        // Best effort: the write already failed, and that is the error worth reporting.
        let _ = fs::remove_file(path);
        return Err(EnrollmentError::WriteFailed(err));
    }
    Ok(())
}

/// Sets the file's permission bits to `0600`, in case the creation mode was narrowed or widened
/// on the way (the process umask can only clear bits, but a filesystem may not honor the mode at
/// all). A failure is ignored: the package is still written.
#[cfg(unix)]
fn restrict_to_owner(file: &File) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
}

/// Owner-only permission bits are a Unix notion; elsewhere the file keeps the platform default.
#[cfg(not(unix))]
const fn restrict_to_owner(_file: &File) {}

impl Db {
    /// Reads the vault UUID and the complete synchronization state in one read transaction.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read or a stored row is malformed.
    pub(crate) fn read_enrollment_state(&self) -> Result<(Uuid, SyncState)> {
        let tx = self.read_transaction()?;
        let vault_uuid = read_sync_meta(&tx)?.vault_uuid;
        let state = read_sync_state(&tx)?;
        tx.commit()?;
        Ok((vault_uuid, state))
    }

    /// Whether the database holds any entry or any tombstone.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read.
    pub(crate) fn holds_entries_or_tombstones(&self) -> Result<bool> {
        let tx = self.read_transaction()?;
        let holds = has_entries_or_tombstones(&tx)?;
        tx.commit()?;
        Ok(holds)
    }

    /// Installs a joined vault in one `IMMEDIATE` transaction: the `meta` row, the carried vault
    /// UUID, a newly minted device ID, the carried entries and tombstones, and the high-water
    /// mark of the carried revisions. The emptiness checks of [`Vault::join_enrollment`] are
    /// repeated under the write lock, so a concurrent initialization or write is not overwritten.
    ///
    /// # Errors
    /// Returns [`EnrollmentError::AlreadyInitialized`] or [`EnrollmentError::VaultNotEmpty`]
    /// when the checks fail under the lock, and any database error. The transaction is then
    /// rolled back and nothing is changed.
    pub(crate) fn install_enrollment(
        &self,
        kdf: &KdfParams,
        wrapped: &WrappedVaultKey,
        verifier: &[u8],
        vault_uuid: Uuid,
        state: &SyncState,
    ) -> Result<()> {
        let tx = self.write_transaction()?;
        let initialized: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM meta)", [], |r| r.get(0))?;
        if initialized {
            return Err(EnrollmentError::AlreadyInitialized.into());
        }
        if has_entries_or_tombstones(&tx)? {
            return Err(EnrollmentError::VaultNotEmpty.into());
        }

        write_meta_row(&tx, kdf, wrapped, verifier)?;

        let device_id = new_random_uuid()?;
        let hwm = state
            .entries
            .iter()
            .map(|entry| entry.revision.high_water_mark())
            .max()
            .unwrap_or_default();
        replace_sync_meta(&tx, vault_uuid, device_id, hwm)?;

        for entry in &state.entries {
            insert_entry(&tx, entry)?;
        }
        let mut record = tx.prepare("INSERT INTO tombstones (uuid) VALUES (?1)")?;
        for tombstone in &state.tombstones {
            record.execute(params![tombstone.as_bytes()])?;
        }
        drop(record);

        tx.commit()?;
        Ok(())
    }
}

/// Whether `items` or `tombstones` has any row.
fn has_entries_or_tombstones(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM items) OR EXISTS (SELECT 1 FROM tombstones)",
        [],
        |r| r.get(0),
    )?)
}

/// Overwrites every field of the single `sync_meta` row.
fn replace_sync_meta(conn: &Connection, vault_uuid: Uuid, device_id: Uuid, hwm: HighWaterMark) -> Result<()> {
    let changed = conn.execute(
        "UPDATE sync_meta SET vault_uuid = ?1, device_id = ?2, hwm_wall_ms = ?3, hwm_counter = ?4 WHERE id = 1",
        params![
            vault_uuid.as_bytes(),
            device_id.as_bytes(),
            wall_ms_to_sql(hwm.wall_ms),
            hwm.counter
        ],
    )?;
    if changed != 1 {
        return Err(eyre!("The vault's sync_meta row is missing"));
    }
    Ok(())
}

// ---- Errors ----

/// Why writing, reading, or joining from an enrollment package failed.
///
/// Messages are written for users. They name the reason and what to do about it, and never
/// contain entry names, payload contents, the transfer secret, or key material.
#[derive(Debug)]
pub enum EnrollmentError {
    /// The transfer secret is not 26 base32 characters encoding 16 bytes.
    InvalidTransferSecret,
    /// The output path's extension is not exactly [`ENROLLMENT_EXTENSION`].
    WrongExtension,
    /// Something already exists at the output path.
    OutputExists,
    /// The package file could not be created, written, or flushed.
    WriteFailed(io::Error),
    /// The package file could not be opened or read.
    Unreadable(io::Error),
    /// The file is larger than [`MAX_FILE_LEN`].
    TooLarge {
        /// The file's size in bytes.
        len: u64,
    },
    /// The file is smaller than [`ENROLLMENT_HEADER_LEN`] plus the 16-byte tag.
    TooSmall {
        /// The file's size in bytes.
        len: u64,
    },
    /// The file does not start with [`MAGIC`].
    BadMagic,
    /// The format version is not [`FORMAT_VERSION`].
    UnsupportedVersion {
        /// The version the file declares.
        version: u16,
    },
    /// The file is a snapshot (package type 1), not an enrollment package.
    IsSnapshot,
    /// The package type is neither an enrollment package nor a snapshot.
    UnknownPackageType {
        /// The package type the file declares.
        package_type: u8,
    },
    /// Decryption failed authentication: the transfer secret is wrong or the file is damaged.
    WrongSecretOrDamaged,
    /// The decrypted payload breaks one of the snapshot payload rules, carried as the
    /// [`SnapshotRejection`] for that rule.
    Payload(SnapshotRejection),
    /// The payload's `vault_uuid` is not a lowercase hyphenated UUID.
    MalformedVaultUuid,
    /// The payload's `vault_key` is not standard padded base64 of exactly 32 bytes.
    MalformedVaultKey,
    /// The vault to join is already initialized.
    AlreadyInitialized,
    /// The vault to join already holds an entry or a tombstone.
    VaultNotEmpty,
}

impl EnrollmentError {
    /// Maps a rejection from the shared size, magic, and version checks to its enrollment case.
    /// Those checks return no other rejection; anything else is carried as it is.
    fn from_header_rejection(rejection: SnapshotRejection) -> Self {
        match rejection {
            SnapshotRejection::TooLarge { len } => Self::TooLarge { len },
            SnapshotRejection::TooSmall { len } => Self::TooSmall { len },
            SnapshotRejection::BadMagic => Self::BadMagic,
            SnapshotRejection::UnsupportedVersion { version } => Self::UnsupportedVersion { version },
            other => Self::Payload(other),
        }
    }
}

/// The advice for a package that decrypted correctly but carries content Chamber never writes.
const AUTHENTIC_BUT_INVALID: &str = "The package was sealed with this transfer secret, so make sure both devices run the same version of \
     Chamber and write a new enrollment package.";

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransferSecret => write!(
                f,
                "The transfer secret is not valid: it is {TRANSFER_SECRET_CHARS} letters and digits (A to Z and 2 to \
                 7), shown in groups separated by hyphens. Check it and enter it again."
            ),
            Self::WrongExtension => write!(
                f,
                "An enrollment package must be written to a file whose name ends in `.{ENROLLMENT_EXTENSION}`. \
                 Choose a path with that extension."
            ),
            Self::OutputExists => f.write_str(
                "Something already exists at the chosen path, and an enrollment package never replaces an existing \
                 file. Choose another path.",
            ),
            Self::WriteFailed(err) => write!(
                f,
                "The enrollment package could not be written ({err}). Check that the directory exists, that you \
                 can write to it, and that the disk has space."
            ),
            Self::Unreadable(err) => write!(
                f,
                "The enrollment package could not be read ({err}). Check that it exists and that you have \
                 permission to read it."
            ),
            Self::TooLarge { len } => write!(
                f,
                "The file is {len} bytes, larger than the {MAX_FILE_LEN}-byte (64 MiB) limit, so it is not a \
                 Chamber enrollment package or it is damaged."
            ),
            Self::TooSmall { len } => write!(
                f,
                "The file is {len} bytes, too small to be an enrollment package (at least {} bytes). It is \
                 incomplete or not a Chamber enrollment package; if it is still being copied, try again once the \
                 copy finishes.",
                ENROLLMENT_HEADER_LEN + TAG_LEN
            ),
            Self::BadMagic => f.write_str(
                "The file is not a Chamber enrollment package: it does not start with the Chamber file signature. \
                 Check that the right file was chosen.",
            ),
            Self::UnsupportedVersion { version } if *version > FORMAT_VERSION => write!(
                f,
                "The enrollment package uses format version {version}, which is newer than this version of \
                 Chamber reads (version {FORMAT_VERSION}). Update Chamber on this device to read it."
            ),
            Self::UnsupportedVersion { version } => write!(
                f,
                "The enrollment package declares format version {version}, which Chamber has never written. The \
                 file is damaged or was not made by Chamber."
            ),
            Self::IsSnapshot => f.write_str(
                "The file is a snapshot, not an enrollment package. Snapshots are merged into a vault a device \
                 already has; to join this device, write an enrollment package on a device that has the vault.",
            ),
            Self::UnknownPackageType { package_type } => write!(
                f,
                "The file has package type {package_type}, which this version of Chamber does not recognize. It may \
                 come from a newer version of Chamber; update Chamber, or check that the file is an enrollment \
                 package."
            ),
            Self::WrongSecretOrDamaged => f.write_str(
                "The enrollment package could not be decrypted: the transfer secret is wrong, or the package is \
                 damaged or incomplete. Check the transfer secret and try again; if it is right, write a new \
                 package.",
            ),
            Self::Payload(rejection) => write!(
                f,
                "The enrollment package decrypted, but the state it carries is not valid, so nothing was joined. \
                 {AUTHENTIC_BUT_INVALID} The payload broke this rule: {rejection}"
            ),
            Self::MalformedVaultUuid => write!(
                f,
                "The enrollment package decrypted, but its vault UUID is not a lowercase hyphenated UUID, so nothing \
                 was joined. {AUTHENTIC_BUT_INVALID}"
            ),
            Self::MalformedVaultKey => write!(
                f,
                "The enrollment package decrypted, but its vault key is not {VAULT_KEY_LEN} bytes of standard base64, \
                 so nothing was joined. {AUTHENTIC_BUT_INVALID}"
            ),
            Self::AlreadyInitialized => f.write_str(
                "This vault is already initialized, so it cannot join another vault. Joining needs a vault that has \
                 never been set up.",
            ),
            Self::VaultNotEmpty => f.write_str(
                "This vault already holds entries or deletion records, so it cannot join another vault. Joining \
                 needs an empty vault that has never been set up.",
            ),
        }
    }
}

impl std::error::Error for EnrollmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WriteFailed(err) | Self::Unreadable(err) => Some(err),
            Self::Payload(rejection) => Some(rejection),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    use super::*;
    use crate::clock::ManualClock;
    use crate::merge::SyncEntry;
    use crate::revision::Revision;
    use crate::snapshot::{DecodedSnapshot, decode_snapshot, derive_snapshot_key, encode_snapshot, read_snapshot_file};
    use crate::{Item, ItemKind, NewItem};
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;
    use time::macros::datetime;

    /// A distinctive entry name that must never appear in package bytes or error messages.
    const SECRET_NAME: &str = "Zebra-Quokka-4417";
    const PASSWORD_A: &str = "alpha-master";
    const PASSWORD_B: &str = "bravo-master";

    const UUID_A: &str = "7b0e6c1e-3f5a-4a52-9c0d-2f6d3b1a9e10";
    const VAULT_UUID: &str = "c2a4e8f0-5b6d-4c1a-9e3f-7a8b9c0d1e2f";

    // ---- Helpers ----

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    fn fresh_vault(dir: &TempDir, name: &str) -> Vault {
        Vault::open_or_create(Some(&dir.path().join(name))).unwrap()
    }

    fn unlocked_vault(dir: &TempDir, name: &str, password: &str) -> Vault {
        let mut vault = fresh_vault(dir, name);
        vault.initialize(password).unwrap();
        vault.unlock(password).unwrap();
        vault
    }

    fn add(vault: &mut Vault, name: &str, kind: ItemKind, value: &str) {
        vault
            .create_item(&NewItem {
                name: name.into(),
                kind,
                value: value.into(),
            })
            .unwrap();
    }

    fn id_of(vault: &Vault, name: &str) -> u64 {
        vault.get_item_by_name(name).unwrap().unwrap().id
    }

    /// Machine A: several entries, one edited and one deleted.
    fn machine_a(dir: &TempDir) -> Vault {
        let mut a = unlocked_vault(dir, "a.sqlite3", PASSWORD_A);
        populate(&mut a);
        a
    }

    fn populate(a: &mut Vault) {
        add(a, SECRET_NAME, ItemKind::Password, "hunter2");
        add(a, "aws", ItemKind::ApiKey, "AKIAEXAMPLE");
        add(a, "server notes", ItemKind::Note, "reboot on Tuesdays");
        add(a, "to delete", ItemKind::Password, "gone soon");
        a.update_item(id_of(a, "aws"), "AKIAEDITED").unwrap();
        a.delete_item(id_of(a, "to delete")).unwrap();
    }

    fn package_path(dir: &TempDir, stem: &str) -> PathBuf {
        dir.path().join(format!("{stem}.{ENROLLMENT_EXTENSION}"))
    }

    fn write_package(vault: &Vault, dir: &TempDir, stem: &str) -> (PathBuf, TransferSecret) {
        let path = package_path(dir, stem);
        let secret = vault.write_enrollment_package(&path).unwrap();
        (path, secret)
    }

    fn open_file(path: &Path, secret: &TransferSecret) -> OpenedEnrollment {
        EnrollmentPackage::read_file(path).unwrap().open(secret).unwrap()
    }

    fn enrollment_error(err: &color_eyre::Report) -> &EnrollmentError {
        err.downcast_ref::<EnrollmentError>()
            .unwrap_or_else(|| panic!("expected an EnrollmentError, got {err:#}"))
    }

    /// Every item, decrypted, with its identity, as comparable tuples ascending by UUID.
    #[allow(clippy::type_complexity)]
    fn items(vault: &Vault) -> Vec<(Uuid, String, ItemKind, String, Revision)> {
        let mut items: Vec<_> = vault
            .list_items()
            .unwrap()
            .into_iter()
            .map(
                |Item {
                     uuid,
                     name,
                     kind,
                     value,
                     revision,
                     ..
                 }| (uuid, name, kind, value, revision),
            )
            .collect();
        items.sort_by_key(|item| item.0);
        items
    }

    fn greatest_revision(state: &SyncState) -> (u64, u32) {
        let hwm = state
            .entries
            .iter()
            .map(|entry| entry.revision.high_water_mark())
            .max()
            .unwrap_or_default();
        (hwm.wall_ms, hwm.counter)
    }

    /// The vault's identity and contents as seen without a key: initialization, sync metadata,
    /// stored rows, and tombstones.
    #[allow(clippy::type_complexity)]
    fn untouched_state(vault: &Vault) -> (bool, Uuid, Uuid, (u64, u32), usize, Vec<Uuid>) {
        (
            vault.is_initialized(),
            vault.vault_uuid().unwrap(),
            vault.device_id().unwrap(),
            vault.high_water_mark().unwrap(),
            vault.db.list_items().unwrap().len(),
            vault.tombstones().unwrap(),
        )
    }

    /// Seals `payload` into an otherwise valid enrollment package under `secret`.
    fn seal_payload(secret: &TransferSecret, payload: &[u8]) -> Vec<u8> {
        let salt = [5u8; ENROLLMENT_SALT_LEN];
        let nonce = [6u8; NONCE_LEN];
        let header = enrollment_header(&salt, &nonce);
        let key = derive_enrollment_key(secret, &salt);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&seal(&key, &header, &nonce, payload).unwrap());
        bytes
    }

    fn entry_json(uuid: &str, name: &str) -> Value {
        json!({
            "uuid": uuid,
            "name": name,
            "kind": "password",
            "nonce": BASE64.encode([5u8; 24]),
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

    /// A valid hand-written payload carrying one entry and the key `[7; 32]`.
    fn valid_payload() -> Value {
        json!({
            "schema": 1,
            "entries": [entry_json(UUID_A, SECRET_NAME)],
            "tombstones": [],
            "vault_uuid": VAULT_UUID,
            "vault_key": BASE64.encode([7u8; 32]),
        })
    }

    fn open_json(value: &Value) -> Result<OpenedEnrollment, EnrollmentError> {
        let secret = TransferSecret::generate().unwrap();
        let bytes = seal_payload(&secret, &serde_json::to_vec(value).unwrap());
        EnrollmentPackage::from_bytes(bytes).unwrap().open(&secret)
    }

    fn reject_json(value: &Value) -> EnrollmentError {
        let err = open_json(value).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains(SECRET_NAME), "{message}");
        assert!(!message.contains("line "), "no serde_json text: {message}");
        err
    }

    fn from_bytes_err(bytes: Vec<u8>) -> EnrollmentError {
        EnrollmentPackage::from_bytes(bytes).unwrap_err()
    }

    fn assert_wrong_secret(result: Result<OpenedEnrollment, EnrollmentError>) {
        let err = result.unwrap_err();
        assert!(matches!(err, EnrollmentError::WrongSecretOrDamaged), "{err:?}");
        assert!(err.to_string().contains("the transfer secret is wrong"), "{err}");
    }

    // ---- Base32 ----

    #[test]
    fn base32_rfc4648_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (bytes, text) in vectors {
            assert_eq!(base32_encode(bytes), text, "encode {bytes:?}");
            assert_eq!(base32_decode(text).as_deref(), Some(bytes), "decode {text}");
        }
    }

    #[test]
    fn base32_round_trips_every_length_and_byte() {
        let bytes: Vec<u8> = (0..=255).collect();
        for len in 0..=40 {
            let slice = &bytes[255 - len..];
            assert_eq!(base32_decode(&base32_encode(slice)).unwrap(), slice);
        }
    }

    #[test]
    fn base32_decode_is_strict() {
        assert_eq!(base32_decode("my"), None, "lowercase");
        assert_eq!(base32_decode("MY=="), None, "padding");
        assert_eq!(base32_decode("M1"), None, "outside the alphabet");
        assert_eq!(base32_decode("M"), None, "impossible length 1");
        assert_eq!(base32_decode("MZX"), None, "impossible length 3");
        assert_eq!(base32_decode("MZXW6Y"), None, "impossible length 6");
        assert_eq!(base32_decode("MZ"), None, "non-zero unused bits");
    }

    // ---- Transfer secret ----

    #[test]
    fn display_form_is_grouped_base32_and_parses_back() {
        let secret = TransferSecret::generate().unwrap();
        let display = secret.display_form();
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(
            groups.iter().map(|group| group.len()).collect::<Vec<_>>(),
            [4, 4, 4, 4, 4, 4, 2],
            "{display}"
        );
        let characters: String = groups.concat();
        assert_eq!(characters.len(), TRANSFER_SECRET_CHARS);
        assert!(characters.bytes().all(|c| BASE32_ALPHABET.contains(&c)), "{display}");
        assert_eq!(TransferSecret::parse(&display).unwrap(), secret);
    }

    #[test]
    fn display_form_of_known_bytes() {
        let secret = TransferSecret([0u8; TRANSFER_SECRET_LEN]);
        assert_eq!(secret.display_form(), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA");
        let secret = TransferSecret([0xFF; TRANSFER_SECRET_LEN]);
        assert_eq!(secret.display_form(), "7777-7777-7777-7777-7777-7777-74");
    }

    #[test]
    fn parse_ignores_case_spaces_and_hyphens() {
        let secret = TransferSecret::generate().unwrap();
        let plain = secret.display_form().replace('-', "");
        assert_eq!(TransferSecret::parse(&plain.to_lowercase()).unwrap(), secret);
        let spaced: String = plain
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                let sep = match i % 3 {
                    0 if i > 0 => Some(' '),
                    1 if i > 4 => Some('-'),
                    _ => None,
                };
                sep.into_iter().chain(std::iter::once(c))
            })
            .collect();
        assert_eq!(TransferSecret::parse(&format!("  {spaced} - ")).unwrap(), secret);
        let mixed: String = plain
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_ascii_lowercase() } else { c })
            .collect();
        assert_eq!(TransferSecret::parse(&mixed).unwrap(), secret);
    }

    #[test]
    fn parse_rejects_malformed_input_without_echoing_it() {
        let valid = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AE";
        assert!(TransferSecret::parse(valid).is_ok(), "zero unused bits are accepted");
        let rejected = [
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-A", "25 characters"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA", "27 characters"),
            ("", "empty"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-A1", "1 is outside the alphabet"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-A8", "8 is outside the alphabet"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-A!", "punctuation"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AÄ", "non-ASCII letter"),
            ("AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AA", "underscores are not ignored"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AB", "non-zero trailing bits"),
            ("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AH", "non-zero trailing bits"),
        ];
        for (input, why) in rejected {
            let err = TransferSecret::parse(input).unwrap_err();
            assert!(matches!(err, EnrollmentError::InvalidTransferSecret), "{why}: {err:?}");
            let message = err.to_string();
            if !input.is_empty() {
                assert!(!message.contains(input), "{why}: {message}");
            }
        }
    }

    #[test]
    fn generated_secrets_differ_and_debug_is_redacted() {
        let first = TransferSecret::generate().unwrap();
        let second = TransferSecret::generate().unwrap();
        assert_ne!(first, second);
        let debug = format!("{first:?}");
        assert_eq!(debug, "TransferSecret(<redacted>)");
        let display = first.display_form();
        assert!(!debug.contains(&display));
        assert!(!debug.contains(&display.replace('-', "")));
    }

    #[test]
    fn enrollment_key_matches_hkdf_definition() {
        let secret = TransferSecret([3u8; TRANSFER_SECRET_LEN]);
        let salt = [4u8; ENROLLMENT_SALT_LEN];
        let mut expected = [0u8; 32];
        hkdf_sha256(&salt, &[3u8; 16], b"chamber/enroll/v1", &mut expected).unwrap();
        assert_eq!(derive_enrollment_key(&secret, &salt).0, expected);
        assert_ne!(derive_enrollment_key(&secret, &[5u8; ENROLLMENT_SALT_LEN]).0, expected);
    }

    // ---- Package writing ----

    #[test]
    fn header_constants() {
        assert_eq!(ENROLLMENT_HEADER_LEN, 51);
        assert_eq!(ENROLLMENT_HEADER_LEN + TAG_LEN, 67);
    }

    #[test]
    fn written_package_layout_and_fresh_salt_and_nonce() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (first_path, first_secret) = write_package(&a, &dir, "first");
        let (second_path, _) = write_package(&a, &dir, "second");
        let first = fs::read(&first_path).unwrap();
        let second = fs::read(&second_path).unwrap();

        assert_eq!(&first[0..8], b"CHMBSNAP");
        assert_eq!(&first[8..10], &[0x00, 0x01]);
        assert_eq!(first[10], 0x02);
        assert!(first.len() > ENROLLMENT_HEADER_LEN + TAG_LEN);
        assert_ne!(first[11..27], second[11..27], "salts differ");
        assert_ne!(first[27..51], second[27..51], "nonces differ");

        // The rest is the sealed payload, authenticated over the whole 51-byte header.
        let key = derive_enrollment_key(&first_secret, &first[11..27]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&first[27..51]);
        let plaintext = open(&key, &first[..51], &nonce, &first[51..]).unwrap();
        assert_eq!(first.len(), 51 + plaintext.len() + TAG_LEN);
    }

    #[test]
    fn payload_json_has_documented_shape() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "shape");
        let bytes = fs::read(&path).unwrap();
        let key = derive_enrollment_key(&secret, &bytes[11..27]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[27..51]);
        let plaintext = open(&key, &bytes[..51], &nonce, &bytes[51..]).unwrap();
        let value: Value = serde_json::from_slice(&plaintext).unwrap();

        let mut keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["entries", "schema", "tombstones", "vault_key", "vault_uuid"]);
        assert_eq!(value["schema"], json!(1));
        assert_eq!(value["entries"].as_array().unwrap().len(), 3);
        assert_eq!(value["tombstones"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["vault_uuid"].as_str().unwrap(),
            a.vault_uuid().unwrap().hyphenated().to_string()
        );
        let vault_key = value["vault_key"].as_str().unwrap();
        assert!(vault_key.ends_with('='), "padded base64: {vault_key}");
        assert_eq!(BASE64.decode(vault_key).unwrap(), a.key.as_ref().unwrap().0);
    }

    #[test]
    fn package_bytes_reveal_nothing_without_the_secret() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "opaque");
        let bytes = fs::read(&path).unwrap();
        let vault_key = a.key.as_ref().unwrap().0;
        let display = secret.display_form();

        assert!(!contains(&bytes, &vault_key), "raw vault key");
        assert!(
            !contains(&bytes, BASE64.encode(vault_key).as_bytes()),
            "base64 vault key"
        );
        assert!(!contains(&bytes, SECRET_NAME.as_bytes()), "entry name");
        assert!(!contains(&bytes, display.as_bytes()), "secret display form");
        assert!(
            !contains(&bytes, display.replace('-', "").as_bytes()),
            "secret characters"
        );
        assert!(!contains(&bytes, &secret.0), "raw secret");
    }

    #[test]
    fn wrong_extensions_are_refused_and_nothing_is_created() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        for name in [
            "package",
            "package.chenroll.bak",
            "package.CHENROLL",
            "package.txt",
            ".chenroll",
        ] {
            let path = dir.path().join(name);
            let err = a.write_enrollment_package(&path).unwrap_err();
            assert!(
                matches!(enrollment_error(&err), EnrollmentError::WrongExtension),
                "{name}: {err:#}"
            );
            assert!(!path.exists(), "{name} was created");
        }
    }

    #[test]
    fn existing_file_is_refused_and_left_unchanged() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let path = package_path(&dir, "taken");
        fs::write(&path, b"original contents").unwrap();
        let err = a.write_enrollment_package(&path).unwrap_err();
        assert!(
            matches!(enrollment_error(&err), EnrollmentError::OutputExists),
            "{err:#}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"original contents");
    }

    #[test]
    fn creation_never_overwrites_a_file_that_appears_after_the_check() {
        let dir = TempDir::new().unwrap();
        let path = package_path(&dir, "raced");
        fs::write(&path, b"won the race").unwrap();
        let err = write_new_file(&path, b"package bytes").unwrap_err();
        assert!(matches!(err, EnrollmentError::OutputExists), "{err:?}");
        assert_eq!(fs::read(&path).unwrap(), b"won the race");
    }

    #[test]
    fn write_failure_reports_and_leaves_no_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing-dir").join("p.chenroll");
        let err = write_new_file(&path, b"package bytes").unwrap_err();
        assert!(matches!(err, EnrollmentError::WriteFailed(_)), "{err:?}");
        assert!(!path.exists());
    }

    #[test]
    fn locked_vault_is_refused() {
        let dir = TempDir::new().unwrap();
        let mut a = machine_a(&dir);
        a.lock();
        let path = package_path(&dir, "locked");
        let err = a.write_enrollment_package(&path).unwrap_err();
        assert_eq!(err.to_string(), "Locked");
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn package_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, _) = write_package(&a, &dir, "private");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    // ---- Package reading: stage one ----

    fn real_package() -> (Vec<u8>, TransferSecret) {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "real");
        (fs::read(&path).unwrap(), secret)
    }

    #[test]
    fn stage_one_rejects_a_file_under_67_bytes() {
        let (mut bytes, _) = real_package();
        bytes.truncate(66);
        let dir = TempDir::new().unwrap();
        let path = package_path(&dir, "small");
        fs::write(&path, &bytes).unwrap();
        let err = EnrollmentPackage::read_file(&path).unwrap_err();
        assert!(matches!(err, EnrollmentError::TooSmall { len: 66 }), "{err:?}");
        assert!(err.to_string().contains("at least 67 bytes"), "{err}");
        assert!(matches!(from_bytes_err(bytes), EnrollmentError::TooSmall { len: 66 }));
    }

    #[test]
    fn stage_one_accepts_67_bytes_and_stage_two_fails_authentication() {
        let mut bytes = enrollment_header(&[1u8; ENROLLMENT_SALT_LEN], &[2u8; NONCE_LEN]).to_vec();
        bytes.extend_from_slice(&[0u8; TAG_LEN]);
        assert_eq!(bytes.len(), 67);
        let package = EnrollmentPackage::from_bytes(bytes).unwrap();
        assert_wrong_secret(package.open(&TransferSecret::generate().unwrap()));
    }

    #[test]
    fn stage_one_rejects_a_file_over_the_cap() {
        let dir = TempDir::new().unwrap();
        let path = package_path(&dir, "huge");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_FILE_LEN + 1).unwrap();
        drop(file);
        let err = EnrollmentPackage::read_file(&path).unwrap_err();
        assert!(
            matches!(err, EnrollmentError::TooLarge { len } if len == MAX_FILE_LEN + 1),
            "{err:?}"
        );
    }

    #[test]
    fn stage_one_rejects_altered_magic() {
        let (mut bytes, _) = real_package();
        bytes[0] = b'X';
        assert!(matches!(from_bytes_err(bytes), EnrollmentError::BadMagic));
    }

    #[test]
    fn stage_one_rejects_version_2_asking_for_an_update() {
        let (mut bytes, _) = real_package();
        bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
        let err = from_bytes_err(bytes);
        assert!(
            matches!(err, EnrollmentError::UnsupportedVersion { version: 2 }),
            "{err:?}"
        );
        assert!(err.to_string().contains("Update Chamber"), "{err}");
    }

    #[test]
    fn stage_one_rejects_version_0_as_damaged() {
        let (mut bytes, _) = real_package();
        bytes[8..10].copy_from_slice(&0u16.to_be_bytes());
        let err = from_bytes_err(bytes);
        assert!(
            matches!(err, EnrollmentError::UnsupportedVersion { version: 0 }),
            "{err:?}"
        );
        assert!(!err.to_string().contains("Update Chamber"), "{err}");
    }

    #[test]
    fn stage_one_rejects_a_snapshot_file() {
        let vault_key = KeyMaterial([7u8; 32]);
        let vault_uuid = Uuid::from_bytes([0x11; 16]);
        let snapshot = encode_snapshot(
            &derive_snapshot_key(&vault_key, vault_uuid),
            vault_uuid,
            Uuid::from_bytes([0x22; 16]),
            &SyncState::default(),
        )
        .unwrap();
        let dir = TempDir::new().unwrap();
        let path = package_path(&dir, "snapshot");
        fs::write(&path, &snapshot.bytes).unwrap();
        let err = EnrollmentPackage::read_file(&path).unwrap_err();
        assert!(matches!(err, EnrollmentError::IsSnapshot), "{err:?}");
        assert!(err.to_string().contains("is a snapshot"), "{err}");
    }

    #[test]
    fn stage_one_rejects_an_unknown_package_type() {
        let (mut bytes, _) = real_package();
        bytes[10] = 9;
        assert!(matches!(
            from_bytes_err(bytes),
            EnrollmentError::UnknownPackageType { package_type: 9 }
        ));
    }

    #[test]
    fn missing_file_is_unreadable() {
        let dir = TempDir::new().unwrap();
        let err = EnrollmentPackage::read_file(&package_path(&dir, "absent")).unwrap_err();
        assert!(matches!(err, EnrollmentError::Unreadable(_)), "{err:?}");
    }

    // ---- Package reading: stage two ----

    #[test]
    fn stage_two_exposes_uuid_and_counts_and_redacts_debug() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "opened");
        let opened = open_file(&path, &secret);
        assert_eq!(opened.vault_uuid(), a.vault_uuid().unwrap());
        assert_eq!(opened.entry_count(), 3);
        assert_eq!(opened.tombstone_count(), 1);
        assert_eq!(opened.vault_key.0, a.key.as_ref().unwrap().0);
        assert_eq!(opened.state, a.export_sync_state().unwrap());

        let debug = format!("{opened:?}");
        let key = a.key.as_ref().unwrap().0;
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains(&BASE64.encode(key)), "{debug}");
        assert!(!debug.contains(&format!("{key:?}")), "{debug}");
        assert!(!debug.contains(SECRET_NAME), "{debug}");
    }

    #[test]
    fn stage_two_accepts_a_parsed_display_form() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "typed");
        let typed = TransferSecret::parse(&secret.display_form().to_lowercase()).unwrap();
        assert_eq!(open_file(&path, &typed).vault_uuid(), a.vault_uuid().unwrap());
    }

    #[test]
    fn stage_two_rejects_a_wrong_secret_and_can_be_retried() {
        let (bytes, secret) = real_package();
        let package = EnrollmentPackage::from_bytes(bytes).unwrap();
        assert_wrong_secret(package.open(&TransferSecret::generate().unwrap()));
        assert!(package.open(&secret).is_ok(), "the right secret still opens it");
    }

    #[test]
    fn stage_two_rejects_a_flipped_ciphertext_bit() {
        let (mut bytes, secret) = real_package();
        bytes[ENROLLMENT_HEADER_LEN + 1] ^= 0x01;
        assert_wrong_secret(EnrollmentPackage::from_bytes(bytes).unwrap().open(&secret));
    }

    #[test]
    fn stage_two_rejects_a_flipped_salt_bit() {
        let (mut bytes, secret) = real_package();
        bytes[SALT_OFFSET + 3] ^= 0x01;
        assert_wrong_secret(EnrollmentPackage::from_bytes(bytes).unwrap().open(&secret));
    }

    #[test]
    fn stage_two_rejects_a_flipped_nonce_bit() {
        let (mut bytes, secret) = real_package();
        bytes[NONCE_OFFSET] ^= 0x80;
        assert_wrong_secret(EnrollmentPackage::from_bytes(bytes).unwrap().open(&secret));
    }

    #[test]
    fn stage_two_rejects_a_truncated_file() {
        let (mut bytes, secret) = real_package();
        bytes.pop();
        let dir = TempDir::new().unwrap();
        let path = package_path(&dir, "truncated");
        fs::write(&path, &bytes).unwrap();
        assert_wrong_secret(EnrollmentPackage::read_file(&path).unwrap().open(&secret));
    }

    #[test]
    fn hand_built_valid_payload_is_accepted() {
        let opened = open_json(&valid_payload()).unwrap();
        assert_eq!(opened.vault_uuid().to_string(), VAULT_UUID);
        assert_eq!(opened.vault_key.0, [7u8; 32]);
        assert_eq!(opened.entry_count(), 1);
    }

    #[test]
    fn malformed_vault_uuid_is_rejected() {
        for bad in [
            VAULT_UUID.to_uppercase(),
            VAULT_UUID.replace('-', ""),
            format!("{{{VAULT_UUID}}}"),
            "not a uuid".to_string(),
        ] {
            let mut payload = valid_payload();
            payload["vault_uuid"] = json!(bad);
            assert!(
                matches!(reject_json(&payload), EnrollmentError::MalformedVaultUuid),
                "{bad}"
            );
        }
    }

    #[test]
    fn vault_key_of_31_bytes_is_rejected() {
        let mut payload = valid_payload();
        payload["vault_key"] = json!(BASE64.encode([7u8; 31]));
        assert!(matches!(reject_json(&payload), EnrollmentError::MalformedVaultKey));
        payload["vault_key"] = json!(BASE64.encode([7u8; 33]));
        assert!(matches!(reject_json(&payload), EnrollmentError::MalformedVaultKey));
    }

    #[test]
    fn vault_key_that_is_not_base64_is_rejected() {
        let mut payload = valid_payload();
        payload["vault_key"] = json!("!!not base64!!");
        assert!(matches!(reject_json(&payload), EnrollmentError::MalformedVaultKey));
        let unpadded = BASE64.encode([7u8; 32]).trim_end_matches('=').to_string();
        payload["vault_key"] = json!(unpadded);
        assert!(matches!(reject_json(&payload), EnrollmentError::MalformedVaultKey));
    }

    #[test]
    fn missing_vault_key_is_rejected_by_the_payload_rules() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("vault_key");
        assert!(matches!(
            reject_json(&payload),
            EnrollmentError::Payload(SnapshotRejection::InvalidPayload)
        ));
    }

    #[test]
    fn unknown_extra_field_is_rejected() {
        let mut payload = valid_payload();
        payload["device_id"] = json!("0d3c2f6a-91b4-4e0e-8a57-6c1f2b9d4e33");
        assert!(matches!(
            reject_json(&payload),
            EnrollmentError::Payload(SnapshotRejection::InvalidPayload)
        ));
    }

    #[test]
    fn snapshot_payload_rules_apply() {
        let mut payload = valid_payload();
        payload["entries"] = json!([entry_json(UUID_A, SECRET_NAME), entry_json(UUID_A, "other")]);
        let err = reject_json(&payload);
        assert!(
            matches!(err, EnrollmentError::Payload(SnapshotRejection::DuplicateEntry)),
            "{err:?}"
        );
        assert!(std::error::Error::source(&err).is_some(), "the rejection is the source");

        let mut payload = valid_payload();
        payload["schema"] = json!(2);
        assert!(matches!(
            reject_json(&payload),
            EnrollmentError::Payload(SnapshotRejection::InvalidPayload)
        ));

        let mut payload = valid_payload();
        payload["tombstones"] = json!([UUID_A]);
        assert!(matches!(
            reject_json(&payload),
            EnrollmentError::Payload(SnapshotRejection::EntryAndTombstone)
        ));
    }

    #[test]
    fn non_json_payload_is_rejected_without_serde_text() {
        let secret = TransferSecret::generate().unwrap();
        let bytes = seal_payload(&secret, format!("{{\"{SECRET_NAME}\": ").as_bytes());
        let err = EnrollmentPackage::from_bytes(bytes).unwrap().open(&secret).unwrap_err();
        assert!(matches!(
            err,
            EnrollmentError::Payload(SnapshotRejection::InvalidPayload)
        ));
        let message = err.to_string();
        assert!(!message.contains(SECRET_NAME), "{message}");
        assert!(!message.contains("EOF"), "{message}");
    }

    #[test]
    fn snapshot_reader_rejects_an_enrollment_package() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, _) = write_package(&a, &dir, "not-a-snapshot");
        let snapshot_key = derive_snapshot_key(a.key.as_ref().unwrap(), a.vault_uuid().unwrap());
        let rejection: Result<DecodedSnapshot, SnapshotRejection> =
            read_snapshot_file(&path, a.vault_uuid().unwrap(), &snapshot_key);
        assert!(
            matches!(
                rejection,
                Err(SnapshotRejection::WrongPackageType {
                    package_type: PACKAGE_TYPE_ENROLLMENT
                })
            ),
            "{rejection:?}"
        );
        let bytes = fs::read(&path).unwrap();
        assert!(matches!(
            decode_snapshot(&bytes, a.vault_uuid().unwrap(), &snapshot_key),
            Err(SnapshotRejection::WrongPackageType { package_type: 2 })
        ));
    }

    #[test]
    fn every_error_has_a_distinct_message_without_secrets() {
        let errors = [
            EnrollmentError::InvalidTransferSecret,
            EnrollmentError::WrongExtension,
            EnrollmentError::OutputExists,
            EnrollmentError::WriteFailed(io::Error::other("disk full")),
            EnrollmentError::Unreadable(io::Error::other("denied")),
            EnrollmentError::TooLarge { len: MAX_FILE_LEN + 1 },
            EnrollmentError::TooSmall { len: 3 },
            EnrollmentError::BadMagic,
            EnrollmentError::UnsupportedVersion { version: 2 },
            EnrollmentError::UnsupportedVersion { version: 0 },
            EnrollmentError::IsSnapshot,
            EnrollmentError::UnknownPackageType { package_type: 9 },
            EnrollmentError::WrongSecretOrDamaged,
            EnrollmentError::Payload(SnapshotRejection::DuplicateEntry),
            EnrollmentError::MalformedVaultUuid,
            EnrollmentError::MalformedVaultKey,
            EnrollmentError::AlreadyInitialized,
            EnrollmentError::VaultNotEmpty,
        ];
        let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
        for (i, message) in messages.iter().enumerate() {
            assert!(!message.is_empty());
            for other in &messages[i + 1..] {
                assert_ne!(message, other);
            }
        }
    }

    // ---- Joining ----

    #[test]
    fn full_join_reproduces_machine_a() {
        let dir = TempDir::new().unwrap();
        let mut a = machine_a(&dir);
        let mut b = fresh_vault(&dir, "b.sqlite3");
        let b_device_before = b.device_id().unwrap();
        assert!(!b.is_initialized());

        let (path, secret) = write_package(&a, &dir, "join");
        let opened = open_file(&path, &secret);
        b.join_enrollment(&opened, PASSWORD_B).unwrap();

        assert!(b.is_initialized());
        assert!(!b.is_unlocked(), "locked after the join");
        assert_eq!(b.vault_uuid().unwrap(), a.vault_uuid().unwrap());
        let b_device = b.device_id().unwrap();
        assert_ne!(b_device, a.device_id().unwrap());
        assert_ne!(b_device, b_device_before);

        assert!(b.unlock(PASSWORD_A).is_err(), "A's password does not open B");
        b.unlock(PASSWORD_B).unwrap();
        assert_eq!(b.key.as_ref().unwrap().0, a.key.as_ref().unwrap().0, "same vault key");

        let a_items = items(&a);
        assert_eq!(a_items.len(), 3);
        assert_eq!(items(&b), a_items);
        let edited = a_items.iter().find(|item| item.1 == "aws").unwrap();
        assert_eq!(edited.3, "AKIAEDITED");
        assert_eq!(b.tombstones().unwrap(), a.tombstones().unwrap());
        assert_eq!(b.tombstones().unwrap().len(), 1);

        let a_state = a.export_sync_state().unwrap();
        assert_eq!(b.export_sync_state().unwrap(), a_state);
        assert_eq!(b.high_water_mark().unwrap(), greatest_revision(&a_state));

        // The package file is left in place.
        assert!(path.exists());
        // A is unaffected and still works.
        a.lock();
        a.unlock(PASSWORD_A).unwrap();
        assert_eq!(items(&a), a_items);
    }

    #[test]
    fn create_after_join_sorts_after_every_imported_revision() {
        let dir = TempDir::new().unwrap();
        // A's clock runs years ahead of B's, so only the high-water mark orders B's write after.
        let clock = Arc::new(ManualClock::new(datetime!(2031-01-01 00:00 UTC)));
        let mut a = Vault::open_or_create_with_clock(Some(&dir.path().join("a.sqlite3")), clock).unwrap();
        a.initialize(PASSWORD_A).unwrap();
        a.unlock(PASSWORD_A).unwrap();
        populate(&mut a);

        let (path, secret) = write_package(&a, &dir, "future");
        let mut b = fresh_vault(&dir, "b.sqlite3");
        b.join_enrollment(&open_file(&path, &secret), PASSWORD_B).unwrap();
        b.unlock(PASSWORD_B).unwrap();
        add(&mut b, "made on b", ItemKind::Note, "fresh");

        let state = b.export_sync_state().unwrap();
        let created: &SyncEntry = state.entries.iter().find(|e| e.name == "made on b").unwrap();
        assert_eq!(created.revision.device_id, b.device_id().unwrap());
        for imported in a.export_sync_state().unwrap().entries {
            assert!(created.revision > imported.revision, "{created:?} vs {imported:?}");
        }
    }

    #[test]
    fn empty_package_joins_with_zero_high_water_mark() {
        let dir = TempDir::new().unwrap();
        let a = unlocked_vault(&dir, "a.sqlite3", PASSWORD_A);
        let (path, secret) = write_package(&a, &dir, "empty");
        let opened = open_file(&path, &secret);
        assert_eq!(opened.entry_count(), 0);

        let mut b = fresh_vault(&dir, "b.sqlite3");
        b.join_enrollment(&opened, PASSWORD_B).unwrap();
        assert_eq!(b.high_water_mark().unwrap(), (0, 0));
        assert_eq!(b.vault_uuid().unwrap(), a.vault_uuid().unwrap());
        b.unlock(PASSWORD_B).unwrap();
        assert!(b.list_items().unwrap().is_empty());
        assert!(b.tombstones().unwrap().is_empty());
    }

    #[test]
    fn same_package_joins_a_second_machine_with_a_third_device_id() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "twice");

        let mut b = fresh_vault(&dir, "b.sqlite3");
        b.join_enrollment(&open_file(&path, &secret), PASSWORD_B).unwrap();
        let mut c = fresh_vault(&dir, "c.sqlite3");
        c.join_enrollment(&open_file(&path, &secret), "charlie-master").unwrap();

        let devices = [a.device_id().unwrap(), b.device_id().unwrap(), c.device_id().unwrap()];
        assert_ne!(devices[0], devices[1]);
        assert_ne!(devices[0], devices[2]);
        assert_ne!(devices[1], devices[2]);
        assert_eq!(c.vault_uuid().unwrap(), a.vault_uuid().unwrap());
        c.unlock("charlie-master").unwrap();
        assert_eq!(items(&c), items(&a));
    }

    #[test]
    fn join_into_initialized_vault_is_refused_and_changes_nothing() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "refused");
        let opened = open_file(&path, &secret);

        let mut b = fresh_vault(&dir, "b.sqlite3");
        b.initialize(PASSWORD_B).unwrap();
        let before = untouched_state(&b);

        let err = b.join_enrollment(&opened, "another-master").unwrap_err();
        assert!(
            matches!(enrollment_error(&err), EnrollmentError::AlreadyInitialized),
            "{err:#}"
        );
        assert_eq!(untouched_state(&b), before);
        assert_ne!(b.vault_uuid().unwrap(), a.vault_uuid().unwrap());
        assert!(b.unlock("another-master").is_err());
        b.unlock(PASSWORD_B).unwrap();
    }

    #[test]
    fn join_with_empty_password_is_refused() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "empty-password");
        let mut b = fresh_vault(&dir, "b.sqlite3");
        let before = untouched_state(&b);

        let err = b.join_enrollment(&open_file(&path, &secret), "").unwrap_err();
        assert_eq!(err.to_string(), "Master password cannot be empty");
        assert_eq!(untouched_state(&b), before);
        assert!(!b.is_initialized());
    }

    #[test]
    fn join_into_vault_holding_rows_is_refused() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "not-empty");
        let opened = open_file(&path, &secret);

        // An uninitialized vault cannot normally hold rows; these are written below the Vault.
        let mut with_item = fresh_vault(&dir, "item.sqlite3");
        with_item
            .db
            .insert_item("stray", "note", b"n", b"c", datetime!(2026-11-17 00:00 UTC))
            .unwrap();
        let before = untouched_state(&with_item);
        let err = with_item.join_enrollment(&opened, PASSWORD_B).unwrap_err();
        assert!(
            matches!(enrollment_error(&err), EnrollmentError::VaultNotEmpty),
            "{err:#}"
        );
        assert_eq!(untouched_state(&with_item), before);

        let mut with_tombstone = fresh_vault(&dir, "tombstone.sqlite3");
        rusqlite::Connection::open(with_tombstone.db_path())
            .unwrap()
            .execute("INSERT INTO tombstones (uuid) VALUES (?1)", params![[9u8; 16]])
            .unwrap();
        let before = untouched_state(&with_tombstone);
        let err = with_tombstone.join_enrollment(&opened, PASSWORD_B).unwrap_err();
        assert!(
            matches!(enrollment_error(&err), EnrollmentError::VaultNotEmpty),
            "{err:#}"
        );
        assert_eq!(untouched_state(&with_tombstone), before);
    }

    #[test]
    fn install_rechecks_initialization_under_the_write_lock() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "raced-init");
        let opened = open_file(&path, &secret);

        // A second handle initializes the vault after the first handle's checks would pass.
        let b = fresh_vault(&dir, "b.sqlite3");
        let mut other = fresh_vault(&dir, "b.sqlite3");
        other.initialize(PASSWORD_B).unwrap();
        let before = untouched_state(&b);

        let kdf = KdfParams::default_secure();
        let derived = derive_key("x", &kdf).unwrap();
        let (wrapped, verifier) = wrap_vault_key(&derived, &opened.vault_key).unwrap();
        let err =
            b.db.install_enrollment(&kdf, &wrapped, &verifier, opened.vault_uuid, &opened.state)
                .unwrap_err();
        assert!(
            matches!(enrollment_error(&err), EnrollmentError::AlreadyInitialized),
            "{err:#}"
        );
        assert_eq!(untouched_state(&b), before);
    }

    #[test]
    fn failed_join_transaction_leaves_the_vault_as_it_was() {
        let dir = TempDir::new().unwrap();
        let a = machine_a(&dir);
        let (path, secret) = write_package(&a, &dir, "atomic");
        let opened = open_file(&path, &secret);
        assert!(opened.tombstone_count() > 0, "the package must write a tombstone");

        let mut b = fresh_vault(&dir, "b.sqlite3");
        let before = untouched_state(&b);
        rusqlite::Connection::open(b.db_path())
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_tombstone BEFORE INSERT ON tombstones \
                 BEGIN SELECT RAISE(ABORT, 'tombstone refused by test'); END;",
            )
            .unwrap();

        let err = b.join_enrollment(&opened, PASSWORD_B).unwrap_err();
        assert!(format!("{err:#}").contains("tombstone refused by test"), "{err:#}");
        assert!(!b.is_initialized());
        assert!(b.db.list_items().unwrap().is_empty(), "no entries");
        assert!(b.tombstones().unwrap().is_empty(), "no tombstones");
        assert_eq!(untouched_state(&b), before, "UUID, device ID, and high-water mark kept");
        assert!(b.unlock(PASSWORD_B).is_err(), "still not initialized");

        // No transaction was left open: once the trigger is gone the same join succeeds.
        rusqlite::Connection::open(b.db_path())
            .unwrap()
            .execute_batch("DROP TRIGGER refuse_tombstone;")
            .unwrap();
        b.join_enrollment(&opened, PASSWORD_B).unwrap();
        assert_eq!(b.vault_uuid().unwrap(), a.vault_uuid().unwrap());
    }
}
