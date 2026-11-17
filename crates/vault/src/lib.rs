mod autolock;
mod autolock_service;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod db;
pub mod enroll;
mod manager;
pub mod merge;
pub mod names;
mod registry;
pub mod revision;
pub mod snapshot;

// Re-export commonly used types and functions for easier access
pub use crypto::{
    HmacSha256, KdfParams, KeyMaterial, WrappedVaultKey, aead_decrypt, aead_encrypt, derive_key, hkdf_sha256,
    unwrap_vault_key, wrap_vault_key,
};

pub use clock::{Clock, ManualClock, SystemClock};
pub use db::{Db, ItemRow, SCHEMA_VERSION};
pub use merge::{MergeCounts, SyncEntry, SyncState, content_digest};
pub use names::{SHORT_UUID_LEN, display_name, shared_names, short_uuid};
pub use revision::{HighWaterMark, Revision, RevisionSpaceExhausted, next_local_revision, unix_millis};
pub use uuid::Uuid;

pub use crate::autolock::AutoLockConfig;
pub use crate::autolock_service::AutoLockCallback;
pub use crate::autolock_service::AutoLockService;
pub use crate::config::BackupConfig;
pub use crate::manager::VaultManager;
pub use crate::registry::{VaultCategory, VaultInfo, VaultRegistry};
use color_eyre::Result;
use color_eyre::eyre::Error;
use color_eyre::eyre::eyre;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use time::OffsetDateTime;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ItemKind {
    Password,
    EnvVar,
    Note,
    ApiKey,
    SshKey,
    Certificate,
    Database,
    CreditCard,
    SecureNote,
    Identity,
    BankAccount,
    Document,
    Recovery,
    OAuth,
    License,
    WifiPassword,
    Server,
}

impl FromStr for ItemKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = match s.to_lowercase().as_str() {
            "password" | "pass" | "pwd" => ItemKind::Password,
            "envvar" | "env" => ItemKind::EnvVar,
            "note" => ItemKind::Note,
            "apikey" | "api_key" | "api-key" | "token" | "api" => ItemKind::ApiKey,
            "sshkey" | "ssh" => ItemKind::SshKey,
            "certificate" | "cert" | "ssl" | "tls" => ItemKind::Certificate,
            "database" | "db" => ItemKind::Database,
            "creditcard" | "credit" | "card" => ItemKind::CreditCard,
            "securenote" | "secure" => ItemKind::SecureNote,
            "identity" | "id" | "passport" | "ssn" => ItemKind::Identity,
            "bankaccount" | "bank" | "account" => ItemKind::BankAccount,
            "document" | "doc" | "file" => ItemKind::Document,
            "recovery" | "recoverycode" | "backup" => ItemKind::Recovery,
            "oauth" | "oauth2" => ItemKind::OAuth,
            "license" | "lic" | "key" => ItemKind::License,
            "server" | "srv" | "host" => ItemKind::Server,
            "wifi" | "wifi-password" | "wifi-pass" => ItemKind::WifiPassword,
            _ => return Err(eyre!("Invalid item type: '{}'", s)),
        };
        Ok(result)
    }
}

impl ItemKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::EnvVar => "env",
            Self::Note => "note",
            Self::ApiKey => "apikey",
            Self::SshKey => "sshkey",
            Self::Certificate => "certificate",
            Self::Database => "database",
            Self::CreditCard => "creditcard",
            Self::SecureNote => "securenote",
            Self::Identity => "identity",
            Self::Server => "server",
            Self::WifiPassword => "wifi",
            Self::License => "license",
            Self::BankAccount => "bankaccount",
            Self::Document => "document",
            Self::Recovery => "recovery",
            Self::OAuth => "oauth",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [ItemKind] {
        &[
            ItemKind::Password,
            ItemKind::EnvVar,
            ItemKind::Note,
            ItemKind::ApiKey,
            ItemKind::SshKey,
            ItemKind::Certificate,
            ItemKind::Database,
            ItemKind::CreditCard,
            ItemKind::SecureNote,
            ItemKind::Identity,
            ItemKind::Server,
            ItemKind::WifiPassword,
            ItemKind::License,
            ItemKind::BankAccount,
            ItemKind::Document,
            ItemKind::Recovery,
            ItemKind::OAuth,
        ]
    }

    /// Returns a user-friendly display name
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            ItemKind::Password => "Password",
            ItemKind::EnvVar => "Environment Variable",
            ItemKind::Note => "Note",
            ItemKind::ApiKey => "API Key",
            ItemKind::SshKey => "SSH Key",
            ItemKind::Certificate => "Certificate",
            ItemKind::Database => "Database Connection",
            ItemKind::CreditCard => "Credit Card",
            ItemKind::SecureNote => "Secure Note",
            ItemKind::Identity => "Identity",
            ItemKind::Server => "Server",
            ItemKind::WifiPassword => "Wifi",
            ItemKind::License => "License",
            ItemKind::BankAccount => "Bank Account",
            ItemKind::Document => "Document",
            ItemKind::Recovery => "Recovery",
            ItemKind::OAuth => "OAuth",
        }
    }
}

/// One decrypted vault entry, as returned by [`Vault::list_items`].
///
/// `value` is the decrypted secret. `uuid` and `revision` are synchronization metadata: they
/// are not secret and are stored in plain text next to the ciphertext.
#[derive(Debug, Clone)]
pub struct Item {
    /// The local row ID. It is specific to this database file and never shared.
    pub id: u64,
    pub name: String,
    pub kind: ItemKind,
    /// The decrypted secret value.
    pub value: String,
    /// When the item was created, as recorded by the writing device's clock. Display data only.
    pub created_at: OffsetDateTime,
    /// When the item was last written, as recorded by the writing device's clock. Display data
    /// only: it may go backward after a clock rollback, while `revision` never does.
    pub updated_at: OffsetDateTime,
    /// The entry's permanent UUID, which identifies it across devices. It is minted when the
    /// entry is created (or when its vault was migrated to schema version 1) and never changes:
    /// not on edit, lock and unlock, or reopening the vault. When the entry is deleted, this
    /// UUID is what [`Vault::tombstones`] records.
    pub uuid: Uuid,
    /// The revision of the entry's latest write. Every edit assigns a greater one.
    pub revision: Revision,
}

#[derive(Debug, Clone)]
pub struct NewItem {
    pub name: String,
    pub kind: ItemKind,
    pub value: String,
}

#[derive(Debug)]
pub struct Vault {
    db: Db,
    key: Option<KeyMaterial>,
    db_path: PathBuf,
    clock: Arc<dyn Clock>,
}

impl Vault {
    /// Open an existing database or create a new one if it doesn't exist.
    ///
    /// This function initializes a database instance from a given file system path.
    /// If a path is provided, it attempts to use that specific path.
    /// If no path is provided (`None` is passed), it will determine a default database path
    /// using the `default_db_path` function.
    ///
    /// The vault reads item timestamps from [`SystemClock`], the real UTC clock. Use
    /// [`Vault::open_or_create_with_clock`] to supply a different clock.
    ///
    /// # Parameters
    /// * `path` - An optional reference to a path (`Option<&Path>`). If `Some`, the database
    ///   will be opened or created at the specified path. If `None`, a default path is used.
    ///
    /// # Returns
    /// * `Result<Self>` - On success, returns an instance of `Self` with an open database.
    ///   If any operation fails (e.g., obtaining the default path or opening the database),
    ///   an error is returned.
    ///
    /// # Errors
    /// This function returns an error if:
    /// * Obtaining the default database path via `default_db_path` fails.
    /// * Opening the database at the specified or default path fails.
    pub fn open_or_create(path: Option<&Path>) -> Result<Self> {
        Self::open_or_create_with_clock(path, Arc::new(SystemClock))
    }

    /// Open an existing database or create a new one, reading item timestamps from `clock`.
    ///
    /// Behaves exactly like [`Vault::open_or_create`] except for where the time comes from:
    /// `create_item` and `update_item` take one reading of `clock` per call and store it as
    /// the item's `created_at`/`updated_at`. Whatever the clock returns is stored as is, even a
    /// time earlier than a previous write. Clones of the returned vault share the same clock.
    ///
    /// # Parameters
    /// * `path` - An optional path to the database file. If `None`, a default path is used.
    /// * `clock` - The clock item writes read the current time from.
    ///
    /// # Errors
    /// This function returns an error if:
    /// * Obtaining the default database path via `default_db_path` fails.
    /// * Creating the database's parent directory fails.
    /// * Opening the database at the specified or default path fails.
    pub fn open_or_create_with_clock(path: Option<&Path>, clock: Arc<dyn Clock>) -> Result<Self> {
        let db_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_db_path()?,
        };

        // Ensure the parent directory exists before trying to open the database
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Db::open(&db_path)?;
        Ok(Self {
            db,
            key: None,
            db_path,
            clock,
        })
    }

    /// Opens the default instance of a resource.
    ///
    /// This function attempts to open the default instance of a resource. If the default instance
    /// does not exist, it will create a new one. The specific behavior of this function depends
    /// on the implementation of `Self::open_or_create`.
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - If successful, returns an instance of the resource wrapped in `Ok`.
    ///   If an error occurs during the opening or creation process, it returns an `Err` containing
    ///   the corresponding error.
    ///
    /// # Errors
    ///
    /// This function will return an error if the resource cannot be opened or created for any
    /// reason, such as insufficient permissions or missing configuration.
    pub fn open_default() -> Result<Self> {
        Self::open_or_create(None)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Retrieves the backup configuration for the system.
    ///
    /// This function attempts to load the backup configuration from a JSON file
    /// stored in the directory containing the database. If the configuration file
    /// does not exist, a default `BackupConfig` instance is returned.
    ///
    /// # Behavior
    ///
    /// - The configuration file is named `backup_config.json`, and its location
    ///   is inferred based on the parent directory of the `db_path` provided.
    /// - If the parent directory cannot be determined, the current directory (`"."`)
    ///   is used as the fallback location to look for the configuration file.
    /// - The function reads the contents of the file and deserializes it into a
    ///   `BackupConfig` object using `serde_json`.
    /// - If the file does not exist, the function returns the default
    ///   `BackupConfig` object.
    ///
    /// # Errors
    ///
    /// This function may return an error in the following scenarios:
    /// - If the configuration file exists, but reading its contents fails,
    ///   an `std::io::Error` is returned.
    /// - If deserialization of the file content into a `BackupConfig` object fails,
    ///   a `serde_json::Error` is returned.
    ///
    /// # Returns
    ///
    /// A `Result` wrapping the backup configuration:
    /// - `Ok(BackupConfig)` if the configuration is successfully loaded or the
    ///   default configuration is returned.
    /// - `Err` if an error occurs while reading or deserializing the configuration file.
    pub fn get_backup_config(&self) -> Result<BackupConfig> {
        // Try to read backup config from the database
        // For now, we'll store it as a JSON string in a special meta-table or file
        let config_path = self
            .db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("backup_config.json");

        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            let config: BackupConfig = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            Ok(BackupConfig::default())
        }
    }

    /// Sets the backup configuration for the database by saving it to a file named `backup_config.json`
    /// in the parent directory of the database path.
    ///
    /// The method performs the following steps:
    /// 1. Resolves the `backup_config.json` file path in the parent directory of `self.db_path`.
    /// 2. Ensures the parent directory for the file exists, creating it if necessary.
    /// 3. Serializes the `BackupConfig` object to a pretty-printed JSON string.
    /// 4. Writes the serialized JSON string to the file.
    ///
    /// # Arguments
    /// * `config` - A reference to a `BackupConfig` object containing the backup configuration settings
    ///   that will be saved to the file.
    ///
    /// # Returns
    /// * `Ok(())` if the backup configuration is successfully saved.
    /// * `Err` if any file system or serialization operation fails.
    ///
    /// # Errors
    /// This function can return an error in the following cases:
    /// * Failure to create the parent directory for the config file.
    /// * Failure to serialize the `BackupConfig` object into a JSON string.
    /// * Failure to write the serialized JSON string to the file.
    pub fn set_backup_config(&self, config: &BackupConfig) -> Result<()> {
        let config_path = self
            .db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("backup_config.json");

        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&config)?;
        std::fs::write(config_path, content)?;
        Ok(())
    }

    /// Get the database path for this vault
    pub fn get_db_path(&self) -> &std::path::Path {
        &self.db_path
    }

    pub fn is_initialized(&self) -> bool {
        !self.db.is_meta_empty().unwrap_or(false)
    }

    /// Initializes the storage system with a master key.
    ///
    /// This function is used to initialize the storage backend only if it has not been
    /// initialized already. It generates a vault key that is securely wrapped using the
    /// derived master key, and then stores the necessary metadata in the database.
    ///
    /// An empty master key is always refused, even when the vault is already initialized.
    /// Only an empty string is refused: whitespace is not trimmed and no other password rule
    /// is applied here.
    ///
    /// # Parameters
    /// - `master`: A reference to a string slice representing the master key. This key is
    ///   used as the input to derive a secure key for wrapping the vault key. It must not be
    ///   empty.
    ///
    /// # Returns
    /// - `Ok(())`: If the storage is successfully initialized or was already initialized.
    /// - `Err`: If `master` is empty, or if any step in the initialization process fails
    ///   (e.g., key derivation, key wrapping, or database write).
    ///
    /// # Implementation Details
    /// - First, the function refuses an empty `master` before doing anything else, so a
    ///   refused call writes nothing.
    /// - Next, it checks whether the storage system has already been initialized using the
    ///   `is_initialized()` method. If true, it immediately returns `Ok(())`.
    /// - The function then generates secure key derivation parameters (`KdfParams`) using
    ///   `KdfParams::default_secure()`.
    /// - Using the provided master key and the key derivation parameters, a derived key
    ///   is computed (`derive_key` function).
    /// - A new random vault key is generated (`KeyMaterial::random()`), which serves as the
    ///   key to encrypt secure data.
    /// - The vault key is securely wrapped using the derived master key, resulting in the
    ///   wrapped key and a verifier (`wrap_vault_key` function).
    /// - The derived key, wrapped vault key, and verifier are then persisted into the
    ///   database by calling `db.write_meta`.
    ///
    /// # Errors
    /// - Fails with an error if:
    ///   - `master` is empty. The error text is "Master password cannot be empty", and the
    ///     database is left unchanged.
    ///   - The master key derivation fails.
    ///   - The vault key wrapping fails.
    ///   - Writing the required metadata to the database fails.
    /// - Errors are returned as a `Result::Err`, allowing the caller to handle the failure.
    pub fn initialize(&mut self, master: &str) -> Result<()> {
        if master.is_empty() {
            return Err(eyre!("Master password cannot be empty"));
        }
        if self.is_initialized() {
            return Ok(());
        }
        let kdf = KdfParams::default_secure();
        let master_derived = derive_key(master, &kdf)?;
        let vault_key = KeyMaterial::random();
        let (wrapped, verifier) = wrap_vault_key(&master_derived, &vault_key)?;
        self.db.write_meta(&kdf, &wrapped, &verifier)?;
        Ok(())
    }

    /// Unlocks the vault using the provided master key.
    ///
    /// This function attempts to unlock a vault instance by using the given `master` key.
    /// It reads the metadata from the vault, validates the provided master key against the verifier,
    /// and upon successful verification, derives and stores the corresponding vault key.
    ///
    /// # Arguments
    ///
    /// * `master` - A string slice representing the master key used to unlock the vault.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the vault is successfully unlocked and the vault key is derived.
    /// * `Err` - If the vault metadata is uninitialized, the derived master key is invalid,
    ///   or there is an issue during the unlocking process.
    ///
    /// # Errors
    ///
    /// This function can return the following errors wrapped in a `Result`:
    /// * `eyre!("Vault not initialized")` - If the vault metadata is not present.
    /// * `eyre!("Invalid master key")` - If the provided master key is invalid or fails verification.
    /// * Other errors arising from key derivation or vault key unwrapping.
    ///
    /// # Implementation Details
    ///
    /// 1. Reads metadata from the vault, including a key derivation function (KDF) configuration (`kdf`),
    ///    a wrapped vault key (`wrapped`), and a verifier.
    /// 2. Derives a key from the provided `master` key using the KDF.
    /// 3. Verifies the derived key against the verifier. If the verification fails, returns an error.
    /// 4. Attempts to unwrap the vault key using the derived key. Upon success, stores the derived
    ///    vault key (`vk`) within the instance's `key` field.
    ///
    pub fn unlock(&mut self, master: &str) -> Result<()> {
        let (kdf, wrapped, verifier) = self.db.read_meta()?.ok_or_else(|| eyre!("Vault not initialized"))?;
        let master_derived = derive_key(master, &kdf)?;
        // Verify first
        unwrap_vault_key(&master_derived, &wrapped, Some(&verifier)).map_err(|_| eyre!("Invalid master key"))?;
        let vk = unwrap_vault_key(&master_derived, &wrapped, None)?;
        self.key = Some(vk);
        Ok(())
    }

    /// Returns this vault's UUID, which identifies the vault across devices.
    ///
    /// It is minted when the database is created or migrated to schema version 1, needs no
    /// key, and works on a locked vault.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read.
    pub fn vault_uuid(&self) -> Result<Uuid> {
        self.db.vault_uuid()
    }

    /// Returns this device's ID, which every local revision carries. Works on a locked vault.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read.
    pub fn device_id(&self) -> Result<Uuid> {
        self.db.device_id()
    }

    /// Returns the high-water mark as `(wall_ms, counter)`: the greatest pair this vault has
    /// seen in any revision. Works on a locked vault.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read.
    pub fn high_water_mark(&self) -> Result<(u64, u32)> {
        let hwm = self.db.high_water_mark()?;
        Ok((hwm.wall_ms, hwm.counter))
    }

    pub const fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// Locks the vault by dropping the in-memory vault key.
    ///
    /// The key is removed from this `Vault` and dropped. `KeyMaterial`'s `Drop` implementation
    /// zeroizes the key bytes, so no copy of the vault key remains in this value afterward.
    ///
    /// This method does not touch the database: the database handle and path are left as they
    /// are. It takes no password, returns nothing, and cannot fail.
    ///
    /// Calling it on a vault that is already locked, or was never unlocked, is a no-op.
    ///
    /// The same `Vault` can be unlocked again with [`Vault::unlock`] and the master key.
    ///
    /// Locking does not erase decrypted values a caller already holds, such as `Item` values
    /// returned earlier by [`Vault::list_items`] or [`Vault::get_item_by_name`]. Clearing those
    /// is the caller's job.
    pub fn lock(&mut self) {
        self.key = None;
    }

    /// Retrieves a list of items from the database, decrypting their stored values.
    ///
    /// # Returns
    /// - `Ok(Vec<Item>)`: A vector of decrypted items if the operation is successful.
    /// - `Err(anyhow::Error)`: An error if the database is locked, decryption fails, or another issue occurs.
    ///
    /// # Implementation Details
    /// 1. The function attempts to retrieve the encryption key (`vk`) from the `self.key` field.
    ///    If the key is unavailable, an error is returned with the message `"Locked"`.
    /// 2. The database records are fetched using `self.db.list_items()`.
    /// 3. For each record:
    ///    - The ciphertext is decrypted using `aead_decrypt` with the provided nonce, ciphertext, and additional authentication data (AAD).
    ///    - The decrypted plaintext is converted to a UTF-8 string to derive the item's `value`.
    ///    - An `Item` is constructed with the decrypted and existing meta-information, such as `id`, `name`, `kind`,
    ///      timestamps, and the entry's `uuid` and current `revision`.
    /// 4. The constructed items are aggregated into a `Vec<Item>` and returned.
    ///
    /// # Errors
    /// - Returns an error if:
    ///   - The encryption key is not available (e.g., when the data store is locked).
    ///   - The database query fails.
    ///   - The decryption operation fails (e.g., due to invalid data).
    ///   - The plaintext fails UTF-8 validation.
    ///   - An invalid `ItemKind` is provided.
    ///
    /// # Dependencies
    /// - `aead_decrypt`: A function used to decrypt the encrypted data.
    /// - `String::from_utf8`: Used to convert decrypted data into a String.
    /// - `ItemKind::from_str`: Parses the `kind` field into its corresponding `ItemKind` enum variant.
    ///
    /// # Notes
    /// - Ensure `self.key` is properly initialized before calling this method.
    /// - The database schema must provide the required fields for each item: `id`, `name`, `kind`, `ciphertext`, `nonce`, and timestamps.
    pub fn list_items(&self) -> Result<Vec<Item>> {
        let vk = self.key.as_ref().ok_or_else(|| eyre!("Locked"))?;
        let rows = self.db.list_items()?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let plaintext = aead_decrypt(vk, &r.nonce, &r.ciphertext, &r.ad())?;
            let value = String::from_utf8(plaintext)?;
            out.push(Item {
                id: r.id,
                name: r.name,
                kind: ItemKind::from_str(&r.kind)?,
                value,
                created_at: r.created_at,
                updated_at: r.updated_at,
                uuid: r.uuid,
                revision: r.revision,
            });
        }
        Ok(out)
    }

    /// Returns every item whose name equals `name` exactly (case-sensitive), in the order
    /// [`Vault::list_items`] returns them.
    ///
    /// Names are not unique: a merge can carry in entries from another device that share a
    /// name with a local entry, because the entry UUID is the identity and merging never
    /// renames. Callers that need a single item must decide among the matches themselves.
    ///
    /// # Errors
    /// Returns an error if the call to [`Vault::list_items`] fails, for example on a locked
    /// vault.
    pub fn items_by_name(&self, name: &str) -> Result<Vec<Item>> {
        let items = self.list_items()?;
        Ok(items.into_iter().filter(|i| i.name == name).collect())
    }

    /// Retrieves the one item named exactly `name`, refusing to guess when several share it.
    ///
    /// # Returns
    /// - `Ok(Some(Item))`: exactly one item has this name.
    /// - `Ok(None)`: no item has this name.
    ///
    /// # Errors
    /// Returns an error if the call to [`Vault::list_items`] fails, and also when more than one
    /// item has this name (which a merge can produce). Use [`Vault::items_by_name`] to get every
    /// match and choose among them.
    pub fn get_item_by_name(&self, name: &str) -> Result<Option<Item>> {
        let mut matches = self.items_by_name(name)?;
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.pop()),
            n => Err(eyre!("Several items are named '{name}' ({n} matches)")),
        }
    }

    /// Creates a new item and inserts it into the database.
    ///
    /// This function encrypts the value of the provided item using an AEAD encryption
    /// scheme and then stores the encrypted data, along with additional metadata, in
    /// the database. The encryption process uses the key stored within the struct and
    /// associates the encrypted value with the provided item's name and kind.
    ///
    /// # Parameters
    /// - `item`: A reference to a `NewItem`, containing the data required to create the item.
    ///
    /// # Returns
    /// - `Ok(())` on successful encryption and insertion of the item.
    /// - `Err(anyhow::Error)` if any step of the process fails, including:
    ///   - The key is not available (when the struct is in a "Locked" state).
    ///   - Failure during the encryption process.
    ///   - Errors encountered during the database insertion.
    ///
    /// # Errors
    /// This function returns an error in the following scenarios:
    /// - If the struct's `key` field is `None`, indicating it is locked.
    /// - If encryption fails for any reason.
    /// - If the database insertion fails.
    ///
    /// # Timestamps and revision
    /// `created_at` and `updated_at` are both set to one reading of the vault's clock. The same
    /// reading feeds the item's first revision, which [`Db::insert_item`] assigns from the
    /// stored high-water mark along with a new entry UUID.
    pub fn create_item(&mut self, item: &NewItem) -> Result<()> {
        let vk = self.key.as_ref().ok_or_else(|| eyre!("Locked"))?;
        let nonce_cipher = aead_encrypt(
            vk,
            item.value.as_bytes(),
            ItemRow::ad_for_name_kind(&item.name, item.kind.as_str()).as_ref(),
        )?;
        let now = self.clock.now_utc();
        self.db
            .insert_item(&item.name, item.kind.as_str(), &nonce_cipher.0, &nonce_cipher.1, now)?;
        Ok(())
    }

    /// Deletes the item with the local row ID `id` and records its entry UUID as a tombstone.
    ///
    /// # Parameters
    /// - `id` (u64): The local row ID of the item to be deleted.
    ///
    /// # Returns
    /// - `Ok(())` if the item was deleted, and also when no item has this `id` (nothing is
    ///   recorded then).
    ///
    /// # Behavior
    /// [`Db::delete_item`] removes the row and adds its UUID to the tombstones in one
    /// transaction, so either both happen or neither does. The delete assigns no revision and
    /// leaves the high-water mark unchanged. Tombstones are permanent and can be read with
    /// [`Vault::tombstones`]; creating an item under the deleted item's name later is an
    /// ordinary create with a fresh UUID, and the old tombstone stays.
    ///
    /// # Errors
    /// This function will return an error if:
    /// - The vault is locked (no vault key is loaded). This returns `eyre!("Locked")` before the
    ///   database is touched, so no tombstone is written.
    /// - There is a failure in the underlying database operation. Nothing is written then.
    pub fn delete_item(&mut self, id: u64) -> Result<()> {
        if self.key.is_none() {
            return Err(eyre!("Locked"));
        }
        self.db.delete_item(id)
    }

    /// Returns the entry UUID of every item deleted from this vault, ascending by bytes.
    ///
    /// Tombstones are plain metadata: this needs no key and works on a locked vault.
    ///
    /// # Errors
    /// Returns an error if the database cannot be read.
    pub fn tombstones(&self) -> Result<Vec<Uuid>> {
        self.db.tombstones()
    }

    /// Returns this vault's complete synchronization state: every entry exactly as stored
    /// (still encrypted) and every tombstone, read consistently. See [`Db::export_sync_state`].
    ///
    /// The key is not used beyond requiring an unlocked vault: nothing is decrypted.
    ///
    /// # Errors
    /// Returns `eyre!("Locked")` on a locked vault, before the database is touched, and
    /// otherwise any error from [`Db::export_sync_state`].
    pub fn export_sync_state(&self) -> Result<SyncState> {
        if self.key.is_none() {
            return Err(eyre!("Locked"));
        }
        self.db.export_sync_state()
    }

    /// Merges another copy's synchronization state into this vault in one transaction and
    /// reports what changed. See [`Db::merge_sync_state`] for the rules.
    ///
    /// The key is not used beyond requiring an unlocked vault: carried ciphertexts are stored
    /// as they are, without being decrypted or re-encrypted, and the clock is not read.
    ///
    /// # Errors
    /// Returns `eyre!("Locked")` on a locked vault, before the database is touched, and
    /// otherwise any error from [`Db::merge_sync_state`], in which case nothing is changed.
    pub fn merge_sync_state(&mut self, state: &SyncState) -> Result<MergeCounts> {
        if self.key.is_none() {
            return Err(eyre!("Locked"));
        }
        self.db.merge_sync_state(state)
    }

    /// Changes the master key for the vault.
    ///
    /// This function updates the master key used to protect the vault by verifying the current
    /// master key and re-encrypting the vault key using the new master key. It also updates
    /// the key derivation function (KDF) parameters for the new master key and persists the
    /// updated metadata in the database.
    ///
    /// # Arguments
    ///
    /// * `current_master` - The currently active master key used to protect the vault. This must
    ///   be provided to verify the existing setup and decrypt the vault key.
    /// * `new_master` - The new master key to which the vault will be re-encrypted. It must conform
    ///   to the same security requirements as the old master key.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` on successful master key change, or an error if the operation
    ///   fails. Possible error cases include:
    ///   - The vault is not initialized.
    ///   - The provided `current_master` key is invalid.
    ///   - Issues with deriving keys, unwrapping the vault key, or re-wrapping with the new key.
    ///   - Errors while persisting the updated metadata.
    ///
    /// # Behavior
    ///
    /// 1. Reads the current metadata (KDF parameters, wrapped key, and verifier) from the database.
    /// 2. Validates the `current_master` key using the stored KDF parameters and verifier.
    /// 3. Unwraps the vault key using the `current_master` key.
    /// 4. Generates new secure KDF parameters for the `new_master` key.
    /// 5. Derives a key from the `new_master` and wraps the vault key with it, generating a new verifier.
    /// 6. Writes the new KDF parameters, wrapped key, and verifier to the metadata in the database.
    /// 7. Updates the in-memory vault key if it is already unlocked.
    ///
    /// # Errors
    ///
    /// * Returns an error if the vault has not been initialized (e.g., no metadata exists yet).
    /// * Returns an error if the `current_master` key fails verification or cannot unwrap the vault key.
    /// * Returns an error for any issues in key operations (e.g., deriving, wrapping, or unwrapping).
    /// * Returns an error if writing the updated metadata to the database fails.
    ///
    /// # Notes
    ///
    /// The updated master key takes effect immediately upon successful execution of this function.
    /// Ensure that the `new_master` key is securely stored and managed to prevent loss of access
    /// to the vault.
    pub fn change_master_key(&mut self, current_master: &str, new_master: &str) -> Result<()> {
        let (kdf_old, wrapped_old, verifier_old) =
            self.db.read_meta()?.ok_or_else(|| eyre!("Vault not initialized"))?;

        // Verify the current master and unwrap the existing vault key
        let current_derived = derive_key(current_master, &kdf_old)?;
        let _ = unwrap_vault_key(&current_derived, &wrapped_old, Some(&verifier_old))
            .map_err(|_| eyre!("Invalid current master key"))?;
        let vault_key = unwrap_vault_key(&current_derived, &wrapped_old, None)?;

        // Generate fresh KDF params and wrap with a new master-derived key
        let kdf_new = KdfParams::default_secure();
        let new_derived = derive_key(new_master, &kdf_new)?;
        let (wrapped_new, verifier_new) = wrap_vault_key(&new_derived, &vault_key)?;

        // Persist new meta
        self.db.write_meta(&kdf_new, &wrapped_new, &verifier_new)?;

        // Keep the in-memory vault key usable if we were unlocked
        self.key = Some(vault_key);
        Ok(())
    }

    /// Updates an item in the database with a new value, preserving the item's associated metadata.
    ///
    /// # Parameters
    /// - `id`: The unique identifier of the item to be updated.
    /// - `new_value`: A reference to the new string value that will replace the current value of the item.
    ///
    /// # Returns
    /// - `Ok(())`: If the operation is successful.
    /// - `Err`: Returns an error in the following scenarios:
    ///   - If the encryption key (`self.key`) is not available (locked).
    ///   - If the specified item with the given `id` is not found in the list.
    ///   - If there's any failure during the encryption or database update.
    ///
    /// # Behavior
    /// 1. Verifies that the encryption key (`self.key`) is available. If not, an error is returned.
    /// 2. Retrieves the list of items stored and searches for the item matching the provided `id`.
    /// 3. If the item is found, constructs authenticated data (AD) using the item's metadata (name and kind).
    /// 4. Encrypts the `new_value` using the encryption key (`vk`), the new value, and the constructed AD.
    /// 5. Updates the item in the database with the newly encrypted value and its corresponding nonce.
    ///
    /// # Errors
    /// - If the encryption key is missing, an `eyre!("Locked")` error is returned.
    /// - If the item is not found, an `eyre!("Item not found")` error is returned.
    /// - Any failures during encryption or database operations propagate as errors.
    ///
    /// # Timestamps and revision
    /// `updated_at` is set to one reading of the vault's clock; `created_at` is unchanged. The
    /// same reading feeds the item's new revision, which [`Db::update_item`] assigns from the
    /// stored high-water mark. The revision is greater than every earlier one even when the
    /// clock has moved backward, while `updated_at` stores the clock reading as is.
    pub fn update_item(&mut self, id: u64, new_value: &str) -> Result<()> {
        let vk = self.key.as_ref().ok_or_else(|| eyre!("Locked"))?;

        // Get the item to preserve name and kind for AD
        let items = self.list_items()?;
        let item = items
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| eyre!("Item not found"))?;

        // Encrypt new value with same AD (name and kind)
        let nonce_cipher = aead_encrypt(
            vk,
            new_value.as_bytes(),
            ItemRow::ad_for_name_kind(&item.name, item.kind.as_str()).as_ref(),
        )?;

        let now = self.clock.now_utc();
        self.db.update_item(id, &nonce_cipher.0, &nonce_cipher.1, now)?;
        Ok(())
    }

    /// Opens an existing vault by its ID.
    ///
    /// This function attempts to load the `VaultRegistry` and retrieves the vault information
    /// associated with the given `vault_id`. If the specified vault ID does not exist in the
    /// registry, it returns an error. If found, it proceeds to open or create the vault
    /// at the associated path.
    ///
    /// # Arguments
    ///
    /// * `vault_id` - A string slice that represents the unique identifier of the vault to open.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Returns an instance of the vault if the operation succeeds.
    /// * `Err(anyhow::Error)` - Returns an error if the vault cannot be found, if the registry
    ///   fails to load, or if the vault cannot be opened or created.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following cases:
    /// - The `VaultRegistry` fails to load.
    /// - The vault with the given `vault_id` is not found
    pub fn open_by_id(vault_id: &str) -> Result<Self> {
        let registry = VaultRegistry::load()?;
        let vault_info = registry
            .get_vault(vault_id)
            .ok_or_else(|| eyre!("Vault '{}' not found", vault_id))?;

        Self::open_or_create(Some(&vault_info.path))
    }

    /// Creates a new vault with the specified parameters.
    ///
    /// # Parameters
    /// - `name`: The name of the vault to be created.
    /// - `path`: An optional `PathBuf` specifying the directory path of the vault. If `None`, a default path is used.
    /// - `category`: An instance of `VaultCategory` indicating the category for the vault (e.g., Personal, Business).
    /// - `description`: An optional description providing additional details about the vault.
    /// - `master_password`: A reference to a string containing the master password used for securing the vault.
    ///   It must not be empty.
    ///
    /// # Returns
    /// - `Ok((String, Self))`: Returns a tuple containing:
    ///     - `String`: The unique ID of the newly created vault.
    ///     - `Self`: The newly initialized vault instance.
    /// - `Err(_)`: Returns an error if the password is empty, or if the vault creation or initialization
    ///   process fails.
    ///
    /// # Errors
    /// This function may return an error in the following cases:
    /// - If `master_password` is empty. The error text is "Master password cannot be empty". This check runs
    ///   before the registry is loaded, so a refused call reads and writes nothing: no registry entry and no
    ///   vault file. Only an empty string is refused; whitespace is not trimmed.
    /// - If the `VaultRegistry` fails to load.
    /// - If the vault cannot be created in the registry (e.g., due to duplicate names or invalid paths).
    /// - If the vault cannot be opened or initialized (e.g., due to issues with the provided path or master password).
    ///
    /// # Panics
    ///
    /// # Notes
    /// - The vault ID generated is unique and can be used to reference the vault in the future.
    /// - Initializing the vault with the master password is required to securely store and access its contents.
    #[allow(clippy::expect_fun_call)]
    pub fn create_new_vault(
        name: String,
        path: Option<PathBuf>,
        category: VaultCategory,
        description: Option<String>,
        master_password: &str,
    ) -> Result<(String, Self)> {
        if master_password.is_empty() {
            return Err(eyre!("Master password cannot be empty"));
        }
        let mut registry = VaultRegistry::load()?;
        let vault_id = registry.create_vault(name, path, category, description)?;

        let vault_info = registry
            .get_vault(&vault_id)
            .expect(format!("Cannot find vault {vault_id}").as_str());
        let mut vault = Self::open_or_create(Some(&vault_info.path))?;

        // Initialize the vault with the master password
        vault.initialize(master_password)?;

        Ok((vault_id, vault))
    }

    /// Retrieves the vault ID associated with the current instance's database path (`db_path`).
    ///
    /// This function searches through the `VaultRegistry` to locate a vault entry whose path matches
    /// the `db_path` of the current instance. If a match is found, the corresponding vault ID is returned.
    /// If no match is found, `None` is returned.
    ///
    /// # Returns
    /// - `Ok(Some(String))` if a matching vault ID is found in the registry.
    /// - `Ok(None)` if no matching vault ID is found.
    /// - `Err` if there is an issue loading the `VaultRegistry`.
    ///
    /// # Errors
    /// This function may return an error if the `VaultRegistry` cannot be loaded properly.
    pub fn get_vault_id(&self) -> Result<Option<String>> {
        let registry = VaultRegistry::load()?;
        for (id, vault_info) in &registry.vaults {
            if vault_info.path == self.db_path {
                return Ok(Some(id.clone()));
            }
        }
        Ok(None)
    }

    /// Opens the currently active vault.
    ///
    /// This function retrieves the active vault from the `VaultRegistry`
    /// and attempts to open it. If no active vault is found in the registry,
    /// an error is returned. If a vault exists, it is either opened or created
    /// at the path associated with the active vault.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If the active vault is successfully opened or created.
    /// * `Err(anyhow::Error)` - If no active vault is found or an error occurs
    ///   during the opening or creation process.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following cases:
    /// - The `VaultRegistry` cannot be loaded.
    /// - No active vault exists in the registry.
    /// - An error occurs while trying to open or create the vault.
    pub fn open_active() -> Result<Self> {
        let registry = VaultRegistry::load()?;
        let active_vault = registry
            .get_active_vault()
            .ok_or_else(|| eyre!("No active vault found"))?;

        Self::open_or_create(Some(&active_vault.path))
    }
}

// Add Clone implementation for Vault if it doesn't exist
impl Clone for Vault {
    #[allow(clippy::expect_used)]
    fn clone(&self) -> Self {
        // Note: This creates a new database connection
        // The key material is not cloned for security reasons
        // The clock handle is shared, so the clone stamps items from the same clock
        Self {
            db: Db::open(&self.db_path).expect("Failed to open database connection"),
            key: None, // Don't clone the key for security
            db_path: self.db_path.clone(),
            clock: Arc::clone(&self.clock),
        }
    }
}

fn default_db_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| eyre!("No config dir"))?;
    let dir = base.join("chamber");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("vault.sqlite3"))
}

// Rust
#[cfg(test)]
mod lib_module_tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unwrap_in_result)]
    #![allow(clippy::panic)]
    #![allow(clippy::panic_in_result_fn)]
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::crypto::hex_encode;
    use std::fs;
    use std::str::FromStr;

    fn tmp_db(name: &str) -> PathBuf {
        let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let pid = std::process::id();
        std::env::temp_dir().join(format!("chamber_vault_lib_{name}_{pid}_{now}.sqlite3"))
    }

    #[test]
    fn test_itemkind_as_str_and_from_str() {
        // Round-trip known variants
        for (kind, s) in [
            (ItemKind::Password, "password"),
            (ItemKind::EnvVar, "env"),
            (ItemKind::Note, "note"),
            (ItemKind::ApiKey, "apikey"),
            (ItemKind::SshKey, "sshkey"),
            (ItemKind::Certificate, "certificate"),
            (ItemKind::Database, "database"),
        ] {
            assert_eq!(kind.as_str(), s);
            // Fuzzy forms should still parse
            assert_eq!(ItemKind::from_str(s).unwrap(), kind);
            assert_eq!(ItemKind::from_str(&s.to_uppercase()).unwrap(), kind);
        }

        // Aliases
        assert_eq!(ItemKind::from_str("pass").unwrap(), ItemKind::Password);
        assert_eq!(ItemKind::from_str("pwd").unwrap(), ItemKind::Password);
        assert_eq!(ItemKind::from_str("envvar").unwrap(), ItemKind::EnvVar);
        assert_eq!(ItemKind::from_str("api").unwrap(), ItemKind::ApiKey);
        assert_eq!(ItemKind::from_str("ssh").unwrap(), ItemKind::SshKey);
        assert_eq!(ItemKind::from_str("cert").unwrap(), ItemKind::Certificate);
        assert_eq!(ItemKind::from_str("db").unwrap(), ItemKind::Database);

        // Unknown -> Note
        assert!(ItemKind::from_str("something-else").is_err());
    }

    #[test]
    fn test_itemkind_all_and_display_names() {
        let all = ItemKind::all();
        // Ensure all variants present
        assert!(all.contains(&ItemKind::Password));
        assert!(all.contains(&ItemKind::EnvVar));
        assert!(all.contains(&ItemKind::Note));
        assert!(all.contains(&ItemKind::ApiKey));
        assert!(all.contains(&ItemKind::SshKey));
        assert!(all.contains(&ItemKind::Certificate));
        assert!(all.contains(&ItemKind::Database));

        // Display names are human-friendly and stable
        assert_eq!(ItemKind::Password.display_name(), "Password");
        assert_eq!(ItemKind::EnvVar.display_name(), "Environment Variable");
        assert_eq!(ItemKind::Note.display_name(), "Note");
        assert_eq!(ItemKind::ApiKey.display_name(), "API Key");
        assert_eq!(ItemKind::SshKey.display_name(), "SSH Key");
        assert_eq!(ItemKind::Certificate.display_name(), "Certificate");
        assert_eq!(ItemKind::Database.display_name(), "Database Connection");
    }

    #[test]
    fn test_vault_initialize_and_is_initialized() -> Result<()> {
        let path = tmp_db("init");
        let mut v = Vault::open_or_create(Some(&path))?;
        assert!(!v.is_initialized());

        v.initialize("master-1")?;
        assert!(v.is_initialized());

        // Initialize again should be no-op and not fail
        v.initialize("master-1")?;
        assert!(v.is_initialized());

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_vault_unlock_success_and_failure_paths() -> Result<()> {
        let path = tmp_db("unlock");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("secret")?;

        // Good master unlocks
        v.unlock("secret")?;

        // Wrong master returns error
        let mut v2 = Vault::open_or_create(Some(&path))?;
        let err = v2.unlock("wrong").unwrap_err().to_string();
        assert!(!err.is_empty());

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_vault_create_list_get_update_delete() -> Result<()> {
        let path = tmp_db("crud");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("m")?;
        v.unlock("m")?;

        // Initially empty
        let items = v.list_items()?;
        assert!(items.is_empty());

        // Create a few items
        v.create_item(&NewItem {
            name: "alpha".into(),
            kind: ItemKind::Password,
            value: "A1".into(),
        })?;
        v.create_item(&NewItem {
            name: "beta".into(),
            kind: ItemKind::EnvVar,
            value: "B2".into(),
        })?;

        // List sorts by name
        let items = v.list_items()?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "alpha");
        assert_eq!(items[1].name, "beta");

        // Get by name
        let got = v.get_item_by_name("alpha")?.expect("exists");
        assert_eq!(got.value, "A1");
        assert_eq!(got.kind, ItemKind::Password);

        // Update item value
        v.update_item(got.id, "A1-updated")?;
        let got2 = v.get_item_by_name("alpha")?.expect("exists");
        assert_eq!(got2.value, "A1-updated");
        assert!(got2.updated_at >= got.updated_at);

        // Delete beta
        let beta = v.get_item_by_name("beta")?.expect("exists");
        v.delete_item(beta.id)?;
        let items_after = v.list_items()?;
        assert_eq!(items_after.len(), 1);
        assert_eq!(items_after[0].name, "alpha");

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_vault_persistence_across_reopen() -> Result<()> {
        let path = tmp_db("persist");
        {
            let mut v = Vault::open_or_create(Some(&path))?;
            v.initialize("k")?;
            v.unlock("k")?;
            v.create_item(&NewItem {
                name: "one".into(),
                kind: ItemKind::Note,
                value: "first".into(),
            })?;
        }

        // Reopen and unlock, item should be there
        {
            let mut v = Vault::open_or_create(Some(&path))?;
            v.unlock("k")?;
            let items = v.list_items()?;
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].name, "one");
            assert_eq!(items[0].value, "first");
        }

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_change_master_key_preserves_items_and_allows_new_unlock() -> Result<()> {
        let path = tmp_db("change_key");

        // Initialize, add items
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("old-master")?;
        v.unlock("old-master")?;
        v.create_item(&NewItem {
            name: "svc".into(),
            kind: ItemKind::ApiKey,
            value: "token-123".into(),
        })?;

        // Change master key
        v.change_master_key("old-master", "new-master")?;

        // Old master should no longer unlock; new one should
        let mut v2 = Vault::open_or_create(Some(&path))?;
        let err = v2.unlock("old-master").unwrap_err().to_string();
        assert!(!err.is_empty());

        v2.unlock("new-master")?;
        let items = v2.list_items()?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "svc");
        assert_eq!(items[0].value, "token-123");

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_get_item_by_name_not_found() -> Result<()> {
        let path = tmp_db("get_missing");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("m")?;
        v.unlock("m")?;
        v.create_item(&NewItem {
            name: "exists".into(),
            kind: ItemKind::Note,
            value: "v".into(),
        })?;

        assert!(v.get_item_by_name("nope")?.is_none());

        fs::remove_file(path).ok();
        Ok(())
    }

    /// Asserts that every item operation on `v` is rejected with the `Locked` error.
    fn assert_item_ops_locked(v: &mut Vault, existing: &Item) {
        assert_eq!(v.list_items().unwrap_err().to_string(), "Locked");
        assert_eq!(v.get_item_by_name(&existing.name).unwrap_err().to_string(), "Locked");
        let new_item = NewItem {
            name: "lock-test-new".into(),
            kind: ItemKind::Note,
            value: "synthetic-new-value".into(),
        };
        assert_eq!(v.create_item(&new_item).unwrap_err().to_string(), "Locked");
        assert_eq!(
            v.update_item(existing.id, "synthetic-updated-value")
                .unwrap_err()
                .to_string(),
            "Locked"
        );
        assert_eq!(v.delete_item(existing.id).unwrap_err().to_string(), "Locked");
    }

    #[test]
    fn test_lock_revokes_access_and_unlock_restores_items() -> Result<()> {
        let path = tmp_db("lock_revokes");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("lock-master")?;
        v.unlock("lock-master")?;
        v.create_item(&NewItem {
            name: "lock-test-item".into(),
            kind: ItemKind::Password,
            value: "synthetic-value".into(),
        })?;

        let before = v.list_items()?;
        assert_eq!(before.len(), 1);
        let recorded = before[0].clone();

        // First lock revokes access to every item operation.
        v.lock();
        assert!(!v.is_unlocked());
        assert_item_ops_locked(&mut v, &recorded);

        // A second lock is a no-op: no panic, still locked, still rejected.
        v.lock();
        assert!(!v.is_unlocked());
        assert_item_ops_locked(&mut v, &recorded);

        // Unlocking again restores the original item, unchanged by the rejected operations.
        v.unlock("lock-master")?;
        assert!(v.is_unlocked());
        let after = v.list_items()?;
        assert_eq!(after.len(), 1);
        let item = &after[0];
        assert_eq!(item.id, recorded.id);
        assert_eq!(item.name, recorded.name);
        assert_eq!(item.kind, recorded.kind);
        assert!(
            item.value == recorded.value,
            "item value changed across lock and unlock"
        );
        assert_eq!(item.created_at, recorded.created_at);
        assert_eq!(item.updated_at, recorded.updated_at);

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_delete_item_on_locked_vault_fails_before_database() -> Result<()> {
        let path = tmp_db("lock_delete_missing");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("lock-master")?;
        v.unlock("lock-master")?;
        v.lock();

        // An id that does not exist must still report Locked, not a database or not-found error.
        let err = v.delete_item(u64::MAX).unwrap_err();
        assert_eq!(err.to_string(), "Locked");

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_lock_on_never_unlocked_vault() -> Result<()> {
        let path = tmp_db("lock_never_unlocked");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("lock-master")?;
        assert!(!v.is_unlocked());

        v.lock();
        assert!(!v.is_unlocked());

        v.unlock("lock-master")?;
        assert!(v.is_unlocked());

        fs::remove_file(path).ok();
        Ok(())
    }

    const EMPTY_PASSWORD_ERROR: &str = "Master password cannot be empty";

    /// Sorted names of the entries directly inside `dir`.
    fn dir_listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Writes vault metadata for an empty master password straight to the database, the way older
    /// versions could, without going through `initialize`.
    fn write_empty_password_meta(v: &Vault) -> Result<()> {
        let kdf = KdfParams::default_secure();
        let master_derived = derive_key("", &kdf)?;
        let vault_key = KeyMaterial::random();
        let (wrapped, verifier) = wrap_vault_key(&master_derived, &vault_key)?;
        v.db.write_meta(&kdf, &wrapped, &verifier)
    }

    #[test]
    fn test_initialize_refuses_empty_password_on_new_vault() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let mut v = Vault::open_or_create(Some(&dir.path().join("vault.db")))?;

        let err = v.initialize("").unwrap_err();
        assert_eq!(err.to_string(), EMPTY_PASSWORD_ERROR);
        assert!(!v.is_initialized());
        Ok(())
    }

    #[test]
    fn test_initialize_refuses_empty_password_on_initialized_vault() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("vault.db");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("original-master")?;

        let err = v.initialize("").unwrap_err();
        assert_eq!(err.to_string(), EMPTY_PASSWORD_ERROR);
        assert!(v.is_initialized());

        let mut reopened = Vault::open_or_create(Some(&path))?;
        reopened.unlock("original-master")?;
        assert!(reopened.is_unlocked());
        Ok(())
    }

    #[test]
    fn test_create_new_vault_refuses_empty_password_before_touching_anything() -> Result<()> {
        // The empty-password check is the first statement, so this call returns before the real
        // registry is loaded.
        let dir = tempfile::TempDir::new()?;
        let requested = dir.path().join("refused.db");
        let before = dir_listing(dir.path());

        let err = Vault::create_new_vault(
            "refused".to_string(),
            Some(requested.clone()),
            VaultCategory::Personal,
            None,
            "",
        )
        .unwrap_err();

        assert_eq!(err.to_string(), EMPTY_PASSWORD_ERROR);
        assert!(!requested.exists());
        assert_eq!(dir_listing(dir.path()), before);
        Ok(())
    }

    #[test]
    fn test_existing_empty_password_vault_still_unlocks() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("legacy.db");
        let v = Vault::open_or_create(Some(&path))?;
        write_empty_password_meta(&v)?;
        drop(v);

        let mut reopened = Vault::open_or_create(Some(&path))?;
        assert!(reopened.is_initialized());
        reopened.unlock("")?;
        assert!(reopened.is_unlocked());
        Ok(())
    }

    #[test]
    fn test_vault_debug_redacts_key_material() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("vault_debug.db");

        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("test-master")?;
        v.unlock("test-master")?;

        assert!(v.key.is_some(), "vault must be unlocked to test key formatting");

        let debug_compact = format!("{v:?}");
        let debug_pretty = format!("{v:#?}");

        assert!(
            debug_compact.contains("KeyMaterial(<redacted>)"),
            "compact must show redacted key placeholder"
        );
        assert!(
            debug_pretty.contains("KeyMaterial(<redacted>)"),
            "pretty must show redacted key placeholder"
        );

        let key_bytes = v.key.as_ref().expect("unlocked").0;
        let decimal: String = key_bytes
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let hex = hex_encode(&key_bytes);

        let output_no_ws = debug_compact.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert!(
            !output_no_ws.contains(&decimal),
            "compact output must not contain decimal bytes"
        );
        assert!(
            !output_no_ws.to_lowercase().contains(&hex),
            "compact output must not contain hex bytes"
        );

        let output_no_ws_pretty = debug_pretty.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert!(
            !output_no_ws_pretty.contains(&decimal),
            "pretty output must not contain decimal bytes"
        );
        assert!(
            !output_no_ws_pretty.to_lowercase().contains(&hex),
            "pretty output must not contain hex bytes"
        );

        dir.close()?;
        Ok(())
    }

    fn manual_vault(dir: &tempfile::TempDir, start: OffsetDateTime) -> Result<(Vault, Arc<ManualClock>)> {
        let clock = Arc::new(ManualClock::new(start));
        let path = dir.path().join("vault.sqlite3");
        let mut v = Vault::open_or_create_with_clock(Some(&path), clock.clone())?;
        v.initialize("m")?;
        v.unlock("m")?;
        Ok((v, clock))
    }

    fn new_note(name: &str) -> NewItem {
        NewItem {
            name: name.into(),
            kind: ItemKind::Note,
            value: "v".into(),
        }
    }

    #[test]
    fn test_manual_clock_create_stamps_exact_time() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06.789_012_345 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;

        v.create_item(&new_note("a"))?;

        let item = v.get_item_by_name("a")?.expect("exists");
        assert_eq!(item.created_at, t0);
        assert_eq!(item.updated_at, t0);
        Ok(())
    }

    #[test]
    fn test_manual_clock_update_after_advance_and_rollback() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("a"))?;
        let id = v.get_item_by_name("a")?.expect("exists").id;

        // Advance: updated_at follows the clock, created_at stays.
        clock.advance(time::Duration::hours(2));
        v.update_item(id, "v2")?;
        let item = v.get_item_by_name("a")?.expect("exists");
        assert_eq!(item.updated_at, t0 + time::Duration::hours(2));
        assert_eq!(item.created_at, t0);

        // Roll back to before the creation time: the earlier time is stored, not clamped.
        let earlier = t0 - time::Duration::days(1);
        clock.set(earlier);
        v.update_item(id, "v3")?;
        let item = v.get_item_by_name("a")?.expect("exists");
        assert_eq!(item.updated_at, earlier);
        assert_eq!(item.created_at, t0);
        assert_eq!(item.value, "v3");
        Ok(())
    }

    #[test]
    fn test_clone_shares_manual_clock() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (v, clock) = manual_vault(&dir, t0)?;

        let mut c = v.clone();
        c.unlock("m")?;
        let t1 = time::macros::datetime!(2030-01-01 00:00:00 UTC);
        clock.set(t1);
        c.create_item(&new_note("from-clone"))?;

        let item = v.get_item_by_name("from-clone")?.expect("exists");
        assert_eq!(item.created_at, t1);
        assert_eq!(item.updated_at, t1);
        Ok(())
    }

    #[test]
    fn test_open_or_create_uses_system_clock() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("vault.sqlite3");
        let mut v = Vault::open_or_create(Some(&path))?;
        v.initialize("m")?;
        v.unlock("m")?;

        let before = OffsetDateTime::now_utc();
        v.create_item(&new_note("sys"))?;
        let after = OffsetDateTime::now_utc();

        let item = v.get_item_by_name("sys")?.expect("exists");
        assert!(before <= item.created_at && item.created_at <= after);
        assert_eq!(item.created_at, item.updated_at);
        assert_eq!(item.created_at.offset(), time::UtcOffset::UTC);
        Ok(())
    }
    /// The stored row for `name`, with its UUID and revision.
    fn row(v: &Vault, name: &str) -> ItemRow {
        v.db.list_items()
            .unwrap()
            .into_iter()
            .find(|r| r.name == name)
            .expect("row exists")
    }

    #[test]
    fn test_sync_identifiers_readable_while_locked() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("vault.sqlite3");
        let mut v = Vault::open_or_create(Some(&path))?;
        // Before initialize: the identifiers exist and the vault is still uninitialized.
        assert!(!v.is_initialized());
        let vault_uuid = v.vault_uuid()?;
        let device_id = v.device_id()?;
        assert_ne!(vault_uuid, Uuid::nil());
        assert_ne!(device_id, Uuid::nil());
        assert_eq!(v.high_water_mark()?, (0, 0));

        v.initialize("m")?;
        v.unlock("m")?;
        let t = time::macros::datetime!(2026-02-03 04:05:06.007 UTC);
        let clock = Arc::new(ManualClock::new(t));
        let mut v = Vault::open_or_create_with_clock(Some(&path), clock)?;
        v.unlock("m")?;
        v.create_item(&new_note("a"))?;
        v.lock();

        assert!(!v.is_unlocked());
        assert_eq!(v.vault_uuid()?, vault_uuid);
        assert_eq!(v.device_id()?, device_id);
        assert_eq!(v.high_water_mark()?, (unix_millis(t), 0));
        Ok(())
    }

    #[test]
    fn test_create_and_edit_revisions_come_from_vault_clock() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06.789 UTC);
        let (mut v, clock) = manual_vault(&dir, t0)?;
        let device_id = v.device_id()?;

        v.create_item(&new_note("a"))?;
        let created = row(&v, "a");
        assert_eq!(
            created.revision,
            Revision {
                wall_ms: unix_millis(t0),
                counter: 0,
                device_id
            }
        );

        clock.advance(time::Duration::milliseconds(1));
        v.update_item(created.id, "v2")?;
        let edited = row(&v, "a");
        assert_eq!(edited.uuid, created.uuid);
        assert_eq!(
            edited.revision,
            Revision {
                wall_ms: unix_millis(t0) + 1,
                counter: 0,
                device_id
            }
        );
        assert_eq!(v.high_water_mark()?, (unix_millis(t0) + 1, 0));
        Ok(())
    }

    #[test]
    fn test_clock_rollback_edit_still_gets_greater_revision() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, clock) = manual_vault(&dir, t)?;
        v.create_item(&new_note("a"))?;
        let before = row(&v, "a");

        let earlier = t - time::Duration::hours(1);
        clock.set(earlier);
        v.update_item(before.id, "v2")?;
        let after = row(&v, "a");

        assert!(after.revision > before.revision);
        assert_eq!(after.revision.wall_ms, before.revision.wall_ms);
        assert_eq!(after.revision.counter, before.revision.counter + 1);
        assert_eq!(after.uuid, before.uuid);
        assert_eq!(after.updated_at, earlier, "updated_at shows the clock reading as is");
        assert_eq!(after.created_at, t);
        assert_eq!(v.get_item_by_name("a")?.expect("exists").value, "v2");
        Ok(())
    }

    #[test]
    fn test_future_dated_high_water_mark_orders_later_creates_after() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let present = time::macros::datetime!(2026-11-17 00:00:00 UTC);
        let future = time::macros::datetime!(2399-01-01 00:00:00 UTC);
        let (mut v, clock) = manual_vault(&dir, future)?;
        v.create_item(&new_note("from-future"))?;
        let first = row(&v, "from-future");
        assert_eq!(first.revision.wall_ms, unix_millis(future));

        clock.set(present);
        v.create_item(&new_note("from-present"))?;
        let second = row(&v, "from-present");

        assert!(second.revision > first.revision);
        assert_eq!(second.revision.wall_ms, unix_millis(future));
        assert_eq!(second.revision.counter, 1);
        assert_eq!(second.created_at, present);
        assert_ne!(second.uuid, first.uuid);
        Ok(())
    }

    #[test]
    fn test_vault_duplicate_name_still_refused() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, clock) = manual_vault(&dir, t)?;
        v.create_item(&new_note("a"))?;
        let hwm = v.high_water_mark()?;

        clock.advance(time::Duration::hours(1));
        let err = v.create_item(&new_note("a")).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(v.list_items()?.len(), 1);
        assert_eq!(v.high_water_mark()?, hwm);
        Ok(())
    }

    // ---- Entry identity and tombstones ----

    /// The listed item named `name`.
    fn listed(v: &Vault, name: &str) -> Item {
        v.get_item_by_name(name).unwrap().expect("item exists")
    }

    #[test]
    fn test_list_items_exposes_stored_uuid_and_revision() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("a"))?;
        v.create_item(&new_note("b"))?;

        for item in v.list_items()? {
            let stored = row(&v, &item.name);
            assert_eq!((item.uuid, item.revision), (stored.uuid, stored.revision));
            assert_ne!(item.uuid, Uuid::nil());
        }
        let created = listed(&v, "a");
        assert_ne!(created.uuid, listed(&v, "b").uuid);

        // Edit: same UUID, greater revision, and still what the row holds.
        clock.advance(time::Duration::seconds(1));
        v.update_item(created.id, "v2")?;
        let edited = listed(&v, "a");
        assert_eq!(edited.uuid, created.uuid);
        assert!(edited.revision > created.revision);
        let stored = row(&v, "a");
        assert_eq!((edited.uuid, edited.revision), (stored.uuid, stored.revision));

        // Lock and unlock: unchanged.
        v.lock();
        v.unlock("m")?;
        let relocked = listed(&v, "a");
        assert_eq!((relocked.uuid, relocked.revision), (edited.uuid, edited.revision));

        // Reopen the database: unchanged.
        drop(v);
        let mut v = Vault::open_or_create_with_clock(Some(&dir.path().join("vault.sqlite3")), clock)?;
        v.unlock("m")?;
        let reopened = listed(&v, "a");
        assert_eq!((reopened.uuid, reopened.revision), (edited.uuid, edited.revision));
        Ok(())
    }

    #[test]
    fn test_vault_delete_records_tombstone() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("keep"))?;
        v.create_item(&new_note("gone"))?;
        let keep = listed(&v, "keep");
        let gone = listed(&v, "gone");
        let hwm = v.high_water_mark()?;

        v.delete_item(gone.id)?;

        let remaining = v.list_items()?;
        assert_eq!(remaining.len(), 1);
        assert_eq!((remaining[0].uuid, remaining[0].revision), (keep.uuid, keep.revision));
        assert_eq!(v.tombstones()?, vec![gone.uuid]);
        assert_eq!(v.high_water_mark()?, hwm);
        Ok(())
    }

    #[test]
    fn test_delete_on_locked_vault_writes_no_tombstone() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("a"))?;
        let item = listed(&v, "a");
        v.lock();

        let err = v.delete_item(item.id).unwrap_err();
        assert_eq!(err.to_string(), "Locked");
        assert!(v.tombstones()?.is_empty());

        v.unlock("m")?;
        assert_eq!(listed(&v, "a").uuid, item.uuid, "the item is still there");
        Ok(())
    }

    #[test]
    fn test_tombstones_readable_while_locked_and_after_reopen() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("a"))?;
        let item = listed(&v, "a");
        v.delete_item(item.id)?;

        v.lock();
        assert!(!v.is_unlocked());
        assert_eq!(v.tombstones()?, vec![item.uuid]);

        drop(v);
        let v = Vault::open_or_create_with_clock(Some(&dir.path().join("vault.sqlite3")), clock)?;
        assert!(!v.is_unlocked());
        assert_eq!(v.tombstones()?, vec![item.uuid]);
        Ok(())
    }

    #[test]
    fn test_recreate_after_delete_gets_new_uuid_and_keeps_tombstone() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("reused"))?;
        let old = listed(&v, "reused");
        v.delete_item(old.id)?;

        clock.advance(time::Duration::seconds(1));
        v.create_item(&NewItem {
            name: "reused".into(),
            kind: ItemKind::Password,
            value: "second".into(),
        })?;

        let new = listed(&v, "reused");
        assert_ne!(new.uuid, old.uuid);
        assert_eq!(new.value, "second");
        assert_eq!(new.kind, ItemKind::Password);
        assert!(new.revision > old.revision);
        assert_eq!(v.list_items()?.len(), 1);
        assert_eq!(v.tombstones()?, vec![old.uuid]);
        Ok(())
    }

    #[test]
    fn test_two_deletes_record_two_tombstones_in_byte_order() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("a"))?;
        v.create_item(&new_note("b"))?;
        v.create_item(&new_note("c"))?;
        let a = listed(&v, "a");
        let c = listed(&v, "c");

        v.delete_item(c.id)?;
        v.delete_item(a.id)?;

        let mut expected = vec![a.uuid, c.uuid];
        expected.sort_by_key(|u| *u.as_bytes());
        assert_eq!(v.tombstones()?, expected);
        assert_eq!(v.list_items()?.len(), 1);
        assert_eq!(listed(&v, "b").name, "b");
        Ok(())
    }

    // ---- Synchronization state ----

    #[test]
    fn test_sync_state_methods_require_unlock() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("a"))?;
        let item = listed(&v, "a");
        let hwm = v.high_water_mark()?;
        v.lock();

        assert_eq!(v.export_sync_state().unwrap_err().to_string(), "Locked");
        let state = SyncState {
            entries: vec![SyncEntry {
                uuid: Uuid::from_bytes([0x77; 16]),
                name: "b".into(),
                kind: "note".into(),
                nonce: vec![0; 24],
                ciphertext: vec![1, 2, 3],
                created_at: t0,
                updated_at: t0,
                revision: Revision {
                    wall_ms: u64::MAX,
                    counter: 0,
                    device_id: Uuid::from_bytes([0x88; 16]),
                },
            }],
            tombstones: vec![item.uuid],
        };
        assert_eq!(v.merge_sync_state(&state).unwrap_err().to_string(), "Locked");

        // Nothing was touched: the item, the tombstones, and the high-water mark are as before.
        assert!(v.tombstones()?.is_empty());
        assert_eq!(v.high_water_mark()?, hwm);
        v.unlock("m")?;
        let items = v.list_items()?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].uuid, item.uuid);
        Ok(())
    }

    #[test]
    fn test_merge_stores_ciphertext_it_cannot_decrypt() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        let foreign = SyncEntry {
            uuid: Uuid::from_bytes([0x42; 16]),
            name: "foreign".into(),
            kind: "note".into(),
            nonce: vec![0x13; 24],
            ciphertext: b"sealed under another vault's key".to_vec(),
            created_at: t0,
            updated_at: t0,
            revision: Revision {
                wall_ms: 1_000,
                counter: 0,
                device_id: Uuid::from_bytes([0x99; 16]),
            },
        };
        let state = SyncState {
            entries: vec![foreign],
            tombstones: vec![],
        };

        let counts = v.merge_sync_state(&state)?;
        assert_eq!(
            counts,
            MergeCounts {
                added: 1,
                ..MergeCounts::default()
            }
        );
        assert_eq!(v.export_sync_state()?, state);
        assert!(
            v.list_items().is_err(),
            "the local key cannot decrypt the carried entry"
        );
        Ok(())
    }

    #[test]
    fn test_entry_copied_under_new_uuid_decrypts_alongside_original() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&NewItem {
            name: "shared".into(),
            kind: ItemKind::Password,
            value: "s3cret".into(),
        })?;

        let exported = v.export_sync_state()?;
        assert_eq!(exported.entries.len(), 1);
        let original = exported.entries[0].clone();
        let copy = SyncEntry {
            uuid: Uuid::from_bytes([0xC0; 16]),
            ..original.clone()
        };
        assert_ne!(copy.uuid, original.uuid);
        let counts = v.merge_sync_state(&SyncState {
            entries: vec![copy.clone()],
            tombstones: vec![],
        })?;
        assert_eq!(counts.added, 1);

        let items = v.list_items()?;
        assert_eq!(items.len(), 2);
        let mut uuids: Vec<Uuid> = items.iter().map(|i| i.uuid).collect();
        uuids.sort_by_key(|u| *u.as_bytes());
        let mut expected = vec![original.uuid, copy.uuid];
        expected.sort_by_key(|u| *u.as_bytes());
        assert_eq!(uuids, expected);
        for item in &items {
            assert_eq!(item.name, "shared");
            assert_eq!(item.kind, ItemKind::Password);
            assert_eq!(item.value, "s3cret");
        }
        Ok(())
    }

    // ---- Entries that share a name ----

    /// Copies the entry named `name` under `uuid` through a merge, so the vault then holds two
    /// decryptable entries with that name. Returns the UUID of the original.
    fn duplicate_via_merge(v: &mut Vault, name: &str, uuid: Uuid) -> Result<Uuid> {
        let exported = v.export_sync_state()?;
        let original = exported
            .entries
            .into_iter()
            .find(|e| e.name == name)
            .expect("entry to copy exists");
        let copy = SyncEntry {
            uuid,
            ..original.clone()
        };
        let counts = v.merge_sync_state(&SyncState {
            entries: vec![copy],
            tombstones: vec![],
        })?;
        assert_eq!(counts.added, 1);
        Ok(original.uuid)
    }

    #[test]
    fn test_items_by_name_returns_zero_one_and_two_exact_matches() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("shared"))?;
        v.create_item(&new_note("unique"))?;

        assert!(v.items_by_name("missing")?.is_empty());
        assert!(v.items_by_name("Unique")?.is_empty(), "matching is case-sensitive");
        assert!(v.items_by_name("uniq")?.is_empty(), "matching is exact, not by prefix");
        let one = v.items_by_name("unique")?;
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "unique");

        let copy = Uuid::from_bytes([0xC0; 16]);
        let original = duplicate_via_merge(&mut v, "shared", copy)?;
        let two = v.items_by_name("shared")?;
        assert_eq!(two.len(), 2);
        let mut uuids: Vec<Uuid> = two.iter().map(|i| i.uuid).collect();
        uuids.sort_by_key(|u| *u.as_bytes());
        let mut expected = vec![original, copy];
        expected.sort_by_key(|u| *u.as_bytes());
        assert_eq!(uuids, expected);
        assert!(v.items_by_name("SHARED")?.is_empty());
        Ok(())
    }

    #[test]
    fn test_get_item_by_name_none_single_and_error_on_two() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("shared"))?;
        v.create_item(&new_note("unique"))?;

        assert!(v.get_item_by_name("missing")?.is_none());
        assert_eq!(v.get_item_by_name("unique")?.expect("one match").name, "unique");

        duplicate_via_merge(&mut v, "shared", Uuid::from_bytes([0xC0; 16]))?;
        let err = v.get_item_by_name("shared").unwrap_err().to_string();
        assert!(err.contains("Several items"), "{err}");
        assert!(err.contains("'shared'"), "{err}");
        // Unrelated names still resolve.
        assert_eq!(v.get_item_by_name("unique")?.expect("one match").name, "unique");
        Ok(())
    }

    #[test]
    fn test_create_under_name_two_entries_share_is_still_refused() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("shared"))?;
        duplicate_via_merge(&mut v, "shared", Uuid::from_bytes([0xC0; 16]))?;
        let hwm = v.high_water_mark()?;

        let err = v.create_item(&new_note("shared")).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(v.items_by_name("shared")?.len(), 2);
        assert_eq!(v.high_water_mark()?, hwm);
        Ok(())
    }

    #[test]
    fn test_display_name_marks_only_shared_names_in_a_vault() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let t0 = time::macros::datetime!(2026-02-03 04:05:06 UTC);
        let (mut v, _clock) = manual_vault(&dir, t0)?;
        v.create_item(&new_note("shared"))?;
        v.create_item(&new_note("unique"))?;
        let copy = Uuid::from_bytes([0xC0; 16]);
        let original = duplicate_via_merge(&mut v, "shared", copy)?;

        let items = v.list_items()?;
        let shared = shared_names(&items);
        assert_eq!(shared.len(), 1);
        assert!(shared.contains("shared"));
        let mut shown: Vec<String> = items.iter().map(|i| display_name(i, &shared)).collect();
        shown.sort();
        let mut expected = vec![
            format!("shared ({})", short_uuid(original)),
            "shared (c0c0c0c0)".to_owned(),
            "unique".to_owned(),
        ];
        expected.sort();
        assert_eq!(shown, expected);
        Ok(())
    }
}
