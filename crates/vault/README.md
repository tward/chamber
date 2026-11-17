# Chamber Vault

Core vault functionality for the Chamber secrets' manager. Provides encrypted storage and retrieval of secrets using ChaCha20-Poly1305 authenticated encryption and Argon2 key derivation.

## Synchronization Support

The crate owns everything offline synchronization needs; the CLI only gathers input and prints the reports. See
[Offline Synchronization](../../README.md#offline-synchronization) in the main README for the user-facing behavior.

- **Versioned schema and migration**: the schema version lives in `PRAGMA user_version` (`SCHEMA_VERSION`, currently
  1). `Db::open` migrates a version 0 database to version 1 in one transaction without the key, and refuses a version
  newer than the binary supports without writing anything.
- **Identities**: each vault has a vault UUID and each machine a device ID (`Vault::vault_uuid`, `Vault::device_id`),
  minted at creation or migration. Every entry has a permanent UUID (`Item::uuid`). Names are not unique, and the
  `names` module (`short_uuid`, `shared_names`, `display_name`) shows same-named entries as `name (1a2b3c4d)`.
- **Revisions and tombstones on every local write**: `create_item` and `update_item` assign the next `Revision`
  (wall clock milliseconds, counter, device ID) from the stored `HighWaterMark` with `next_local_revision`, which
  stays ahead even when the clock moves backward. `delete_item` records the entry UUID as a permanent tombstone.
- **Merge of carried state**: `SyncState` holds every entry exactly as stored (still encrypted) and every tombstone.
  `Vault::export_sync_state` reads one consistently, and `Vault::merge_sync_state` merges one in a single transaction
  and returns `MergeCounts`. Tombstones always win, the greater revision wins otherwise, and equal revisions are
  settled by `content_digest`, so merging is idempotent, commutative, and associative. Merging never decrypts, never
  assigns a revision, and never reads the clock.
- **File formats**: the `snapshot` module encodes and fully validates snapshot files (`encode_snapshot`,
  `decode_snapshot`, `read_snapshot_file`), rejecting a file with a `SnapshotRejection` that names the first rule it
  broke. The `enroll` module writes and reads enrollment packages (`Vault::write_enrollment_package`,
  `EnrollmentPackage::read_file` and `open`, `Vault::join_enrollment`) sealed under a `TransferSecret`.
- **Publish and merge through a sync directory**: `Vault::publish_snapshot` and `Vault::merge_snapshots` take an
  unlocked vault and a sync directory and return a `PublishReport` or a `MergeReport`. `resolve_sync_dir` applies the
  explicit path, then `CHAMBER_SYNC_DIR` (`SYNC_DIR_ENV`), then `default_sync_dir`. Neither operation touches the
  terminal, decrypts a secret value, or writes plaintext to disk.
- **Clock seam**: item writes read the time through the `Clock` trait. `Vault::open_or_create` uses `SystemClock`,
  and `Vault::open_or_create_with_clock` accepts any clock, such as a `ManualClock` that tests set, advance, or move
  backward.

This crate is part of the [Chamber](https://github.com/mikeleppane/chamber) secrets manager ecosystem.
