//! Shared helpers for CLI tests: an unlocked vault in a temp directory, synthetic items, and
//! assertions that a write recorded its synchronization state (entry UUID and revision).
//!
//! Nothing here opens the default vault or the vault registry, touches the clipboard, or prompts.

use chamber_vault::{Item, ItemKind, NewItem, Vault};
use tempfile::TempDir;

/// Synthetic master password for test vaults.
pub const MASTER_PASSWORD: &str = "Synthetic-Cli-Master-42";

/// A vault in its own temp directory, initialized with `MASTER_PASSWORD` and unlocked.
///
/// Fields drop in declaration order, so the vault closes its database before the directory is
/// removed.
pub struct TestVault {
    pub vault: Vault,
    _dir: TempDir,
}

/// Builds an initialized, unlocked vault at a temp path.
pub fn unlocked_vault() -> TestVault {
    let dir = TempDir::new().expect("create temp dir");
    let mut vault = Vault::open_or_create(Some(&dir.path().join("vault.db"))).expect("create vault");
    vault.initialize(MASTER_PASSWORD).expect("initialize vault");
    vault.unlock(MASTER_PASSWORD).expect("unlock vault");
    TestVault { vault, _dir: dir }
}

/// A synthetic note item.
pub fn new_item(name: &str, value: &str) -> NewItem {
    NewItem {
        name: name.to_string(),
        kind: ItemKind::Note,
        value: value.to_string(),
    }
}

/// The listed item named `name`.
pub fn listed(vault: &Vault, name: &str) -> Item {
    vault
        .list_items()
        .expect("list items")
        .into_iter()
        .find(|i| i.name == name)
        .expect("the item is listed")
}

/// Asserts that the item named `name` was recorded as a create: a non-nil UUID shared with no
/// other item, a revision from this vault's device, and a revision equal to the high-water mark.
/// Returns the item.
pub fn assert_recorded_create(vault: &Vault, name: &str) -> Item {
    let item = assert_created_entry(vault, name);
    assert_eq!(
        (item.revision.wall_ms, item.revision.counter),
        vault.high_water_mark().expect("read high-water mark"),
        "the revision of '{name}' is the high-water mark"
    );
    item
}

/// Asserts that every item in `names` was recorded as a create in one batch that started after
/// `hwm_before`: each has a non-nil UUID distinct from every other item's, a revision from this
/// vault's device that is greater than `hwm_before`, and the greatest of those revisions equals
/// the high-water mark. Returns the items in the order of `names`.
pub fn assert_recorded_creates(vault: &Vault, names: &[&str], hwm_before: (u64, u32)) -> Vec<Item> {
    let items: Vec<Item> = names.iter().map(|name| assert_created_entry(vault, name)).collect();
    for item in &items {
        assert!(
            (item.revision.wall_ms, item.revision.counter) > hwm_before,
            "the revision of '{}' is after the high-water mark read before the batch",
            item.name
        );
    }
    let greatest = items.iter().map(|i| i.revision).max().expect("at least one item");
    assert_eq!(
        (greatest.wall_ms, greatest.counter),
        vault.high_water_mark().expect("read high-water mark"),
        "the latest revision in the batch is the high-water mark"
    );
    items
}

/// Asserts that `before`, as listed before an edit, was recorded as an edit: same UUID, a
/// strictly greater revision from this vault's device, equal to the high-water mark. Returns the
/// item as listed now.
pub fn assert_recorded_edit(vault: &Vault, before: &Item) -> Item {
    let after = listed(vault, &before.name);
    assert_eq!(after.uuid, before.uuid, "an edit keeps the entry UUID");
    assert!(after.revision > before.revision, "an edit assigns a greater revision");
    assert_eq!(
        after.revision.device_id,
        vault.device_id().expect("read device id"),
        "the edit revision names this device"
    );
    assert_eq!(
        (after.revision.wall_ms, after.revision.counter),
        vault.high_water_mark().expect("read high-water mark"),
        "the edit revision is the high-water mark"
    );
    after
}

fn assert_created_entry(vault: &Vault, name: &str) -> Item {
    let items = vault.list_items().expect("list items");
    let item = items
        .iter()
        .find(|i| i.name == name)
        .expect("the item is listed")
        .clone();
    assert!(!item.uuid.is_nil(), "the UUID of '{name}' is not nil");
    assert!(
        items.iter().filter(|i| i.uuid == item.uuid).count() == 1,
        "the UUID of '{name}' differs from every other item's"
    );
    assert_eq!(
        item.revision.device_id,
        vault.device_id().expect("read device id"),
        "the revision of '{name}' names this device"
    );
    item
}
