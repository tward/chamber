//! Tests that every TUI write records synchronization state: a create mints an entry UUID and a revision, an edit
//! assigns a greater revision under the same UUID, and a delete leaves a tombstone.

use super::support::{ITEM_NAME, auto_lock, harness, store_item, unlock};
use crate::app::{ImportExportMode, Screen};
use chamber_import_export::{ExportFormat, export_items};
use chamber_vault::{Item, ItemKind, Revision, Uuid, Vault};
use time::OffsetDateTime;

/// The listed item named `name`.
fn listed(vault: &Vault, name: &str) -> Item {
    vault
        .list_items()
        .expect("list items")
        .into_iter()
        .find(|i| i.name == name)
        .expect("the item is listed")
}

/// Asserts the item named `name` has a non-nil UUID shared with no other item and a revision from this vault's
/// device. Returns the item.
fn assert_created_entry(vault: &Vault, name: &str) -> Item {
    let items = vault.list_items().expect("list items");
    let item = items
        .iter()
        .find(|i| i.name == name)
        .expect("the created item is listed")
        .clone();
    assert!(!item.uuid.is_nil(), "the UUID of '{name}' is not nil");
    assert_eq!(
        items.iter().filter(|i| i.uuid == item.uuid).count(),
        1,
        "the UUID of '{name}' differs from every other item's"
    );
    assert_eq!(
        item.revision.device_id,
        vault.device_id().expect("read device id"),
        "the revision of '{name}' names this device"
    );
    item
}

/// Asserts the item named `name` was recorded as a create whose revision is the high-water mark.
fn assert_recorded_create(vault: &Vault, name: &str) -> Item {
    let item = assert_created_entry(vault, name);
    assert_eq!(
        (item.revision.wall_ms, item.revision.counter),
        vault.high_water_mark().expect("read high-water mark"),
        "the revision of '{name}' is the high-water mark"
    );
    item
}

#[test]
fn add_item_records_a_create() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);
    let hwm_before = h.app.vault.high_water_mark().expect("read high-water mark");

    h.app.screen = Screen::AddItem;
    h.app.add_name = "zz-tui-added".to_string();
    assert!(h.app.add_value_textarea.insert_str("qq-tui-added-value"));
    h.app.add_item().expect("add_item");

    let added = assert_recorded_create(&h.app.vault, "zz-tui-added");
    assert_eq!(added.value, "qq-tui-added-value");
    assert!(
        (added.revision.wall_ms, added.revision.counter) > hwm_before,
        "the create moves the high-water mark forward"
    );
}

#[test]
fn save_edit_records_an_edit() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);
    let before = listed(&h.app.vault, ITEM_NAME);

    h.app.selected = h
        .app
        .filtered_items
        .iter()
        .position(|i| i.name == ITEM_NAME)
        .expect("the synthetic item is in the list");
    h.app.edit_selected();
    assert_eq!(h.app.screen, Screen::EditItem);
    h.app.edit_value = "qq-tui-edited-value".to_string();
    h.app.save_edit().expect("save_edit");

    assert_eq!(h.app.screen, Screen::Main, "save_edit returns to the main screen");
    let after = listed(&h.app.vault, ITEM_NAME);
    assert_eq!(after.value, "qq-tui-edited-value", "the entry holds the new value");
    assert_eq!(after.uuid, before.uuid, "an edit keeps the entry UUID");
    assert!(after.revision > before.revision, "an edit assigns a greater revision");
    assert_eq!(
        after.revision.device_id,
        h.app.vault.device_id().expect("read device id"),
        "the edit revision names this device"
    );
    assert_eq!(
        (after.revision.wall_ms, after.revision.counter),
        h.app.vault.high_water_mark().expect("read high-water mark"),
        "the edit revision is the high-water mark"
    );
}

#[test]
fn delete_selected_records_a_delete() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);
    store_item(&mut h.app, "zz-tui-kept", ItemKind::Note, "qq-tui-kept-value");
    let deleted = listed(&h.app.vault, ITEM_NAME);
    let kept = listed(&h.app.vault, "zz-tui-kept");

    h.app.selected = h
        .app
        .filtered_items
        .iter()
        .position(|i| i.name == ITEM_NAME)
        .expect("the synthetic item is in the list");
    h.app.delete_selected().expect("delete_selected");

    let items = h.app.vault.list_items().expect("list items");
    assert!(
        items.iter().all(|i| i.uuid != deleted.uuid && i.id != deleted.id),
        "the deleted item is no longer listed"
    );
    assert_eq!(
        h.app.vault.tombstones().expect("read tombstones"),
        [deleted.uuid],
        "the deleted item's UUID is the only tombstone"
    );
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].uuid, kept.uuid, "the other item stays");
}

/// A synthetic item to write into an import file. Its UUID and revision are placeholders the export ignores.
fn export_entry(name: &str, value: &str) -> Item {
    let now = OffsetDateTime::now_utc();
    Item {
        id: 0,
        name: name.to_string(),
        kind: ItemKind::Note,
        value: value.to_string(),
        created_at: now,
        updated_at: now,
        uuid: Uuid::nil(),
        revision: Revision::default(),
    }
}

#[test]
fn import_records_each_imported_item_as_a_create() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);
    let existing = listed(&h.app.vault, ITEM_NAME);
    let hwm_before = h.app.vault.high_water_mark().expect("read high-water mark");

    let file = h.dir.path().join("import.json");
    let entries = [
        export_entry("zz-tui-import-1", "qq-tui-import-value-1"),
        export_entry(ITEM_NAME, "qq-tui-replacement-value"),
        export_entry("zz-tui-import-2", "qq-tui-import-value-2"),
    ];
    export_items(&entries, &ExportFormat::Json, &file).expect("write import file");

    h.app.open_import_export(ImportExportMode::Import);
    h.app.ie_path = file.to_string_lossy().into_owned();
    h.app.ie_format_idx = h
        .app
        .ie_formats
        .iter()
        .position(|f| *f == "json")
        .expect("json is a format");
    h.app.execute_import_export().expect("execute_import_export");

    assert_eq!(h.app.error.as_deref(), Some("Imported 2 items, skipped 1"));
    let names = ["zz-tui-import-1", "zz-tui-import-2"];
    let imported: Vec<Item> = names.iter().map(|n| assert_created_entry(&h.app.vault, n)).collect();
    for item in &imported {
        assert!(
            (item.revision.wall_ms, item.revision.counter) > hwm_before,
            "the revision of '{}' is after the high-water mark read before the import",
            item.name
        );
        assert_ne!(item.uuid, existing.uuid, "imported entries get UUIDs of their own");
    }
    let greatest = imported.iter().map(|i| i.revision).max().expect("two imported items");
    assert_eq!(
        (greatest.wall_ms, greatest.counter),
        h.app.vault.high_water_mark().expect("read high-water mark"),
        "the latest import revision is the high-water mark"
    );

    let kept = listed(&h.app.vault, ITEM_NAME);
    assert_eq!(kept.uuid, existing.uuid, "the skipped entry keeps its UUID");
    assert_eq!(kept.revision, existing.revision, "the skipped entry keeps its revision");
}
