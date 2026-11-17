//! Tests for the main list with entries that share a name: each is shown as `name (suffix)`, where the suffix is
//! the first 8 hexadecimal characters of its UUID, while a uniquely named entry is shown by its bare name.

use super::support::{ITEM_NAME, auto_lock, harness, render, store_item, unlock};
use chamber_vault::{ItemKind, SyncEntry, SyncState, Uuid, short_uuid};

/// Name shared by two synthetic entries.
const SHARED_NAME: &str = "zz-synthetic-shared-name";
/// Value of the first entry with the shared name.
const SHARED_VALUE: &str = "qq-synthetic-shared-value";
/// UUID given to the merged copy of the shared entry.
const COPY_UUID: Uuid = Uuid::from_bytes([0xC0; 16]);

/// Merges a copy of the entry named `name` under `uuid` into the App's vault, as an entry carried from another
/// device would arrive, and reloads the App's items.
fn merge_copy(app: &mut crate::app::App, name: &str, uuid: Uuid) {
    let original = app
        .vault
        .export_sync_state()
        .expect("export sync state")
        .entries
        .into_iter()
        .find(|e| e.name == name)
        .expect("the entry to copy exists");
    let counts = app
        .vault
        .merge_sync_state(&SyncState {
            entries: vec![SyncEntry { uuid, ..original }],
            tombstones: vec![],
        })
        .expect("merge the copy");
    assert_eq!(counts.added, 1, "the copy is added");
    app.refresh_items().expect("reload items");
}

/// Whether some occurrence of `name` on `screen` is followed by ` (` and 8 hexadecimal characters and `)`.
fn has_uuid_suffix(screen: &str, name: &str) -> bool {
    screen.match_indices(name).any(|(at, _)| {
        let rest = &screen[at + name.len()..];
        rest.strip_prefix(" (").is_some_and(|tail| {
            tail.len() > 8 && tail[..8].bytes().all(|b| b.is_ascii_hexdigit()) && tail.as_bytes()[8] == b')'
        })
    })
}

#[test]
fn main_list_marks_entries_that_share_a_name_with_their_uuid_suffix() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);
    store_item(&mut h.app, SHARED_NAME, ItemKind::Password, SHARED_VALUE);
    let original = h
        .app
        .items
        .iter()
        .find(|i| i.name == SHARED_NAME)
        .expect("the shared entry is listed")
        .uuid;
    merge_copy(&mut h.app, SHARED_NAME, COPY_UUID);
    assert_eq!(h.app.items.iter().filter(|i| i.name == SHARED_NAME).count(), 2);

    let screen = render(&mut h.app, 160, 40);

    let original_label = format!("{SHARED_NAME} ({})", short_uuid(original));
    let copy_label = format!("{SHARED_NAME} (c0c0c0c0)");
    assert!(screen.contains(&original_label), "missing {original_label:?}");
    assert!(screen.contains(&copy_label), "missing {copy_label:?}");
    assert!(screen.contains(ITEM_NAME), "the uniquely named entry is listed");
    assert!(
        !has_uuid_suffix(&screen, ITEM_NAME),
        "the uniquely named entry has no suffix"
    );
    assert!(has_uuid_suffix(&screen, SHARED_NAME));
    assert!(!screen.contains(SHARED_VALUE), "no secret value is drawn");
}

#[test]
fn main_list_keeps_the_suffix_when_the_search_hides_the_namesake() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);
    store_item(&mut h.app, SHARED_NAME, ItemKind::Password, SHARED_VALUE);
    merge_copy(&mut h.app, SHARED_NAME, COPY_UUID);

    // Leave only the copy in the filtered view, as a narrowing filter would; `app.items` still holds both.
    h.app.filtered_items.retain(|i| i.uuid == COPY_UUID);
    h.app.selected = 0;
    assert_eq!(h.app.filtered_items.len(), 1);

    let screen = render(&mut h.app, 160, 40);
    assert!(
        screen.contains(&format!("{SHARED_NAME} (c0c0c0c0)")),
        "the copy keeps its suffix"
    );
}
