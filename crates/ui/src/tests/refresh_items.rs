//! Tests for `App::refresh_items`: a selection left past the end of the reloaded list is clamped to its last entry.

use super::support::{auto_lock, harness, store_item, unlock};
use chamber_vault::ItemKind;

/// Name of the second synthetic item stored on top of the harness item.
const SECOND_NAME: &str = "zz-synthetic-second-name";
/// Value of the second synthetic item stored on top of the harness item.
const SECOND_VALUE: &str = "qq-synthetic-second-value";
/// Name of the third synthetic item stored on top of the harness item.
const THIRD_NAME: &str = "zz-synthetic-third-name";
/// Value of the third synthetic item stored on top of the harness item.
const THIRD_VALUE: &str = "qq-synthetic-third-value";

#[test]
fn refresh_items_clamps_selection_past_the_end() {
    let mut h = harness(auto_lock(false, 0));
    unlock(&mut h.app);

    store_item(&mut h.app, SECOND_NAME, ItemKind::Password, SECOND_VALUE);
    store_item(&mut h.app, THIRD_NAME, ItemKind::Password, THIRD_VALUE);
    assert!(
        h.app.filtered_items.len() >= 3,
        "setup needs at least three listed items, got {}",
        h.app.filtered_items.len()
    );

    h.app.selected = h.app.filtered_items.len() - 1;

    let before = h.app.vault.list_items().expect("list items before delete").len();
    let id = h
        .app
        .items
        .iter()
        .find(|i| i.name == SECOND_NAME)
        .expect("items list holds the second item")
        .id;
    h.app
        .vault
        .delete_item(id)
        .expect("delete the second item from the vault");

    let after = h.app.vault.list_items().expect("list items after delete").len();
    assert_eq!(after, before - 1, "the vault lists one item fewer after the delete");
    assert!(
        h.app.selected >= after,
        "stale selection {} must be past the end of the {after} items the next load returns",
        h.app.selected
    );

    let result = h.app.refresh_items();
    assert!(result.is_ok(), "refresh_items must succeed: {result:?}");
    assert!(!h.app.filtered_items.is_empty(), "the reloaded list is non-empty");
    assert_eq!(
        h.app.selected,
        h.app.filtered_items.len() - 1,
        "selection is clamped to the last entry of the reloaded list"
    );
    assert!(
        h.app.selected > 0,
        "clamped selection {} must be past the first entry, so a reset to the first entry would not satisfy the test",
        h.app.selected
    );
}
