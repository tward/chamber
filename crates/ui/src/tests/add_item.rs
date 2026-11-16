//! Tests for the add-item flow: after a successful save the editor is wiped and rebuilt with startup configuration.

use super::support::{
    Harness, ITEM_NAME, ITEM_VALUE, assert_editor_fresh, assert_editor_settings_match_fresh_app, auto_lock, harness,
    unlock,
};
use crate::app::{Screen, StatusType};

/// Fills the add-item value editor with undo history and yank content, leaving the draft value in place.
fn fill_editor(h: &mut Harness) {
    let editor = &mut h.app.add_value_textarea;
    assert!(editor.insert_str("qqeditorcut"));
    editor.select_all();
    assert!(editor.cut());
    assert!(editor.insert_str("qqeditorvalue"));
    assert_eq!(editor.yank_text(), "qqeditorcut");
    assert_eq!(editor.lines(), ["qqeditorvalue"]);
}

#[test]
fn add_item_success_wipes_and_rebuilds_editor() {
    let mut h = harness(auto_lock(false, 0));

    unlock(&mut h.app);
    h.app.screen = Screen::AddItem;
    fill_editor(&mut h);

    h.app.add_name = "test-item".to_string();

    let result = h.app.add_item();
    assert!(result.is_ok(), "add_item must succeed");

    let stored = h.app.vault.list_items().expect("list stored items");
    let added = stored.iter().find(|i| i.name == "test-item").expect("added item");
    assert_eq!(added.value, "qqeditorvalue", "vault holds added item value");
    let cached = h
        .app
        .items
        .iter()
        .find(|i| i.name == "test-item")
        .expect("items list holds added item");
    assert_eq!(cached.value, "qqeditorvalue", "items list holds added item value");

    assert_eq!(h.app.screen, Screen::Main, "add_item returns to the main screen");
    assert_eq!(
        h.app.error.as_deref(),
        Some("Item added."),
        "add_item sets the confirmation text"
    );
    assert_eq!(
        h.app.status_message.as_deref(),
        Some("Item added successfully."),
        "add_item sets the status message"
    );
    assert_eq!(h.app.status_type, StatusType::Success, "add_item sets a success status");

    assert_editor_fresh(&mut h.app);
    assert_editor_settings_match_fresh_app(&h.app);
}

#[test]
fn add_item_duplicate_name_warns_and_keeps_the_draft() {
    let mut h = harness(auto_lock(false, 0));

    unlock(&mut h.app);
    h.app.screen = Screen::AddItem;
    fill_editor(&mut h);

    h.app.add_name = ITEM_NAME.to_string();

    let result = h.app.add_item();
    assert!(result.is_ok(), "add_item reports a duplicate name without failing");

    let expected_error = format!("Item '{ITEM_NAME}' already exists.");
    assert_eq!(
        h.app.error.as_deref(),
        Some(expected_error.as_str()),
        "add_item sets the duplicate-name text"
    );
    let expected_status = format!("Item '{ITEM_NAME}' already exists. Please choose a different name.");
    assert_eq!(
        h.app.status_message.as_deref(),
        Some(expected_status.as_str()),
        "add_item sets the duplicate-name status message"
    );
    assert_eq!(h.app.status_type, StatusType::Warning, "add_item sets a warning status");
    assert_eq!(h.app.screen, Screen::AddItem, "add_item stays on the add-item screen");
    assert_eq!(
        h.app.add_value_textarea.lines(),
        ["qqeditorvalue"],
        "add_item keeps the draft value in the editor"
    );

    let stored = h.app.vault.list_items().expect("list stored items");
    let matching: Vec<_> = stored.iter().filter(|i| i.name == ITEM_NAME).collect();
    assert_eq!(
        matching.len(),
        1,
        "vault holds exactly one item with the duplicate name"
    );
    assert_eq!(matching[0].value, ITEM_VALUE, "vault keeps the original item value");
}
