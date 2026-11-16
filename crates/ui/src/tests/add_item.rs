//! Tests for the add-item flow: after a successful save the editor is wiped and rebuilt with startup configuration.

use super::support::{
    Harness, assert_editor_fresh, assert_editor_settings_match_fresh_app, auto_lock, harness, unlock,
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
