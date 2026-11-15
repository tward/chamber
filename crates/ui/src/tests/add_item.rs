//! Tests for the add-item flow: after a successful save the editor is wiped and rebuilt with startup configuration.

use super::support::{Harness, assert_editor_fresh, assert_editor_settings_match_fresh_app, unlock};
use chamber_vault::AutoLockConfig;

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

fn disabled_config() -> AutoLockConfig {
    super::support::auto_lock(false, 0)
}

#[test]
fn ac8_add_item_wipes_editor() {
    let mut h = Harness {
        app: super::support::harness(disabled_config()).app,
        clock: super::support::TestClock::new(),
        clipboard: super::support::TestClipboard::new(),
        dir: tempfile::TempDir::new().expect("create temp dir"),
    };

    unlock(&mut h.app);
    fill_editor(&mut h);

    h.app.add_name = "test-item".to_string();

    let result = h.app.add_item();
    assert!(result.is_ok(), "add_item must succeed");

    let stored = h.app.vault.list_items().expect("list stored items");
    let added = stored.iter().find(|i| i.name == "test-item").expect("added item");
    assert_eq!(added.value, "qqeditorvalue", "vault holds added item value");
    assert!(
        h.app.items.iter().any(|i| i.name == "test-item"),
        "items list holds added item"
    );

    assert_editor_fresh(&mut h.app);
    assert_editor_settings_match_fresh_app(&h.app);
}
