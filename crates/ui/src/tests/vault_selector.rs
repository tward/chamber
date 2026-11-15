//! Tests for the vault selector's create form: submitting it creates no vault, because the selector has no
//! way to ask for the new vault's master password. It shows a fixed message pointing to the CLI instead.
//!
//! Everything runs against the isolated harness from `support.rs`, with key presses sent through
//! `handle_event`.

use super::support::{Harness, auto_lock, harness, press, unlock};
use crate::app::Screen;
use crate::vault_selector::VaultSelectorMode;
use ratatui::crossterm::event::KeyCode;
use std::path::{Path, PathBuf};

/// The exact message the selector shows, backticks included.
const CREATE_UNAVAILABLE: &str = "Creating a vault here needs a master password prompt, which is not available yet. \
                                  Use `chamber registry create` instead.";
const VAULT_NAME: &str = "zz-synthetic-new-vault";

/// Sorted paths, relative to `root`, of every file and directory below it.
fn tree_listing(root: &Path) -> Vec<PathBuf> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            out.push(path.strip_prefix(root).expect("relative path").to_path_buf());
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// Sorted (id, name, path) of every entry in the App's registry.
fn registry_entries(h: &Harness) -> Vec<(String, String, PathBuf)> {
    let mut entries: Vec<_> = h
        .app
        .vault_manager
        .registry
        .vaults
        .iter()
        .map(|(id, info)| (id.clone(), info.name.clone(), info.path.clone()))
        .collect();
    entries.sort();
    entries
}

/// Presses `code` through `handle_event` and asserts the call returned `Ok(false)`.
fn press_ok(h: &mut Harness, code: KeyCode) {
    let result = press(h, code);
    assert!(
        matches!(result, Ok(false)),
        "{code:?} must return Ok(false), got {result:?}"
    );
}

#[test]
fn create_from_selector_shows_message_and_creates_nothing() {
    let mut h = harness(auto_lock(false, 5));
    unlock(&mut h.app);

    let registry_path = h.app.vault_manager.registry.registry_path.clone();
    let registry_existed = registry_path.exists();
    let registry_before = registry_existed.then(|| std::fs::read(&registry_path).expect("read registry"));
    let entries_before = registry_entries(&h);
    let listing_before = tree_listing(h.dir.path());

    // Open the selector and start a new vault.
    press_ok(&mut h, KeyCode::F(2));
    assert_eq!(h.app.screen, Screen::VaultSelector);
    press_ok(&mut h, KeyCode::Char('n'));
    assert_eq!(h.app.vault_selector.mode, VaultSelectorMode::Create);

    // Name, then confirm the description and the category.
    for c in VAULT_NAME.chars() {
        press_ok(&mut h, KeyCode::Char(c));
    }
    press_ok(&mut h, KeyCode::Enter);
    press_ok(&mut h, KeyCode::Enter);
    press_ok(&mut h, KeyCode::Enter);

    assert_eq!(h.app.vault_selector.error_message.as_deref(), Some(CREATE_UNAVAILABLE));
    assert_eq!(h.app.vault_selector.mode, VaultSelectorMode::Create);
    assert_eq!(h.app.screen, Screen::VaultSelector);

    assert_eq!(registry_entries(&h), entries_before);
    assert_eq!(
        registry_path.exists(),
        registry_existed,
        "registry file must not be created"
    );
    if let Some(before) = registry_before {
        assert_eq!(std::fs::read(&registry_path).expect("read registry"), before);
    }
    assert_eq!(
        tree_listing(h.dir.path()),
        listing_before,
        "no new files in the temp directory"
    );

    let status = h.app.status_message.as_deref().unwrap_or_default();
    assert!(
        !status.contains("Created vault"),
        "status must not report a created vault: {status}"
    );
}
