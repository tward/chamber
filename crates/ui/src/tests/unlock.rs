//! Tests for `App::unlock`: every unlock and setup outcome is handled in place, both password fields are
//! wiped after each attempt, and setup mode ends once the vault is initialized.

use super::support::{
    Harness, ITEM_NAME, ITEM_VALUE, MASTER_PASSWORD, VaultState, auto_lock, harness, harness_with, press, render,
    unlock,
};
use crate::app::{Screen, wipe_items};
use chamber_vault::{AutoLockConfig, Item, ItemKind, NewItem, Revision, Uuid};
use color_eyre::eyre::eyre;
use ratatui::crossterm::event::KeyCode;
use std::time::Duration;
use time::OffsetDateTime;

const TIMEOUT_MINUTES: u64 = 5;
const TIMEOUT: Duration = Duration::from_secs(TIMEOUT_MINUTES * 60);
const LOCKED_MESSAGE: &str = "Locked due to inactivity";
const WRONG_PASSWORD: &str = "Wrong-Synthetic-99";
const LOADER_ERROR: &str = "synthetic loader failure";
const WIDTH: u16 = 140;
const HEIGHT: u16 = 40;

fn enabled() -> AutoLockConfig {
    auto_lock(true, TIMEOUT_MINUTES)
}

fn remaining(h: &Harness) -> Option<Duration> {
    h.app.time_until_auto_lock(h.clock.reading())
}

/// Types `text` into the focused unlock field, one key press at a time, through `handle_event`.
fn type_text(h: &mut Harness, text: &str) {
    for c in text.chars() {
        assert!(!press(h, KeyCode::Char(c)).expect("type key"), "typing must not quit");
    }
}

/// Presses Enter through `handle_event` and asserts the call returned `Ok(false)`, so no error reached the
/// event loop and the TUI keeps running.
fn submit(h: &mut Harness) {
    let result = press(h, KeyCode::Enter);
    assert!(
        matches!(result, Ok(false)),
        "Enter must return Ok(false), got {result:?}"
    );
}

/// Fills the setup form through key presses (master, Tab, confirm) and submits it.
fn submit_setup(h: &mut Harness, master: &str, confirm: &str) {
    type_text(h, master);
    assert!(!press(h, KeyCode::Tab).expect("tab"));
    type_text(h, confirm);
    assert!(!press(h, KeyCode::Tab).expect("tab back"));
    submit(h);
}

fn assert_inputs_empty(h: &Harness) {
    assert!(h.app.master_input.is_empty(), "master_input must be empty");
    assert!(
        h.app.master_confirm_input.is_empty(),
        "master_confirm_input must be empty"
    );
}

/// Asserts a failed attempt left the App locked with no cached items and no timer.
fn assert_failed_locked(h: &Harness) {
    assert!(!h.app.vault.is_unlocked(), "vault must stay locked");
    assert!(h.app.items.is_empty(), "items must be empty");
    assert!(h.app.filtered_items.is_empty(), "filtered_items must be empty");
    assert_eq!(remaining(h), None, "no timer expected");
    assert_eq!(h.app.screen, Screen::Unlock);
    assert_inputs_empty(h);
}

fn item_value<'a>(h: &'a Harness, name: &str) -> Option<&'a str> {
    h.app
        .items
        .iter()
        .find(|item| item.name == name)
        .map(|item| item.value.as_str())
}

#[test]
fn wrong_then_correct_password() {
    let mut h = harness(enabled());

    type_text(&mut h, WRONG_PASSWORD);
    submit(&mut h);
    assert_eq!(h.app.error.as_deref(), Some("Invalid master password"));
    assert_failed_locked(&h);

    type_text(&mut h, MASTER_PASSWORD);
    submit(&mut h);
    assert_eq!(h.app.screen, Screen::Main);
    assert_eq!(remaining(&h), Some(TIMEOUT), "a full interval expected");
    assert_eq!(item_value(&h, ITEM_NAME), Some(ITEM_VALUE));
    assert_eq!(h.app.filtered_items.len(), h.app.items.len());
    assert_eq!(h.app.error, None);
    assert_eq!(h.app.status_message, None);
    assert_inputs_empty(&h);
}

#[test]
fn success_after_lock_clears_status() {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    h.app.lock();
    assert_eq!(h.app.status_message.as_deref(), Some(LOCKED_MESSAGE));

    type_text(&mut h, MASTER_PASSWORD);
    submit(&mut h);
    assert_eq!(h.app.screen, Screen::Main);
    assert_eq!(h.app.status_message, None);
}

#[test]
fn failing_loader_leaves_app_locked_and_recoverable() {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    h.app.lock();
    assert_eq!(h.app.status_message.as_deref(), Some(LOCKED_MESSAGE));

    h.app.master_input = MASTER_PASSWORD.to_string();
    h.app.unlock_with(|_| Err(eyre!(LOADER_ERROR)));

    assert!(!h.app.vault.is_unlocked(), "vault key must be dropped");
    assert!(h.app.items.is_empty(), "items must be wiped");
    assert!(h.app.filtered_items.is_empty(), "filtered_items must be wiped");
    assert_eq!(remaining(&h), None, "no timer expected");
    assert!(h.app.countdown_info.is_none(), "no countdown expected");
    assert_eq!(
        h.app.error.as_deref(),
        Some(format!("Unlock failed: could not load items: {LOADER_ERROR}").as_str())
    );
    assert_eq!(h.app.status_message, None);
    assert_eq!(h.app.screen, Screen::Unlock);
    assert_inputs_empty(&h);

    type_text(&mut h, MASTER_PASSWORD);
    submit(&mut h);
    assert_eq!(h.app.screen, Screen::Main);
    assert!(h.app.vault.is_unlocked());
    assert_eq!(item_value(&h, ITEM_NAME), Some(ITEM_VALUE));
    assert_eq!(h.app.error, None);
}

#[test]
fn first_time_setup_then_lock_shows_unlock_form() {
    let mut h = harness_with(enabled(), VaultState::Uninitialized);
    assert!(h.app.master_mode_is_setup);

    submit_setup(&mut h, MASTER_PASSWORD, MASTER_PASSWORD);
    assert_eq!(h.app.screen, Screen::Main);
    assert!(!h.app.master_mode_is_setup, "setup mode must end after initialize");
    assert!(h.app.vault.is_initialized());
    assert!(h.app.vault.is_unlocked());
    assert_inputs_empty(&h);

    h.app
        .vault
        .create_item(&NewItem {
            name: ITEM_NAME.to_string(),
            kind: ItemKind::Password,
            value: ITEM_VALUE.to_string(),
        })
        .expect("store synthetic item");
    h.app.refresh_items().expect("refresh items");

    h.app.lock();
    assert!(!h.app.master_mode_is_setup, "lock must not bring setup mode back");
    let frame = render(&mut h.app, WIDTH, HEIGHT);
    assert!(frame.contains("Master key"), "unlock form expected");
    assert!(!frame.contains("Confirm master key"), "setup form must not be shown");

    // Only the master field is used; the confirm field stays empty.
    type_text(&mut h, MASTER_PASSWORD);
    assert!(h.app.master_confirm_input.is_empty());
    submit(&mut h);
    assert_eq!(h.app.screen, Screen::Main);
    assert_eq!(item_value(&h, ITEM_NAME), Some(ITEM_VALUE));
}

#[test]
fn setup_failures_stay_on_setup_form() {
    let mut h = harness_with(enabled(), VaultState::Uninitialized);

    submit_setup(&mut h, MASTER_PASSWORD, WRONG_PASSWORD);
    assert_eq!(h.app.error.as_deref(), Some("Passwords do not match"));
    assert_inputs_empty(&h);
    assert!(h.app.master_mode_is_setup);
    assert_eq!(h.app.screen, Screen::Unlock);
    assert!(!h.app.vault.is_initialized());

    // Shorter than eight characters: the first rule `validate_master_strength` checks.
    submit_setup(&mut h, "Ab1", "Ab1");
    assert_eq!(
        h.app.error.as_deref(),
        Some("Master key must be at least 8 characters long")
    );
    assert_inputs_empty(&h);
    assert!(h.app.master_mode_is_setup);
    assert_eq!(h.app.screen, Screen::Unlock);
    assert!(!h.app.vault.is_initialized());
}

#[test]
fn unlock_wipes_both_inputs() {
    let mut h = harness(enabled());
    h.app.master_input = MASTER_PASSWORD.to_string();
    h.app.master_confirm_input = "stray-synthetic-confirm".to_string();

    submit(&mut h);

    assert_eq!(h.app.screen, Screen::Main);
    assert_inputs_empty(&h);
}

#[test]
fn wipe_items_empties_live_buffer() {
    let now = OffsetDateTime::now_utc();
    let mut items: Vec<Item> = (0..3)
        .map(|id| Item {
            id,
            name: format!("synthetic-name-{id}"),
            kind: ItemKind::Note,
            value: format!("synthetic-value-{id}"),
            created_at: now,
            updated_at: now,
            uuid: Uuid::nil(),
            revision: Revision::default(),
        })
        .collect();

    wipe_items(&mut items);

    assert!(items.is_empty());
}
