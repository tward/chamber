//! Tests for the clipboard step of `App::lock`: a value Chamber copied this session is cleared at lock while
//! the clipboard still holds it, anything else is left alone, an unreadable clipboard is cleared anyway, and
//! after every lock the digest is gone and the retained handle is released.
//!
//! Every test uses the clipboard double from `support.rs`; none touches a desktop clipboard.

use super::support::{
    ClipboardCall, Harness, ITEM_NAME, ITEM_VALUE, ReadBehavior, auto_lock, harness, press, store_item, unlock,
};
use crate::app::{Screen, StatusType};
use chamber_vault::ItemKind;
use ratatui::crossterm::event::KeyCode;

const TIMEOUT_MINUTES: u64 = 5;
const LOCKED_MESSAGE: &str = "Locked due to inactivity";
const CLEAR_FAILED_MESSAGE: &str = "Locked due to inactivity. Clipboard could not be cleared.";

/// Second stored item, copied after the first to replace the digest.
const SECOND_NAME: &str = "zz-synthetic-second-name";
const SECOND_VALUE: &str = "QQSECONDCLIPVAL";
/// Text another application puts on the clipboard.
const OTHER_TEXT: &str = "QQOTHERAPPTEXT";

/// A harness on the main screen with the synthetic item loaded.
fn unlocked() -> Harness {
    let mut h = harness(auto_lock(true, TIMEOUT_MINUTES));
    unlock(&mut h.app);
    h
}

/// Index of the item named `name` in the App's filtered list.
fn index_of(h: &Harness, name: &str) -> usize {
    h.app
        .filtered_items
        .iter()
        .position(|i| i.name == name)
        .expect("item is listed")
}

/// Selects the item named `name` and copies it through `copy_selected`.
fn copy_named(h: &mut Harness, name: &str) {
    h.app.selected = index_of(h, name);
    h.app.copy_selected().expect("copy succeeds");
}

/// Unlocks and copies the synthetic item, asserting it reached the double and a digest is stored.
fn unlocked_with_copy() -> Harness {
    let mut h = unlocked();
    copy_named(&mut h, ITEM_NAME);
    assert_eq!(h.clipboard.content().as_deref(), Some(ITEM_VALUE));
    assert!(h.app.clipboard_digest_stored());
    h
}

/// Asserts the status the lock set.
fn assert_status(h: &Harness, message: &str, status_type: StatusType) {
    assert_eq!(h.app.status_message.as_deref(), Some(message));
    assert_eq!(h.app.status_type, status_type);
}

/// Asserts the lock transition completed and the clipboard step finished (AC12 case 6).
fn assert_lock_complete(h: &Harness) {
    assert!(!h.app.vault.is_unlocked(), "vault stays unlocked");
    assert_eq!(h.app.screen, Screen::Unlock);
    assert!(h.app.items.is_empty(), "decrypted items survive the lock");
    assert!(!h.app.clipboard_digest_stored(), "digest survives the lock");
    assert_eq!(h.clipboard.releases(), 1, "handle not released exactly once");
}

/// Case 1: the copied value is still on the clipboard, so the lock clears it.
#[test]
fn copied_value_still_present_is_cleared() {
    let mut h = unlocked_with_copy();
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_eq!(h.clipboard.content(), None);
    assert_eq!(
        h.clipboard.calls(),
        vec![
            ClipboardCall::SetText(ITEM_VALUE.to_string()),
            ClipboardCall::ReadText,
            ClipboardCall::Clear,
        ],
        "the read precedes the clear"
    );
    assert_status(&h, LOCKED_MESSAGE, StatusType::Info);
    assert_lock_complete(&h);
}

/// Case 2: another application replaced the clipboard, so the lock leaves it alone.
#[test]
fn clipboard_replaced_by_other_text_is_left_alone() {
    let mut h = unlocked_with_copy();
    h.clipboard.replace_externally(Some(OTHER_TEXT));
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 0);
    assert_eq!(h.clipboard.content().as_deref(), Some(OTHER_TEXT));
    assert_status(&h, LOCKED_MESSAGE, StatusType::Info);
    assert_lock_complete(&h);
}

/// Case 3: the clipboard reports no text, so the lock leaves it alone.
#[test]
fn clipboard_reporting_no_text_is_left_alone() {
    let mut h = unlocked_with_copy();
    h.clipboard.set_read_behavior(ReadBehavior::NoText);
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 0);
    assert_status(&h, LOCKED_MESSAGE, StatusType::Info);
    assert_lock_complete(&h);
}

/// Case 3, emptied variant: another application emptied the clipboard, so there is nothing to clear.
#[test]
fn emptied_clipboard_is_left_alone() {
    let mut h = unlocked_with_copy();
    h.clipboard.replace_externally(None);
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 0);
    assert_lock_complete(&h);
}

/// Case 4: the clipboard cannot be read, so the lock clears it anyway.
#[test]
fn unreadable_clipboard_is_cleared() {
    let mut h = unlocked_with_copy();
    h.clipboard.set_read_behavior(ReadBehavior::Fail);
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_eq!(h.clipboard.content(), None);
    assert_status(&h, LOCKED_MESSAGE, StatusType::Info);
    assert_lock_complete(&h);
}

/// Case 5: nothing was copied, so the lock does not touch the clipboard but still releases the handle.
#[test]
fn nothing_copied_makes_no_clipboard_call() {
    let mut h = unlocked();
    h.clipboard.replace_externally(Some(OTHER_TEXT));
    h.app.lock();

    assert_eq!(h.clipboard.set_text_calls(), 0);
    assert_eq!(h.clipboard.read_calls(), 0);
    assert_eq!(h.clipboard.clear_calls(), 0);
    assert!(h.clipboard.calls().is_empty());
    assert_eq!(h.clipboard.content().as_deref(), Some(OTHER_TEXT));
    assert_status(&h, LOCKED_MESSAGE, StatusType::Info);
    assert_lock_complete(&h);
}

/// Case 7: a failed clear of the still-present value warns, and the lock still completes in full.
#[test]
fn failed_clear_of_present_value_warns_and_lock_completes() {
    let mut h = unlocked_with_copy();
    h.clipboard.set_fail_clear(true);
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_status(&h, CLEAR_FAILED_MESSAGE, StatusType::Warning);
    assert_lock_complete(&h);
}

/// Case 7: a failed clear of an unreadable clipboard warns, and the lock still completes in full.
#[test]
fn failed_clear_of_unreadable_clipboard_warns_and_lock_completes() {
    let mut h = unlocked_with_copy();
    h.clipboard.set_read_behavior(ReadBehavior::Fail);
    h.clipboard.set_fail_clear(true);
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_status(&h, CLEAR_FAILED_MESSAGE, StatusType::Warning);
    assert_lock_complete(&h);
}

/// Unlocks, stores a second item, and copies the synthetic item (A) and then the second item (B).
fn unlocked_with_two_copies() -> Harness {
    let mut h = unlocked();
    store_item(&mut h.app, SECOND_NAME, ItemKind::Password, SECOND_VALUE);
    copy_named(&mut h, ITEM_NAME);
    copy_named(&mut h, SECOND_NAME);
    assert_eq!(h.clipboard.content().as_deref(), Some(SECOND_VALUE));
    h
}

/// Case 8: after copying A then B, the lock clears B.
#[test]
fn later_copy_is_cleared() {
    let mut h = unlocked_with_two_copies();
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_eq!(h.clipboard.content(), None);
    assert_lock_complete(&h);
}

/// Case 8: after copying A then B, A back on the clipboard is not cleared, since only B's digest is kept.
#[test]
fn earlier_copy_put_back_is_left_alone() {
    let mut h = unlocked_with_two_copies();
    h.clipboard.replace_externally(Some(ITEM_VALUE));
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 0);
    assert_eq!(h.clipboard.content().as_deref(), Some(ITEM_VALUE));
    assert_lock_complete(&h);
}

/// Locks and asserts the value that a copy path put on the double was cleared.
fn assert_lock_clears(h: &mut Harness, copied: &str) {
    assert_eq!(h.clipboard.content().as_deref(), Some(copied));
    assert!(h.app.clipboard_digest_stored());
    h.app.lock();
    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_eq!(h.clipboard.content(), None);
    assert_lock_complete(h);
}

/// Case 9: `copy_selected` stores a digest.
#[test]
fn copy_selected_leads_to_clear() {
    let mut h = unlocked();
    h.app.copy_selected().expect("copy succeeds");
    assert_lock_clears(&mut h, ITEM_VALUE);
}

/// Case 9: the `c` key on the main screen reaches `copy_selected` and stores a digest.
#[test]
fn c_key_copy_leads_to_clear() {
    let mut h = unlocked();
    press(&mut h, KeyCode::Char('c')).expect("handle c");
    assert_eq!(h.app.status_type, StatusType::Success);
    assert_lock_clears(&mut h, ITEM_VALUE);
}

/// Case 9: `copy_viewed` stores a digest.
#[test]
fn copy_viewed_leads_to_clear() {
    let mut h = unlocked();
    h.app.view_selected();
    assert_eq!(h.app.screen, Screen::ViewItem);
    h.app.copy_viewed().expect("copy succeeds");
    assert_lock_clears(&mut h, ITEM_VALUE);
}

/// Case 9: `copy_generated_password` stores a digest.
#[test]
fn copy_generated_password_leads_to_clear() {
    let mut h = unlocked();
    h.app.generate_password();
    let generated = h.app.generated_password.clone().expect("password generated");
    h.app.copy_generated_password().expect("copy succeeds");
    assert_eq!(h.app.error.as_deref(), Some("Password copied to clipboard"));
    assert_lock_clears(&mut h, &generated);
}

/// Case 10: a failed copy reports its error and leaves nothing for the lock to clear.
#[test]
fn failed_copy_reports_error_and_lock_makes_no_read_or_clear() {
    let mut h = unlocked();
    h.clipboard.set_fail_set_text(true);

    let err = h.app.copy_selected().expect_err("copy fails");
    assert!(err.to_string().starts_with("Failed to copy to clipboard"));

    // Through the key, the error lands in the status bar as before.
    press(&mut h, KeyCode::Char('c')).expect("handle c");
    assert_eq!(h.app.status_type, StatusType::Error);
    assert!(
        h.app
            .status_message
            .as_deref()
            .is_some_and(|m| m.starts_with("Failed to copy to clipboard"))
    );

    assert_eq!(h.clipboard.set_text_calls(), 2);
    assert_eq!(h.clipboard.content(), None);
    assert!(!h.app.clipboard_digest_stored());

    h.app.lock();
    assert_eq!(h.clipboard.read_calls(), 0);
    assert_eq!(h.clipboard.clear_calls(), 0);
    assert_status(&h, LOCKED_MESSAGE, StatusType::Info);
    assert_lock_complete(&h);
}

/// A failed copy after a successful one keeps the earlier digest, so the lock still clears that value.
#[test]
fn failed_copy_keeps_earlier_digest() {
    let mut h = unlocked();
    store_item(&mut h.app, SECOND_NAME, ItemKind::Password, SECOND_VALUE);
    copy_named(&mut h, ITEM_NAME);
    h.clipboard.set_fail_set_text(true);
    h.app.selected = index_of(&h, SECOND_NAME);
    let err = h.app.copy_selected().expect_err("copy fails");
    assert!(err.to_string().starts_with("Failed to copy to clipboard"));

    h.app.lock();
    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);
    assert_eq!(h.clipboard.content(), None);
    assert_lock_complete(&h);
}

/// Case 11: the digest does not survive the session, so a later lock without a copy reads nothing.
#[test]
fn digest_does_not_survive_the_session() {
    let mut h = unlocked_with_copy();
    h.app.lock();
    assert_eq!(h.clipboard.read_calls(), 1);
    assert_eq!(h.clipboard.clear_calls(), 1);

    // The same value comes back on the clipboard from elsewhere; the next session never copied it.
    h.clipboard.replace_externally(Some(ITEM_VALUE));
    unlock(&mut h.app);
    assert!(!h.app.clipboard_digest_stored());
    h.app.lock();

    assert_eq!(h.clipboard.read_calls(), 1, "second lock read the clipboard");
    assert_eq!(h.clipboard.clear_calls(), 1, "second lock cleared the clipboard");
    assert_eq!(h.clipboard.content().as_deref(), Some(ITEM_VALUE));
    assert_eq!(h.clipboard.releases(), 2);
    assert!(!h.app.clipboard_digest_stored());
}

/// Case 12: locking an already locked App makes no call on the double, `release` included.
#[test]
fn already_locked_makes_no_clipboard_call() {
    // Never unlocked.
    let mut fresh = harness(auto_lock(true, TIMEOUT_MINUTES));
    fresh.app.lock();
    assert!(fresh.clipboard.calls().is_empty());
    assert_eq!(fresh.clipboard.releases(), 0);

    // Locked after a copy.
    let mut h = unlocked_with_copy();
    h.app.lock();
    let calls = h.clipboard.calls();
    let releases = h.clipboard.releases();
    h.app.lock();
    assert_eq!(h.clipboard.calls(), calls);
    assert_eq!(h.clipboard.releases(), releases);
}
