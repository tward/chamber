//! Tests for the session cleanup inside `App::lock`: after a lock no decrypted value, draft, password text,
//! search text, generated password, editor history, or input mode from the ended session survives, input goes
//! to the unlock form, and preferences keep their values.

use super::support::{
    Harness, ITEM_NAME, ITEM_VALUE, assert_editor_fresh, assert_editor_settings_match_fresh_app, auto_lock, harness,
    press, render, store_item, unlock,
};
use crate::app::{
    AddItemField, App, ChangeKeyField, ImportExportField, ImportExportMode, PasswordGenField, Screen, StatusType,
    UnlockField, ViewMode, new_value_editor, wipe_editor, wipe_item, wipe_items, wipe_optional_string, wipe_string,
};
use crate::vault_selector::{InputField, VaultSelectorMode};
use chamber_vault::{AutoLockConfig, Item, ItemKind};
use ratatui::crossterm::event::KeyCode;
use std::time::Duration;
use time::OffsetDateTime;

const TIMEOUT_MINUTES: u64 = 5;
const TIMEOUT: Duration = Duration::from_secs(TIMEOUT_MINUTES * 60);
const LOCKED_MESSAGE: &str = "Locked due to inactivity";
const WIDTH: u16 = 140;
const HEIGHT: u16 = 40;

/// Second stored item, so the list holds more than one entry.
const SECOND_NAME: &str = "zz-synthetic-second-name";
const SECOND_VALUE: &str = "QQSECONDVAL";

// Synthetic session data the fill helper puts into the App. Short, distinct tokens so a rendered frame
// shows them whole when they are on screen.
const MASTER_TEXT: &str = "QQMASTERIN";
const CONFIRM_TEXT: &str = "QQCONFIRMIN";
const CK_CURRENT_TEXT: &str = "QQCKCURRENT";
const CK_NEW_TEXT: &str = "QQCKNEW";
const CK_CONFIRM_TEXT: &str = "QQCKCONFIRM";
const ADD_NAME_TEXT: &str = "QQADDNAME";
const ADD_VALUE_TEXT: &str = "QQADDVALUE";
const EDIT_VALUE_TEXT: &str = "QQEDITVALUE";
const SEARCH_TEXT: &str = "QQSEARCH";
const IE_PATH_TEXT: &str = "QQIEPATH";
const SELECTOR_INPUT_TEXT: &str = "QQSELECTORIN";
const GENERATED_TEXT: &str = "QQGENERATED";
const EDITOR_CUT_TEXT: &str = "QQEDITORCUT";
const EDITOR_DRAFT_TEXT: &str = "QQEDITORDRAFT";
const ERROR_TEXT: &str = "QQERROR";
const SELECTOR_ERROR_TEXT: &str = "QQSELECTORERR";
const SELECTOR_CONFIRM_TEXT: &str = "QQSELECTORCONFIRM";

/// Preference values the fill helper sets; a lock must keep them.
const GEN_LENGTH: usize = 31;
const GEN_LENGTH_STR: &str = "31";
const IE_FORMAT_IDX: usize = 2;
/// List selection in the vault selector; a lock must keep it.
const SELECTOR_SELECTION: usize = 3;

/// Every synthetic secret that must never appear in a frame rendered after a lock.
const SECRETS: &[&str] = &[
    ITEM_VALUE,
    SECOND_VALUE,
    MASTER_TEXT,
    CONFIRM_TEXT,
    CK_CURRENT_TEXT,
    CK_NEW_TEXT,
    CK_CONFIRM_TEXT,
    ADD_NAME_TEXT,
    ADD_VALUE_TEXT,
    EDIT_VALUE_TEXT,
    SEARCH_TEXT,
    IE_PATH_TEXT,
    SELECTOR_INPUT_TEXT,
    GENERATED_TEXT,
    EDITOR_CUT_TEXT,
    EDITOR_DRAFT_TEXT,
];

fn enabled() -> AutoLockConfig {
    auto_lock(true, TIMEOUT_MINUTES)
}

/// Item names and values, sorted by name.
fn snapshot(items: &[Item]) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = items.iter().map(|i| (i.name.clone(), i.value.clone())).collect();
    pairs.sort();
    pairs
}

/// Unlocks a fresh harness, stores a second item, and fills every piece of session state the lock must
/// discard and every preference it must keep. Returns the stored items as they were before any lock.
fn fill(h: &mut Harness) -> Vec<(String, String)> {
    unlock(&mut h.app);
    store_item(&mut h.app, SECOND_NAME, ItemKind::Password, SECOND_VALUE);
    let stored = snapshot(&h.app.items);
    assert_eq!(stored.len(), 2, "fill needs at least two items");
    let app = &mut h.app;

    app.selected = 1;
    app.scroll_offset = 1;

    let item = app
        .items
        .iter()
        .find(|i| i.name == ITEM_NAME)
        .cloned()
        .expect("synthetic item loaded");
    app.view_item = Some(item.clone());
    app.edit_item = Some(item);
    app.view_show_value = true;
    app.edit_value = EDIT_VALUE_TEXT.to_string();

    app.master_input = MASTER_TEXT.to_string();
    app.master_confirm_input = CONFIRM_TEXT.to_string();
    app.ck_current = CK_CURRENT_TEXT.to_string();
    app.ck_new = CK_NEW_TEXT.to_string();
    app.ck_confirm = CK_CONFIRM_TEXT.to_string();
    app.add_name = ADD_NAME_TEXT.to_string();
    app.add_value = ADD_VALUE_TEXT.to_string();
    app.search_query = SEARCH_TEXT.to_string();
    app.ie_path = IE_PATH_TEXT.to_string();
    app.vault_selector.input_buffer = SELECTOR_INPUT_TEXT.to_string();
    app.generated_password = Some(GENERATED_TEXT.to_string());

    // Draft text with undo history and a yank buffer: insert, select all, cut, insert again.
    let editor = &mut app.add_value_textarea;
    assert!(editor.insert_str(EDITOR_CUT_TEXT));
    editor.select_all();
    assert!(editor.cut());
    assert!(editor.insert_str(EDITOR_DRAFT_TEXT));
    assert_eq!(editor.yank_text(), EDITOR_CUT_TEXT);
    assert_eq!(editor.lines(), [EDITOR_DRAFT_TEXT]);

    app.add_value_scroll = 2;
    app.add_kind_idx = 3;
    app.unlock_focus = UnlockField::Confirm;
    app.ck_focus = ChangeKeyField::New;
    app.add_focus = AddItemField::Value;
    app.gen_focus = PasswordGenField::Generate;
    app.ie_focus = ImportExportField::Action;
    app.error = Some(ERROR_TEXT.to_string());

    app.vault_selector.show_selector = true;
    app.vault_selector.mode = VaultSelectorMode::Create;
    app.vault_selector.input_field = InputField::Name;
    app.vault_selector.error_message = Some(SELECTOR_ERROR_TEXT.to_string());
    app.vault_selector.confirmation_message = SELECTOR_CONFIRM_TEXT.to_string();
    app.vault_selector.state.select(Some(SELECTOR_SELECTION));

    app.view_mode = ViewMode::Passwords;
    app.gen_config.length = GEN_LENGTH;
    app.gen_config.include_symbols = false;
    app.gen_config.exclude_ambiguous = true;
    app.gen_length_str = GEN_LENGTH_STR.to_string();
    app.ie_mode = ImportExportMode::Import;
    app.ie_format_idx = IE_FORMAT_IDX;

    stored
}

/// Asserts every field the lock discards is back to its required state.
fn assert_session_discarded(app: &mut App) {
    assert!(app.items.is_empty(), "items must be empty");
    assert!(app.filtered_items.is_empty(), "filtered_items must be empty");
    assert!(app.view_item.is_none(), "view_item must be None");
    assert!(app.edit_item.is_none(), "edit_item must be None");

    for (name, field) in [
        ("master_input", &app.master_input),
        ("master_confirm_input", &app.master_confirm_input),
        ("ck_current", &app.ck_current),
        ("ck_new", &app.ck_new),
        ("ck_confirm", &app.ck_confirm),
        ("add_value", &app.add_value),
        ("edit_value", &app.edit_value),
        ("search_query", &app.search_query),
        ("add_name", &app.add_name),
        ("ie_path", &app.ie_path),
        ("vault_selector.input_buffer", &app.vault_selector.input_buffer),
    ] {
        assert!(field.is_empty(), "{name} must be empty");
    }
    assert!(app.generated_password.is_none(), "generated_password must be None");
    assert_editor_fresh(app);

    assert!(!app.search_mode, "search_mode must be off");
    assert!(!app.view_show_value, "view_show_value must be off");

    let selector = &app.vault_selector;
    assert!(!selector.show_selector, "selector must be hidden");
    assert_eq!(selector.mode, VaultSelectorMode::Select);
    assert_eq!(selector.error_message, None);
    assert!(selector.confirmation_message.is_empty());
    assert_eq!(selector.input_field, InputField::None);
    assert_eq!(
        selector.state.selected(),
        Some(SELECTOR_SELECTION),
        "list selection is kept"
    );

    assert_eq!(app.selected, 0);
    assert_eq!(app.scroll_offset, 0);
    assert_eq!(app.add_value_scroll, 0);
    assert_eq!(app.add_kind_idx, 0);

    assert!(app.unlock_focus == UnlockField::Master, "unlock_focus must be Master");
    assert!(app.ck_focus == ChangeKeyField::Current, "ck_focus must be Current");
    assert!(app.add_focus == AddItemField::Name, "add_focus must be Name");
    assert!(app.gen_focus == PasswordGenField::Length, "gen_focus must be Length");
    assert!(app.ie_focus == ImportExportField::Path, "ie_focus must be Path");

    assert_eq!(app.error, None);
    assert_eq!(app.status_message.as_deref(), Some(LOCKED_MESSAGE));
    assert_eq!(app.status_type, StatusType::Info);
}

/// Asserts the preferences the fill helper set survived.
fn assert_preferences_kept(app: &App) {
    assert!(app.view_mode == ViewMode::Passwords, "view_mode must be kept");
    assert_eq!(app.gen_config.length, GEN_LENGTH);
    assert!(!app.gen_config.include_symbols, "gen_config must be kept");
    assert!(app.gen_config.exclude_ambiguous, "gen_config must be kept");
    assert_eq!(app.gen_length_str, GEN_LENGTH_STR);
    assert!(app.ie_mode == ImportExportMode::Import, "ie_mode must be kept");
    assert_eq!(app.ie_format_idx, IE_FORMAT_IDX);
    assert!(!app.master_mode_is_setup, "master_mode_is_setup must be kept");
}

fn assert_frame_has_no_secrets(frame: &str) {
    for secret in SECRETS {
        assert!(!frame.contains(secret), "frame shows {secret}");
    }
}

/// How a scenario locks the App.
#[derive(Clone, Copy)]
enum LockVia {
    /// `tick` at the timeout.
    Tick,
    /// A key press arriving at the timeout, through `handle_event`.
    KeyAtExpiry,
    /// A direct `lock()` call.
    Call,
}

/// Fills a fresh harness, puts it on `screen`, locks it, and checks the whole required state after the
/// lock, including that the next key press lands in the master field. Returns the harness and the items
/// stored before the lock.
fn lock_from(screen: Screen, via: LockVia, prepare: impl FnOnce(&mut App)) -> (Harness, Vec<(String, String)>) {
    let mut h = harness(enabled());
    let stored = fill(&mut h);
    h.app.screen = screen;
    prepare(&mut h.app);

    match via {
        LockVia::Tick => {
            h.clock.advance(TIMEOUT);
            let now = h.clock.reading();
            h.app.tick(now);
        }
        LockVia::KeyAtExpiry => {
            h.clock.advance(TIMEOUT);
            assert!(!press(&mut h, KeyCode::Char('w')).expect("key at expiry"));
        }
        LockVia::Call => h.app.lock(),
    }

    assert!(!h.app.vault.is_unlocked(), "vault must be locked");
    assert_eq!(h.app.screen, Screen::Unlock);
    assert_session_discarded(&mut h.app);
    assert_preferences_kept(&h.app);
    assert_frame_has_no_secrets(&render(&mut h.app, WIDTH, HEIGHT));

    assert!(!press(&mut h, KeyCode::Char('k')).expect("type after lock"));
    assert_eq!(h.app.master_input, "k", "key must land in the master field");
    assert!(h.app.search_query.is_empty(), "key must not reach the search query");

    (h, stored)
}

/// Clears the typed character, unlocks with the correct password, and checks that the App shows freshly
/// loaded items and nothing from the discarded session.
fn unlock_again(mut h: Harness, stored: &[(String, String)]) {
    assert!(!press(&mut h, KeyCode::Backspace).expect("backspace"));
    assert!(h.app.master_input.is_empty());
    unlock(&mut h.app);

    assert_eq!(h.app.screen, Screen::Main);
    assert_eq!(
        snapshot(&h.app.items),
        stored,
        "items must match what was stored before the lock"
    );
    let in_vault = h.app.vault.list_items().expect("list stored items");
    assert_eq!(snapshot(&in_vault), stored, "no draft may be saved to the vault");
    assert!(
        !in_vault.iter().any(|i| i.name == ADD_NAME_TEXT),
        "add-item draft was saved"
    );
    let edited = in_vault.iter().find(|i| i.name == ITEM_NAME).expect("edited item");
    assert_eq!(edited.value, ITEM_VALUE, "edit draft was saved");

    assert!(h.app.search_query.is_empty());
    assert!(!h.app.search_mode);
    assert!(!h.app.view_show_value);
    assert!(h.app.view_item.is_none());
    assert!(h.app.edit_item.is_none());
    assert_editor_fresh(&mut h.app);
    assert_editor_settings_match_fresh_app(&h.app);

    let frame = render(&mut h.app, WIDTH, HEIGHT);
    for discarded in [
        SEARCH_TEXT,
        ADD_NAME_TEXT,
        ADD_VALUE_TEXT,
        EDIT_VALUE_TEXT,
        EDITOR_CUT_TEXT,
        EDITOR_DRAFT_TEXT,
        GENERATED_TEXT,
    ] {
        assert!(!frame.contains(discarded), "main frame shows {discarded}");
    }
}

#[test]
fn ac7_lock_from_main_in_search_mode() {
    let (h, stored) = lock_from(Screen::Main, LockVia::KeyAtExpiry, |app| app.search_mode = true);
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_add_item() {
    let (h, stored) = lock_from(Screen::AddItem, LockVia::Tick, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_edit_item() {
    let (h, stored) = lock_from(Screen::EditItem, LockVia::Call, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_item_detail() {
    let (h, stored) = lock_from(Screen::ViewItem, LockVia::Call, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_change_password() {
    let (h, stored) = lock_from(Screen::ChangeMaster, LockVia::Call, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_password_generator() {
    let (h, stored) = lock_from(Screen::GeneratePassword, LockVia::Call, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_import_export() {
    let (h, stored) = lock_from(Screen::ImportExport, LockVia::Call, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac7_lock_from_vault_selector() {
    let (h, stored) = lock_from(Screen::VaultSelector, LockVia::Call, |_| {});
    unlock_again(h, &stored);
}

#[test]
fn ac9_cleanup_with_auto_lock_disabled() {
    let mut h = harness(auto_lock(false, TIMEOUT_MINUTES));
    fill(&mut h);
    assert_eq!(h.app.time_until_auto_lock(h.clock.reading()), None, "no timer expected");

    h.app.lock();

    assert!(!h.app.vault.is_unlocked(), "vault must be locked");
    assert_eq!(h.app.screen, Screen::Unlock);
    assert_session_discarded(&mut h.app);
    assert_preferences_kept(&h.app);
}

/// The parts of the App a lock on a locked App must leave alone.
#[derive(PartialEq)]
struct Observed {
    master_input: String,
    master_confirm_input: String,
    search_query: String,
    add_name: String,
    error: Option<String>,
    status_message: Option<String>,
    status_type: StatusType,
    screen: Screen,
    unlock_focus: UnlockField,
    selected: usize,
    editor_lines: Vec<String>,
}

fn observe(app: &App) -> Observed {
    Observed {
        master_input: app.master_input.clone(),
        master_confirm_input: app.master_confirm_input.clone(),
        search_query: app.search_query.clone(),
        add_name: app.add_name.clone(),
        error: app.error.clone(),
        status_message: app.status_message.clone(),
        status_type: app.status_type,
        screen: app.screen,
        unlock_focus: app.unlock_focus,
        selected: app.selected,
        editor_lines: app.add_value_textarea.lines().to_vec(),
    }
}

#[test]
fn lock_on_a_locked_app_changes_nothing() {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    h.app.lock();
    assert!(!press(&mut h, KeyCode::Char('a')).expect("type"));
    assert!(!press(&mut h, KeyCode::Char('b')).expect("type"));
    // State a lock would reset if it ran.
    h.app.error = Some(ERROR_TEXT.to_string());
    h.app.search_query = SEARCH_TEXT.to_string();
    h.app.add_name = ADD_NAME_TEXT.to_string();
    h.app.selected = 4;
    assert!(h.app.add_value_textarea.insert_str(EDITOR_DRAFT_TEXT));
    let before = observe(&h.app);

    h.app.lock();

    assert_eq!(h.app.master_input, "ab", "typed characters must survive");
    assert!(observe(&h.app) == before, "lock on a locked App changed its state");
}

#[test]
fn wipe_string_empties_live_buffer() {
    let mut s = SEARCH_TEXT.to_string();
    wipe_string(&mut s);
    assert!(s.is_empty());
}

#[test]
fn wipe_optional_string_clears_live_value() {
    let mut s = Some(GENERATED_TEXT.to_string());
    wipe_optional_string(&mut s);
    assert_eq!(s, None);

    let mut none: Option<String> = None;
    wipe_optional_string(&mut none);
    assert_eq!(none, None);
}

#[test]
fn wipe_item_clears_live_value() {
    let now = OffsetDateTime::now_utc();
    let mut item = Some(Item {
        id: 1,
        name: ITEM_NAME.to_string(),
        kind: ItemKind::Password,
        value: ITEM_VALUE.to_string(),
        created_at: now,
        updated_at: now,
    });
    wipe_item(&mut item);
    assert!(item.is_none());

    let mut none: Option<Item> = None;
    wipe_item(&mut none);
    assert!(none.is_none());
}

#[test]
fn wipe_items_empties_live_vector() {
    let now = OffsetDateTime::now_utc();
    let mut items = vec![Item {
        id: 1,
        name: SECOND_NAME.to_string(),
        kind: ItemKind::Password,
        value: SECOND_VALUE.to_string(),
        created_at: now,
        updated_at: now,
    }];
    wipe_items(&mut items);
    assert!(items.is_empty());
}

#[test]
fn wipe_editor_replaces_live_editor_with_a_fresh_one() {
    let mut editor = new_value_editor();
    assert!(editor.insert_str(EDITOR_CUT_TEXT));
    editor.select_all();
    assert!(editor.cut());
    assert!(editor.insert_str(EDITOR_DRAFT_TEXT));

    wipe_editor(&mut editor);

    let fresh = new_value_editor();
    assert!(editor.is_empty());
    assert!(editor.yank_text().is_empty());
    assert!(!editor.undo());
    assert!(!editor.redo());
    assert!(!editor.paste());
    assert!(editor.is_empty());
    assert_eq!(editor.placeholder_text(), fresh.placeholder_text());
    assert_eq!(editor.line_number_style(), fresh.line_number_style());
    assert_eq!(editor.cursor_line_style(), fresh.cursor_line_style());
}

#[test]
fn new_value_editor_matches_startup_configuration() {
    let h = harness(enabled());
    let startup = &h.app.add_value_textarea;
    let fresh = new_value_editor();
    assert_eq!(fresh.placeholder_text(), "Enter your value here...");
    assert_eq!(fresh.placeholder_text(), startup.placeholder_text());
    assert_eq!(fresh.line_number_style(), startup.line_number_style());
    assert!(fresh.line_number_style().is_some(), "line numbers must be enabled");
    assert_eq!(fresh.cursor_line_style(), startup.cursor_line_style());
}

#[test]
fn vault_selector_reset_on_lock_keeps_list_selection() {
    let mut h = harness(enabled());
    let selector = &mut h.app.vault_selector;
    selector.show_selector = true;
    selector.mode = VaultSelectorMode::Import;
    selector.input_field = InputField::Path;
    selector.input_buffer = SELECTOR_INPUT_TEXT.to_string();
    selector.error_message = Some(SELECTOR_ERROR_TEXT.to_string());
    selector.confirmation_message = SELECTOR_CONFIRM_TEXT.to_string();
    selector.state.select(Some(SELECTOR_SELECTION));

    selector.reset_on_lock();

    assert!(!selector.show_selector);
    assert_eq!(selector.mode, VaultSelectorMode::Select);
    assert_eq!(selector.input_field, InputField::None);
    assert!(selector.input_buffer.is_empty());
    assert_eq!(selector.error_message, None);
    assert!(selector.confirmation_message.is_empty());
    assert_eq!(selector.state.selected(), Some(SELECTOR_SELECTION));
}
