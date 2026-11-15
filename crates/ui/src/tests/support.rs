//! Shared helpers for UI tests: a controllable clock, a clipboard double, an isolated App harness, and event
//! and render helpers.
//!
//! Editor assertions: `assert_editor_fresh` checks the editor has no content, history, or yank; `assert_editor_settings_match_fresh_app`
//! compares six settings against a fresh harness. Everything else uses temp-directory vaults and registries with synthetic
//! secrets. Nothing opens the default vault or registry, touches the desktop clipboard, needs a real terminal, or sleeps.

use crate::app::{App, Screen};
use crate::clipboard::ClipboardBackend;
use crate::clock::{Clock, ClockReading};
use crate::ui::{draw, handle_event};
use chamber_vault::{AutoLockConfig, ItemKind, NewItem, Vault, VaultManager, VaultRegistry};
use color_eyre::{Result, eyre::eyre};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

/// Synthetic master password. Passes the TUI strength rules.
pub(crate) const MASTER_PASSWORD: &str = "Synthetic-Master-42";
/// Name of the synthetic item stored in every initialized harness vault.
pub(crate) const ITEM_NAME: &str = "zz-synthetic-item-name";
/// Value of the synthetic item stored in every initialized harness vault.
pub(crate) const ITEM_VALUE: &str = "qq-synthetic-item-value";

/// A clock the test controls. Clones share state, so the handle a test keeps moves the clock the App uses.
#[derive(Clone)]
pub(crate) struct TestClock {
    reading: Rc<Cell<ClockReading>>,
}

impl TestClock {
    pub(crate) fn new() -> Self {
        Self {
            reading: Rc::new(Cell::new(ClockReading {
                monotonic: Duration::from_secs(1_000),
                wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            })),
        }
    }

    /// The current reading.
    pub(crate) fn reading(&self) -> ClockReading {
        self.reading.get()
    }

    fn update(&self, f: impl FnOnce(&mut ClockReading)) {
        let mut reading = self.reading.get();
        f(&mut reading);
        self.reading.set(reading);
    }

    /// Advances both clocks by `by`.
    pub(crate) fn advance(&self, by: Duration) {
        self.update(|r| {
            r.monotonic += by;
            r.wall += by;
        });
    }

    /// Advances only the monotonic clock.
    pub(crate) fn advance_monotonic(&self, by: Duration) {
        self.update(|r| r.monotonic += by);
    }

    /// Advances only the wall clock.
    pub(crate) fn advance_wall(&self, by: Duration) {
        self.update(|r| r.wall += by);
    }

    /// Moves only the wall clock backward.
    pub(crate) fn rewind_wall(&self, by: Duration) {
        self.update(|r| r.wall -= by);
    }

    /// Sets the monotonic clock to an absolute value, leaving the wall clock alone.
    pub(crate) fn set_monotonic(&self, monotonic: Duration) {
        self.update(|r| r.monotonic = monotonic);
    }
}

impl Clock for TestClock {
    fn now(&self) -> ClockReading {
        self.reading.get()
    }
}

/// A call the App made on the clipboard double. `release` calls are counted separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClipboardCall {
    SetText(String),
    ReadText,
    Clear,
}

/// How the clipboard double answers `read_text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadBehavior {
    /// Returns the simulated content: its text, or no text when empty.
    Content,
    /// Reports that the clipboard holds no text, whatever the simulated content.
    NoText,
    /// Fails with an error other than "no text".
    Fail,
}

struct TestClipboardState {
    content: Option<String>,
    calls: Vec<ClipboardCall>,
    releases: usize,
    read: ReadBehavior,
    fail_set_text: bool,
    fail_clear: bool,
}

/// A clipboard double. Clones share state, so the handle a test keeps sees and steers the one the App uses.
#[derive(Clone)]
pub(crate) struct TestClipboard {
    state: Rc<RefCell<TestClipboardState>>,
}

impl TestClipboard {
    /// An empty clipboard that records calls and succeeds at everything.
    pub(crate) fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(TestClipboardState {
                content: None,
                calls: Vec::new(),
                releases: 0,
                read: ReadBehavior::Content,
                fail_set_text: false,
                fail_clear: false,
            })),
        }
    }

    /// The simulated clipboard content.
    pub(crate) fn content(&self) -> Option<String> {
        self.state.borrow().content.clone()
    }

    /// Replaces the content from outside the App, as another application taking the clipboard would.
    /// Not recorded as a call.
    pub(crate) fn replace_externally(&self, content: Option<&str>) {
        self.state.borrow_mut().content = content.map(str::to_string);
    }

    /// Every `set_text`, `read_text`, and `clear` call so far, in order.
    pub(crate) fn calls(&self) -> Vec<ClipboardCall> {
        self.state.borrow().calls.clone()
    }

    /// Number of `set_text` calls so far.
    pub(crate) fn set_text_calls(&self) -> usize {
        self.count(|c| matches!(c, ClipboardCall::SetText(_)))
    }

    /// Number of `read_text` calls so far.
    pub(crate) fn read_calls(&self) -> usize {
        self.count(|c| *c == ClipboardCall::ReadText)
    }

    /// Number of `clear` calls so far.
    pub(crate) fn clear_calls(&self) -> usize {
        self.count(|c| *c == ClipboardCall::Clear)
    }

    /// Number of `release` calls so far.
    pub(crate) fn releases(&self) -> usize {
        self.state.borrow().releases
    }

    /// Sets how `read_text` answers.
    pub(crate) fn set_read_behavior(&self, read: ReadBehavior) {
        self.state.borrow_mut().read = read;
    }

    /// Makes `set_text` fail (without changing the content) or succeed.
    pub(crate) fn set_fail_set_text(&self, fail: bool) {
        self.state.borrow_mut().fail_set_text = fail;
    }

    /// Makes `clear` fail (without changing the content) or succeed.
    pub(crate) fn set_fail_clear(&self, fail: bool) {
        self.state.borrow_mut().fail_clear = fail;
    }

    fn count(&self, pred: impl Fn(&ClipboardCall) -> bool) -> usize {
        self.state.borrow().calls.iter().filter(|c| pred(c)).count()
    }
}

impl ClipboardBackend for TestClipboard {
    fn set_text(&mut self, text: &str) -> Result<()> {
        let mut state = self.state.borrow_mut();
        state.calls.push(ClipboardCall::SetText(text.to_string()));
        if state.fail_set_text {
            return Err(eyre!("Failed to copy to clipboard: simulated failure"));
        }
        state.content = Some(text.to_string());
        Ok(())
    }

    fn read_text(&mut self) -> Result<Option<String>> {
        let mut state = self.state.borrow_mut();
        state.calls.push(ClipboardCall::ReadText);
        match state.read {
            ReadBehavior::Content => Ok(state.content.clone()),
            ReadBehavior::NoText => Ok(None),
            ReadBehavior::Fail => Err(eyre!("Failed to read clipboard: simulated failure")),
        }
    }

    fn clear(&mut self) -> Result<()> {
        let mut state = self.state.borrow_mut();
        state.calls.push(ClipboardCall::Clear);
        if state.fail_clear {
            return Err(eyre!("Failed to clear clipboard: simulated failure"));
        }
        state.content = None;
        Ok(())
    }

    fn release(&mut self) {
        self.state.borrow_mut().releases += 1;
    }
}

/// An App built from isolated parts, the handles to its clock and clipboard, and the temp directory holding
/// its files.
///
/// Fields drop in declaration order, so the App closes its databases before the directory is removed.
pub(crate) struct Harness {
    pub(crate) app: App,
    pub(crate) clock: TestClock,
    pub(crate) clipboard: TestClipboard,
    pub(crate) dir: TempDir,
}

impl Harness {
    /// Path of the harness vault database.
    pub(crate) fn vault_path(&self) -> PathBuf {
        self.dir.path().join("vault.db")
    }
}

/// Which state the harness vault starts in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultState {
    /// Initialized with `MASTER_PASSWORD`, holding the synthetic item, and locked.
    Initialized,
    /// Never initialized, so the App starts on the setup form.
    Uninitialized,
}

/// Builds a harness with an initialized, locked vault holding the synthetic item.
pub(crate) fn harness(config: AutoLockConfig) -> Harness {
    harness_with(config, VaultState::Initialized)
}

/// Builds a harness whose vault starts in `state`.
pub(crate) fn harness_with(config: AutoLockConfig, state: VaultState) -> Harness {
    let dir = TempDir::new().expect("create temp dir");
    let vault_path = dir.path().join("vault.db");

    let mut vault = Vault::open_or_create(Some(&vault_path)).expect("create vault");
    if state == VaultState::Initialized {
        vault.initialize(MASTER_PASSWORD).expect("initialize vault");
        vault.unlock(MASTER_PASSWORD).expect("unlock vault");
        vault
            .create_item(&NewItem {
                name: ITEM_NAME.to_string(),
                kind: ItemKind::Password,
                value: ITEM_VALUE.to_string(),
            })
            .expect("store synthetic item");
        vault.lock();
    }

    let vault_manager = VaultManager {
        registry: VaultRegistry {
            vaults: HashMap::new(),
            active_vault_id: None,
            registry_path: dir.path().join("registry.json"),
        },
        open_vaults: HashMap::new(),
    };

    let clock = TestClock::new();
    let clipboard = TestClipboard::new();
    let app = App::with_parts(
        vault,
        vault_manager,
        config,
        Box::new(clock.clone()),
        Box::new(clipboard.clone()),
    );
    Harness {
        app,
        clock,
        clipboard,
        dir,
    }
}

/// Auto-lock enabled with the given timeout, as the TUI reads it.
pub(crate) const fn auto_lock(enabled: bool, inactivity_timeout_minutes: u64) -> AutoLockConfig {
    AutoLockConfig {
        enabled,
        inactivity_timeout_minutes,
        check_interval_seconds: 15,
    }
}

/// Unlocks the App with `MASTER_PASSWORD` through `App::unlock` and asserts it reached the main screen.
///
/// Every test reaches `App::unlock` only through this helper.
pub(crate) fn unlock(app: &mut App) {
    app.master_input = MASTER_PASSWORD.to_string();
    if app.master_mode_is_setup {
        app.master_confirm_input = MASTER_PASSWORD.to_string();
    }
    app.unlock();
    assert_eq!(app.screen, Screen::Main, "unlock did not reach the main screen");
}

/// Stores a synthetic item in the unlocked App's vault and reloads the App's items.
pub(crate) fn store_item(app: &mut App, name: &str, kind: ItemKind, value: &str) {
    app.vault
        .create_item(&NewItem {
            name: name.to_string(),
            kind,
            value: value.to_string(),
        })
        .expect("store synthetic item");
    app.refresh_items().expect("reload items");
}

/// A key-press event for `code` with no modifiers.
pub(crate) fn key_press(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// Sends `event` through `handle_event` with the test clock's current reading.
pub(crate) fn send(h: &mut Harness, event: &Event) -> Result<bool> {
    let now = h.clock.reading();
    handle_event(&mut h.app, event, now)
}

/// Sends a key press for `code` through `handle_event` with the test clock's current reading.
pub(crate) fn press(h: &mut Harness, code: KeyCode) -> Result<bool> {
    send(h, &key_press(code))
}

/// Asserts the editor holds no text, no history, and no yank content, as a freshly built one.
pub(crate) fn assert_editor_fresh(app: &mut App) {
    let editor = &mut app.add_value_textarea;
    assert!(editor.is_empty(), "editor must be empty");
    assert!(editor.yank_text().is_empty(), "yank buffer must be empty");
    assert!(!editor.undo(), "undo must change nothing");
    assert!(!editor.redo(), "redo must change nothing");
    assert!(!editor.paste(), "paste must insert nothing");
    assert!(editor.is_empty(), "editor must still be empty");
}

/// Asserts the six editor settings match those of a freshly built App.
pub(crate) fn assert_editor_settings_match_fresh_app(app: &App) {
    let reference = harness(auto_lock(false, 0));
    let fresh = &reference.app.add_value_textarea;
    let editor = &app.add_value_textarea;
    assert_eq!(editor.placeholder_text(), fresh.placeholder_text());
    assert_eq!(editor.placeholder_style(), fresh.placeholder_style());
    assert_eq!(editor.line_number_style(), fresh.line_number_style());
    assert_eq!(editor.cursor_line_style(), fresh.cursor_line_style());
    assert_eq!(editor.cursor_style(), fresh.cursor_style());
    assert_eq!(editor.max_histories(), fresh.max_histories());
}

/// Draws the App into a `TestBackend` of the given size and returns every cell symbol as one string.
pub(crate) fn render(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal.draw(|f| draw(f, app)).expect("draw");
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect()
}
