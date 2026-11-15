//! Shared helpers for UI tests: a controllable clock, an isolated App harness, and event and render helpers.
//!
//! Everything here uses temp-directory vaults and registries with synthetic secrets. Nothing opens the
//! default vault or registry, touches the desktop clipboard, needs a real terminal, or sleeps.

use crate::app::{App, Screen};
use crate::clipboard::Clipboard;
use crate::clock::{Clock, ClockReading};
use crate::ui::{draw, handle_event};
use chamber_vault::{AutoLockConfig, ItemKind, NewItem, Vault, VaultManager, VaultRegistry};
use color_eyre::Result;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use std::cell::Cell;
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

/// An App built from isolated parts, the handle to its clock, and the temp directory holding its files.
///
/// Fields drop in declaration order, so the App closes its databases before the directory is removed.
pub(crate) struct Harness {
    pub(crate) app: App,
    pub(crate) clock: TestClock,
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
    let app = App::with_parts(
        vault,
        vault_manager,
        config,
        Box::new(clock.clone()),
        Clipboard::default(),
    );
    Harness { app, clock, dir }
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
