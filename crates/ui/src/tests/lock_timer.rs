//! Tests for the inactivity timer owned by the event loop and the lock transition.

use super::support::{
    Harness, ITEM_NAME, ITEM_VALUE, MASTER_PASSWORD, VaultState, auto_lock, harness, harness_with, key_press, press,
    render, send, unlock,
};
use crate::app::{CountdownInfo, Screen, StatusType};
use crate::clock::{Clock, SystemClock};
use chamber_vault::{AutoLockConfig, Vault, VaultCategory};
use color_eyre::Result;
use ratatui::crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

const TIMEOUT_MINUTES: u64 = 5;
const TIMEOUT: Duration = Duration::from_secs(TIMEOUT_MINUTES * 60);
const LOCKED_MESSAGE: &str = "Locked due to inactivity";
const SENTINEL: &str = "sentinel status";
const WIDTH: u16 = 140;
const HEIGHT: u16 = 40;

fn enabled() -> AutoLockConfig {
    auto_lock(true, TIMEOUT_MINUTES)
}

fn remaining(h: &Harness) -> Option<Duration> {
    h.app.time_until_auto_lock(h.clock.reading())
}

fn tick(h: &mut Harness) {
    let now = h.clock.reading();
    h.app.tick(now);
}

fn assert_no_timer(h: &Harness) {
    assert_eq!(remaining(h), None, "no timer expected");
    assert!(h.app.countdown_info.is_none(), "no countdown expected");
}

/// Asserts the full lock transition took effect.
fn assert_locked(h: &Harness) {
    assert!(!h.app.vault.is_unlocked(), "vault key must be dropped");
    assert!(
        h.app.vault_manager.open_vaults.is_empty(),
        "manager must hold no open vaults"
    );
    assert_eq!(h.app.screen, Screen::Unlock);
    assert_no_timer(h);
    assert_eq!(h.app.status_message.as_deref(), Some(LOCKED_MESSAGE));
    assert_eq!(h.app.status_type, StatusType::Info);
}

/// Whether the frame contains countdown text of the form `<digits>m<digits>s`, such as `2m30s`.
///
/// The lock emoji alone is not a marker: the categories panel uses it too.
fn contains_minutes_seconds(frame: &str) -> bool {
    let chars: Vec<char> = frame.chars().collect();
    chars.iter().enumerate().any(|(i, &c)| {
        if c != 'm' || i == 0 || !chars[i - 1].is_ascii_digit() {
            return false;
        }
        let digits = chars[i + 1..].iter().take_while(|d| d.is_ascii_digit()).count();
        digits > 0 && chars.get(i + 1 + digits) == Some(&'s')
    })
}

/// Asserts the rendered frame shows no countdown in any form.
fn assert_no_countdown_text(frame: &str) {
    assert!(!contains_minutes_seconds(frame), "countdown rendered");
    assert!(!frame.contains("Locking..."), "Locking... rendered");
}

fn countdown(h: &Harness) -> (i64, i64) {
    let info = h.app.countdown_info.as_ref().expect("countdown expected");
    assert!(info.enabled);
    (info.minutes_left, info.seconds_left)
}

#[test]
fn system_clock_readings_do_not_go_backward() {
    let clock = SystemClock::new();
    let first = clock.now();
    let second = clock.now();
    assert!(second.monotonic >= first.monotonic);
}

#[test]
fn ac1_no_timer_while_locked_at_startup() -> Result<()> {
    let mut h = harness(enabled());
    assert!(!h.app.master_mode_is_setup);
    assert_no_timer(&h);

    let typed = "abcdef";
    for c in typed.chars() {
        h.clock.advance(TIMEOUT * 2);
        tick(&mut h);
        assert_no_timer(&h);
        assert!(!press(&mut h, KeyCode::Char(c))?);
        assert_no_timer(&h);
    }
    assert_eq!(h.app.master_input, typed);

    let before = (
        h.app.screen,
        h.app.master_input.clone(),
        h.app.status_message.clone(),
        h.app.error.clone(),
    );
    h.app.lock();
    let after = (
        h.app.screen,
        h.app.master_input.clone(),
        h.app.status_message.clone(),
        h.app.error.clone(),
    );
    assert_eq!(before, after, "lock() while locked must change nothing");
    assert_no_timer(&h);

    assert_no_countdown_text(&render(&mut h.app, WIDTH, HEIGHT));
    Ok(())
}

#[test]
fn ac1_no_timer_on_setup_form() -> Result<()> {
    let mut h = harness_with(enabled(), VaultState::Uninitialized);
    assert!(h.app.master_mode_is_setup);
    assert_eq!(h.app.screen, Screen::Unlock);

    for c in "xyz".chars() {
        h.clock.advance(TIMEOUT * 3);
        tick(&mut h);
        assert!(!press(&mut h, KeyCode::Char(c))?);
        assert_no_timer(&h);
    }
    assert_eq!(h.app.master_input, "xyz");
    assert_no_countdown_text(&render(&mut h.app, WIDTH, HEIGHT));

    // Completing setup unlocks and starts the timer with a full interval.
    unlock(&mut h.app);
    assert_eq!(remaining(&h), Some(TIMEOUT));
    Ok(())
}

#[test]
fn ac2_activity_restarts_the_timer_and_drives_the_countdown() -> Result<()> {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    assert_eq!(remaining(&h), Some(TIMEOUT));

    h.clock.advance(Duration::from_secs(70));
    tick(&mut h);
    assert_eq!(remaining(&h), Some(Duration::from_secs(230)));
    assert_eq!(countdown(&h), (3, 230));

    // A key a handler acts on restarts the timer.
    assert!(!press(&mut h, KeyCode::Down)?);
    assert_eq!(remaining(&h), Some(TIMEOUT));
    tick(&mut h);
    assert_eq!(countdown(&h), (5, 300));

    // A key no handler acts on restarts it too.
    h.clock.advance(Duration::from_secs(200));
    tick(&mut h);
    assert_eq!(remaining(&h), Some(Duration::from_secs(100)));
    let selected = h.app.selected;
    assert!(!press(&mut h, KeyCode::F(12))?);
    assert_eq!(h.app.selected, selected);
    assert_eq!(h.app.screen, Screen::Main);
    assert_eq!(remaining(&h), Some(TIMEOUT));
    Ok(())
}

#[test]
fn ac2_non_press_events_are_not_activity_and_not_dispatched() -> Result<()> {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    h.clock.advance(Duration::from_secs(90));
    tick(&mut h);
    let expected = Some(Duration::from_secs(210));

    let mouse = Event::Mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 3,
        row: 4,
        modifiers: KeyModifiers::NONE,
    });
    let resize = Event::Resize(80, 24);
    let release_q = Event::Key(KeyEvent::new_with_kind(
        KeyCode::Char('q'),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    ));
    let repeat_q = Event::Key(KeyEvent::new_with_kind(
        KeyCode::Char('q'),
        KeyModifiers::NONE,
        KeyEventKind::Repeat,
    ));

    for event in [mouse, resize, release_q, repeat_q, Event::FocusGained] {
        assert!(!send(&mut h, &event)?, "non-press event must not quit: {event:?}");
        assert_eq!(
            remaining(&h),
            expected,
            "non-press event must not reset the timer: {event:?}"
        );
        assert_eq!(h.app.screen, Screen::Main);
    }

    // A pressed q on the main screen does quit, so the release above was not dispatched.
    assert!(press(&mut h, KeyCode::Char('q'))?);
    Ok(())
}

#[test]
fn ac2_countdown_renders_as_before_while_unlocked() {
    let mut h = harness(enabled());
    unlock(&mut h.app);

    // More than four minutes left: no countdown.
    h.clock.advance(Duration::from_secs(30));
    tick(&mut h);
    assert_eq!(countdown(&h), (4, 270));
    assert_no_countdown_text(&render(&mut h.app, WIDTH, HEIGHT));

    // Two minutes thirty seconds left.
    h.clock.advance(Duration::from_secs(120));
    tick(&mut h);
    assert_eq!(countdown(&h), (2, 150));
    let frame = render(&mut h.app, WIDTH, HEIGHT);
    assert!(frame.contains("2m30s"), "expected 2m30s in the status bar");
    assert!(contains_minutes_seconds(&frame));
    assert!(!frame.contains("Locking..."));

    // Less than one second left.
    h.clock.advance(Duration::from_millis(149_500));
    tick(&mut h);
    assert!(h.app.vault.is_unlocked());
    assert_eq!(countdown(&h), (0, 0));
    assert!(render(&mut h.app, WIDTH, HEIGHT).contains("Locking..."));
}

#[test]
fn ac3_expiry_locks_exactly_once() {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    assert!(h.app.status_message.is_none());

    h.clock.advance(TIMEOUT);
    tick(&mut h);
    assert_locked(&h);

    h.app.status_message = Some(SENTINEL.to_string());
    for _ in 0..3 {
        h.clock.advance(TIMEOUT);
        tick(&mut h);
        assert_eq!(h.app.status_message.as_deref(), Some(SENTINEL));
        assert_no_timer(&h);
    }

    let frame = render(&mut h.app, WIDTH, HEIGHT);
    assert_no_countdown_text(&frame);
    assert!(!frame.contains(ITEM_NAME));
    assert!(!frame.contains(ITEM_VALUE));
}

#[test]
fn ac3_key_at_or_after_expiry_is_discarded() -> Result<()> {
    for late_by in [Duration::ZERO, Duration::from_secs(1)] {
        for search_mode in [false, true] {
            let mut h = harness(enabled());
            unlock(&mut h.app);
            if search_mode {
                // In search mode every character a handler receives lands in the query.
                h.app.search_mode = true;
                h.app.search_query = "zz".to_string();
            }

            h.clock.advance(TIMEOUT + late_by);
            assert!(!press(&mut h, KeyCode::Char('w'))?);
            assert_locked(&h);
            assert!(
                h.app.master_input.is_empty(),
                "discarded key reached the unlock handler"
            );
            // The lock wipes the query, so a key that reached the search handler would leave "w" here.
            assert_eq!(h.app.search_query, "", "discarded key reached the search handler");

            let frame = render(&mut h.app, WIDTH, HEIGHT);
            assert_no_countdown_text(&frame);
            assert!(!frame.contains(ITEM_NAME));
            assert!(!frame.contains(ITEM_VALUE));
        }
    }
    Ok(())
}

#[test]
fn ac4_no_timer_restarts_after_a_lock() -> Result<()> {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    h.clock.advance(TIMEOUT);
    tick(&mut h);
    assert_locked(&h);
    h.app.status_message = Some(SENTINEL.to_string());

    let typed = "lmnop";
    for c in typed.chars() {
        h.clock.advance(TIMEOUT + Duration::from_secs(1));
        tick(&mut h);
        assert!(!press(&mut h, KeyCode::Char(c))?);
        assert_eq!(remaining(&h), None);
        tick(&mut h);
        assert_no_timer(&h);
        assert_eq!(h.app.status_message.as_deref(), Some(SENTINEL));
    }
    assert_eq!(h.app.master_input, typed);
    Ok(())
}

#[test]
fn ac6_lock_closes_other_key_owners_and_keeps_the_registry() -> Result<()> {
    let mut h = harness(enabled());
    let others = [
        ("other-a", "Other-Vault-A1", "other-a-item", "other-a-value"),
        ("other-b", "Other-Vault-B2", "other-b-item", "other-b-value"),
    ];

    let mut created = Vec::new();
    for (name, password, item_name, item_value) in others {
        let path = h.dir.path().join(format!("{name}.db"));
        let id = h.app.vault_manager.create_vault(
            name.to_string(),
            Some(path.clone()),
            VaultCategory::Testing,
            None,
            password,
        )?;
        h.app.vault_manager.open_vault(&id, password)?;
        let vault = h.app.vault_manager.get_vault(&id).expect("vault is open");
        assert!(vault.is_unlocked());
        vault.create_item(&chamber_vault::NewItem {
            name: item_name.to_string(),
            kind: chamber_vault::ItemKind::Note,
            value: item_value.to_string(),
        })?;
        created.push((id, path, password));
    }
    h.app.vault_manager.switch_active_vault(&created[0].0)?;
    assert_eq!(h.app.vault_manager.open_vaults.len(), 2);

    let registry_entries = |h: &Harness| -> BTreeMap<String, String> {
        h.app
            .vault_manager
            .registry
            .vaults
            .iter()
            .map(|(id, info)| (id.clone(), format!("{info:?}")))
            .collect()
    };
    let entries_before = registry_entries(&h);
    let active_before = h.app.vault_manager.registry.active_vault_id.clone();
    let registry_path = h.app.vault_manager.registry.registry_path.clone();
    let file_before = fs::read_to_string(&registry_path)?;

    unlock(&mut h.app);
    h.app.lock();

    assert_locked(&h);
    assert_eq!(registry_entries(&h), entries_before);
    assert_eq!(h.app.vault_manager.registry.active_vault_id, active_before);
    assert_eq!(fs::read_to_string(&registry_path)?, file_before);

    // The App's own vault reopens and unlocks with its items intact.
    assert!(h.vault_path().exists());
    let mut own = Vault::open_or_create(Some(&h.vault_path()))?;
    own.unlock(MASTER_PASSWORD)?;
    let own_items: Vec<_> = own.list_items()?.into_iter().map(|i| (i.name, i.value)).collect();
    assert_eq!(own_items, vec![(ITEM_NAME.to_string(), ITEM_VALUE.to_string())]);

    for ((_, password, item_name, item_value), (_, path, _)) in others.iter().zip(&created) {
        assert!(path.exists());
        let mut vault = Vault::open_or_create(Some(path))?;
        vault.unlock(password)?;
        let items: Vec<_> = vault.list_items()?.into_iter().map(|i| (i.name, i.value)).collect();
        assert_eq!(items, vec![((*item_name).to_string(), (*item_value).to_string())]);
    }
    Ok(())
}

#[test]
fn ac9_disabled_auto_lock_never_starts_a_timer() -> Result<()> {
    let mut h = harness(auto_lock(false, TIMEOUT_MINUTES));
    unlock(&mut h.app);
    assert_no_timer(&h);

    for _ in 0..5 {
        h.clock.advance(TIMEOUT * 10);
        tick(&mut h);
        assert!(!press(&mut h, KeyCode::Down)?);
        tick(&mut h);
        assert_no_timer(&h);
        assert!(h.app.vault.is_unlocked());
        assert_eq!(h.app.screen, Screen::Main);
    }

    h.app.lock();
    assert_locked(&h);
    Ok(())
}

#[test]
fn ac10_stale_countdown_is_hidden_while_locked() {
    let stale = |seconds_left| CountdownInfo {
        enabled: true,
        minutes_left: seconds_left / 60,
        seconds_left,
    };

    // Locked at startup, then locked by expiry.
    let mut h = harness(enabled());
    for round in 0..2 {
        if round == 1 {
            unlock(&mut h.app);
            h.clock.advance(TIMEOUT);
            tick(&mut h);
            assert_locked(&h);
        }
        assert!(!h.app.vault.is_unlocked());

        h.app.countdown_info = Some(stale(150));
        let frame = render(&mut h.app, WIDTH, HEIGHT);
        assert!(!frame.contains("2m30s"));
        assert_no_countdown_text(&frame);

        h.app.countdown_info = Some(stale(0));
        assert_no_countdown_text(&render(&mut h.app, WIDTH, HEIGHT));
    }
}

#[test]
fn ac13_wall_clock_counts_suspended_time() {
    let mut h = harness(enabled());
    unlock(&mut h.app);

    h.clock.advance_wall(TIMEOUT + Duration::from_secs(1));
    h.clock.advance_monotonic(Duration::from_secs(1));
    tick(&mut h);
    assert_locked(&h);
}

#[test]
fn ac13_wall_clock_moved_backward_cannot_extend_a_session() {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    let start = h.clock.reading().monotonic;

    h.clock.rewind_wall(Duration::from_secs(3_600));
    h.clock
        .set_monotonic(start + TIMEOUT.saturating_sub(Duration::from_millis(1)));
    tick(&mut h);
    assert!(h.app.vault.is_unlocked());
    assert_eq!(remaining(&h), Some(Duration::from_millis(1)));

    h.clock.set_monotonic(start + TIMEOUT);
    tick(&mut h);
    assert_locked(&h);
}

#[test]
fn lock_drops_the_key_so_the_same_vault_unlocks_again() {
    let mut h = harness(enabled());
    unlock(&mut h.app);
    let db_path = h.app.vault.db_path().to_path_buf();

    h.app.lock();
    assert_locked(&h);
    assert_eq!(h.app.vault.db_path(), db_path);

    unlock(&mut h.app);
    assert!(h.app.vault.is_unlocked());
    assert_eq!(remaining(&h), Some(TIMEOUT));
    assert!(h.app.status_message.is_none(), "unlock clears the lock message");
    assert!(h.app.items.iter().any(|i| i.name == ITEM_NAME));
}

#[test]
fn key_press_helper_builds_a_press() {
    assert!(matches!(
        key_press(KeyCode::Char('a')),
        Event::Key(key) if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('a')
    ));
}
