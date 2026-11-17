//! Sources of the current time for the vault.
//!
//! Item writes read the time through the [`Clock`] trait instead of calling
//! `OffsetDateTime::now_utc()` directly, so tests can drive timestamps with a
//! [`ManualClock`]. Production code uses [`SystemClock`].

use std::sync::{Mutex, PoisonError};
use time::{Duration, OffsetDateTime, UtcOffset};

/// A source of the current UTC time.
///
/// A `Vault` holds one clock and takes exactly one reading from it per item write.
pub trait Clock: std::fmt::Debug + Send + Sync {
    /// Returns the current time.
    fn now_utc(&self) -> OffsetDateTime;
}

/// The real clock: reads the operating system's current UTC time.
///
/// This is the only place on the item create and update path that reads the system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock that only moves when told to, for tests.
///
/// The time lives behind a mutex, so one `Arc<ManualClock>` can be kept by a test while a
/// `Vault` holds another handle to the same clock: every `set` or `advance` through either
/// handle is seen by the other. Setting a time earlier than the current one is allowed, which
/// lets tests simulate a clock rollback.
///
/// Every reading is in UTC. A time given with another offset, to [`ManualClock::new`] or
/// [`ManualClock::set`], is stored as given and read back as the same instant in UTC.
///
/// # Panics
/// Reading panics only if the stored instant cannot be expressed in UTC, which can happen only
/// at the very edge of the range `OffsetDateTime` represents.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<OffsetDateTime>,
}

impl ManualClock {
    /// Creates a clock that reads the instant `start`, in UTC, until it is set or advanced.
    #[must_use]
    pub const fn new(start: OffsetDateTime) -> Self {
        Self { now: Mutex::new(start) }
    }

    /// Sets the clock to the instant `time`, which may be earlier than the current reading.
    ///
    /// Later readings return that instant in UTC, whatever offset `time` carries.
    pub fn set(&self, time: OffsetDateTime) {
        *self.lock() = time;
    }

    /// Moves the clock by `by`. A negative duration moves it backwards.
    ///
    /// # Panics
    /// Panics if the resulting time is outside the range `OffsetDateTime` can represent.
    pub fn advance(&self, by: Duration) {
        let mut now = self.lock();
        *now += by;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OffsetDateTime> {
        // The guarded value is a plain `Copy` timestamp, so a poisoned lock cannot hold a
        // half-written state; recover it instead of panicking.
        self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> OffsetDateTime {
        let now = *self.lock();
        now.to_offset(UtcOffset::UTC)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unwrap_in_result)]
    #![allow(clippy::panic)]
    #![allow(clippy::panic_in_result_fn)]
    #![allow(clippy::expect_used)]
    use super::*;
    use std::sync::Arc;
    use time::macros::datetime;

    #[test]
    fn test_manual_clock_reads_start_time() {
        let start = datetime!(2026-01-02 03:04:05.123_456_789 UTC);
        let clock = ManualClock::new(start);
        assert_eq!(clock.now_utc(), start);
        // Reading does not move the clock.
        assert_eq!(clock.now_utc(), start);
    }

    #[test]
    fn test_manual_clock_set_and_advance_visible_through_second_handle() {
        let start = datetime!(2026-01-02 03:04:05 UTC);
        let clock = Arc::new(ManualClock::new(start));
        let other: Arc<dyn Clock> = clock.clone();

        clock.advance(Duration::seconds(90));
        assert_eq!(other.now_utc(), datetime!(2026-01-02 03:05:35 UTC));

        let later = datetime!(2026-06-01 00:00:00 UTC);
        clock.set(later);
        assert_eq!(other.now_utc(), later);

        // Rolling back to an earlier time works and is seen through the other handle.
        let earlier = datetime!(2025-12-31 23:59:59 UTC);
        clock.set(earlier);
        assert_eq!(other.now_utc(), earlier);

        clock.advance(Duration::seconds(-59));
        assert_eq!(other.now_utc(), datetime!(2025-12-31 23:59:00 UTC));
    }

    #[test]
    fn test_manual_clock_reads_non_utc_input_as_utc() {
        let start = datetime!(2026-01-02 05:04:05 +02:00);
        let clock = ManualClock::new(start);
        let reading = clock.now_utc();
        assert_eq!(reading.offset(), UtcOffset::UTC);
        assert_eq!(reading, start);
        assert_eq!(reading, datetime!(2026-01-02 03:04:05 UTC));

        let later = datetime!(2026-06-01 10:30:00 +02:00);
        clock.set(later);
        let reading = clock.now_utc();
        assert_eq!(reading.offset(), UtcOffset::UTC);
        assert_eq!(reading, later);
        assert_eq!(reading, datetime!(2026-06-01 08:30:00 UTC));

        // Advancing after a non-UTC `set` still reads in UTC and moves by exactly the duration.
        clock.advance(Duration::seconds(90));
        let reading = clock.now_utc();
        assert_eq!(reading.offset(), UtcOffset::UTC);
        assert_eq!(reading, datetime!(2026-06-01 08:31:30 UTC));
    }

    #[test]
    fn test_system_clock_tracks_real_time() {
        let before = OffsetDateTime::now_utc();
        let reading = SystemClock.now_utc();
        let after = OffsetDateTime::now_utc();
        assert!(before <= reading && reading <= after);
        assert_eq!(reading.offset(), time::UtcOffset::UTC);
    }
}
