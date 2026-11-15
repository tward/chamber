//! Clock readings for the TUI inactivity timer.
//!
//! A reading carries two clocks taken at the same moment. The monotonic clock is immune to wall-clock
//! adjustments, but on Linux it is expected not to advance while the machine is suspended. The wall clock
//! does advance across suspend, so it is what makes suspended time count toward inactivity.

use std::time::{Duration, Instant, SystemTime};

/// One reading of both clocks, taken at the same moment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClockReading {
    /// Time since an arbitrary fixed origin on the monotonic clock.
    pub(crate) monotonic: Duration,
    /// Wall-clock time.
    pub(crate) wall: SystemTime,
}

/// Source of clock readings, injectable so tests can control time.
pub(crate) trait Clock {
    fn now(&self) -> ClockReading;
}

/// The production clock, backed by `Instant` and `SystemTime`.
pub(crate) struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub(crate) fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> ClockReading {
        ClockReading {
            monotonic: self.origin.elapsed(),
            wall: SystemTime::now(),
        }
    }
}
