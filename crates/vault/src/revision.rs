//! Revisions: the version stamp every vault entry carries.
//!
//! A [`Revision`] orders writes to an entry. Each local create or edit gets the next revision
//! from [`next_local_revision`], which always sorts after every revision the machine has seen
//! (its [`HighWaterMark`]), even when the clock moves backward.
//!
//! Nothing in this module reads the system clock. The time in milliseconds comes from
//! [`unix_millis`], applied to a timestamp the caller already holds (a `Vault` takes it from
//! its clock).

use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

/// The version stamp of one write to a vault entry.
///
/// Revisions compare field by field in declaration order: `wall_ms` first, then `counter`,
/// then `device_id`. `Uuid` compares as its 16 bytes, unsigned, so the device ID breaks ties
/// between two machines that wrote at the same `(wall_ms, counter)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Revision {
    /// Milliseconds since the Unix epoch, or a later value when the machine's high-water mark
    /// was already ahead of its clock.
    pub wall_ms: u64,
    /// Orders revisions that share a `wall_ms`.
    pub counter: u32,
    /// The device that made the write.
    pub device_id: Uuid,
}

impl Revision {
    /// The high-water mark this revision leaves behind: its `(wall_ms, counter)`.
    #[must_use]
    pub const fn high_water_mark(self) -> HighWaterMark {
        HighWaterMark {
            wall_ms: self.wall_ms,
            counter: self.counter,
        }
    }
}

/// The greatest `(wall_ms, counter)` this machine has seen in any revision.
///
/// Ordered by `wall_ms`, then `counter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HighWaterMark {
    /// The greatest `wall_ms` seen.
    pub wall_ms: u64,
    /// The greatest `counter` seen at that `wall_ms`.
    pub counter: u32,
}

/// Returned by [`next_local_revision`] when no revision is left after the high-water mark:
/// both `wall_ms` and `counter` are at their maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionSpaceExhausted;

impl fmt::Display for RevisionSpaceExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "No revision is left after the vault's high-water mark (wall_ms and counter are both at their maximum)",
        )
    }
}

impl std::error::Error for RevisionSpaceExhausted {}

/// Computes the revision for the next local write.
///
/// * If `now_ms` is greater than `hwm.wall_ms`, the revision is `(now_ms, 0, device_id)`.
/// * Otherwise it is `(hwm.wall_ms, hwm.counter + 1, device_id)`. This covers a clock that
///   stands still, moves backward, or is behind a high-water mark from the future.
/// * If the counter would overflow, `wall_ms` advances by one and the counter resets to zero.
///
/// The new high-water mark is the returned revision's `(wall_ms, counter)`
/// ([`Revision::high_water_mark`]). The result always sorts after every revision whose
/// `(wall_ms, counter)` is at or below `hwm`.
///
/// # Errors
/// Returns [`RevisionSpaceExhausted`] when `hwm` is `(u64::MAX, u32::MAX)` and `now_ms` is not
/// ahead of it, instead of wrapping around.
pub const fn next_local_revision(
    hwm: HighWaterMark,
    now_ms: u64,
    device_id: Uuid,
) -> Result<Revision, RevisionSpaceExhausted> {
    if now_ms > hwm.wall_ms {
        return Ok(Revision {
            wall_ms: now_ms,
            counter: 0,
            device_id,
        });
    }
    match hwm.counter.checked_add(1) {
        Some(counter) => Ok(Revision {
            wall_ms: hwm.wall_ms,
            counter,
            device_id,
        }),
        None => match hwm.wall_ms.checked_add(1) {
            Some(wall_ms) => Ok(Revision {
                wall_ms,
                counter: 0,
                device_id,
            }),
            None => Err(RevisionSpaceExhausted),
        },
    }
}

/// Milliseconds since the Unix epoch for `t`, truncated, or 0 for a time before the epoch.
///
/// This converts a timestamp the caller supplies; it does not read the system clock.
#[must_use]
pub fn unix_millis(t: OffsetDateTime) -> u64 {
    let ms = t.unix_timestamp_nanos() / 1_000_000;
    // Negative (pre-epoch) values seed 0. `OffsetDateTime` cannot reach u64::MAX
    // milliseconds, so the saturating arm is unreachable in practice.
    if ms < 0 {
        0
    } else {
        u64::try_from(ms).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const DEV_A: Uuid = Uuid::from_bytes([0x11; 16]);

    fn dev(bytes: [u8; 16]) -> Uuid {
        Uuid::from_bytes(bytes)
    }

    fn hwm(wall_ms: u64, counter: u32) -> HighWaterMark {
        HighWaterMark { wall_ms, counter }
    }

    #[test]
    fn test_ordering_wall_ms_dominates_counter() {
        let low = Revision {
            wall_ms: 1,
            counter: u32::MAX,
            device_id: dev([0xFF; 16]),
        };
        let high = Revision {
            wall_ms: 2,
            counter: 0,
            device_id: Uuid::nil(),
        };
        assert!(low < high);
    }

    #[test]
    fn test_ordering_counter_dominates_device_id() {
        let low = Revision {
            wall_ms: 5,
            counter: 1,
            device_id: dev([0xFF; 16]),
        };
        let high = Revision {
            wall_ms: 5,
            counter: 2,
            device_id: Uuid::nil(),
        };
        assert!(low < high);
    }

    #[test]
    fn test_ordering_device_id_breaks_ties_as_unsigned_bytes() {
        // 0x7F < 0x80 unsigned, but 0x80 would be negative as i8: the ordering must be unsigned.
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a[3] = 0x7F;
        b[3] = 0x80;
        let ra = Revision {
            wall_ms: 5,
            counter: 1,
            device_id: dev(a),
        };
        let rb = Revision {
            wall_ms: 5,
            counter: 1,
            device_id: dev(b),
        };
        assert!(ra < rb);

        // Both bytes at or above 0x80.
        a[0] = 0x80;
        b[0] = 0xFE;
        let ra = Revision {
            device_id: dev(a),
            ..ra
        };
        let rb = Revision {
            device_id: dev(b),
            ..rb
        };
        assert!(ra < rb);
        assert_eq!(ra.cmp(&ra), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_default_is_zero_revision() {
        let r = Revision::default();
        assert_eq!(r.wall_ms, 0);
        assert_eq!(r.counter, 0);
        assert_eq!(r.device_id, Uuid::nil());
    }

    #[test]
    fn test_next_when_now_ahead_of_hwm() {
        let r = next_local_revision(hwm(1_000, 7), 2_000, DEV_A).unwrap();
        assert_eq!(
            r,
            Revision {
                wall_ms: 2_000,
                counter: 0,
                device_id: DEV_A
            }
        );
        assert_eq!(r.high_water_mark(), hwm(2_000, 0));
    }

    #[test]
    fn test_next_when_now_equals_hwm() {
        let r = next_local_revision(hwm(1_000, 7), 1_000, DEV_A).unwrap();
        assert_eq!(
            r,
            Revision {
                wall_ms: 1_000,
                counter: 8,
                device_id: DEV_A
            }
        );
        assert_eq!(r.high_water_mark(), hwm(1_000, 8));
    }

    #[test]
    fn test_next_when_clock_rolled_back() {
        let r = next_local_revision(hwm(1_000, 0), 400, DEV_A).unwrap();
        assert_eq!(
            r,
            Revision {
                wall_ms: 1_000,
                counter: 1,
                device_id: DEV_A
            }
        );
    }

    #[test]
    fn test_next_when_hwm_far_in_future() {
        let future = unix_millis(datetime!(2400-01-01 00:00:00 UTC));
        let now = unix_millis(datetime!(2026-11-17 00:00:00 UTC));
        let prev = Revision {
            wall_ms: future,
            counter: 3,
            device_id: dev([0xFF; 16]),
        };
        let r = next_local_revision(prev.high_water_mark(), now, Uuid::nil()).unwrap();
        assert_eq!(r.wall_ms, future);
        assert_eq!(r.counter, 4);
        assert!(r > prev, "a later local write must sort after the future-dated one");
    }

    #[test]
    fn test_counter_overflow_advances_wall_ms() {
        let r = next_local_revision(hwm(1_000, u32::MAX), 1_000, DEV_A).unwrap();
        assert_eq!(
            r,
            Revision {
                wall_ms: 1_001,
                counter: 0,
                device_id: DEV_A
            }
        );
        let prev = Revision {
            wall_ms: 1_000,
            counter: u32::MAX,
            device_id: dev([0xFF; 16]),
        };
        assert!(r > prev);
    }

    #[test]
    fn test_exhausted_returns_error() {
        let err = next_local_revision(hwm(u64::MAX, u32::MAX), 0, DEV_A).unwrap_err();
        assert_eq!(err, RevisionSpaceExhausted);
        assert!(err.to_string().contains("high-water mark"));
        // now cannot be ahead of u64::MAX either.
        assert!(next_local_revision(hwm(u64::MAX, u32::MAX), u64::MAX, DEV_A).is_err());
        // One step below exhaustion still works.
        let r = next_local_revision(hwm(u64::MAX, u32::MAX - 1), 0, DEV_A).unwrap();
        assert_eq!((r.wall_ms, r.counter), (u64::MAX, u32::MAX));
    }

    #[test]
    fn test_unix_millis() {
        assert_eq!(unix_millis(datetime!(1970-01-01 00:00:00 UTC)), 0);
        assert_eq!(unix_millis(datetime!(1970-01-01 00:00:01.234_999 UTC)), 1_234);
        assert_eq!(unix_millis(datetime!(1969-12-31 23:59:59 UTC)), 0);
        assert_eq!(unix_millis(datetime!(1900-01-01 00:00:00 UTC)), 0);
        assert_eq!(
            unix_millis(datetime!(2026-01-01 02:00:00 +02:00)),
            unix_millis(datetime!(2026-01-01 00:00:00 UTC))
        );
        assert_eq!(unix_millis(datetime!(2026-01-01 00:00:00 UTC)), 1_767_225_600_000);
    }
}
