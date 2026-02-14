//! # Time smearing.
//!
//! As e-mails typically only use a second-based-resolution for timestamps,
//! the order of two mails sent within one second is unclear.
//! This is bad e.g. when forwarding some messages from a chat -
//! these messages will appear at the recipient easily out of order.
//!
//! We work around this issue by not sending out two mails with the same timestamp.
//! For this purpose, in short, we track the last timestamp used in `last_smeared_timestamp`
//! when another timestamp is needed in the same second, we use `last_smeared_timestamp+1`
//! after some moments without messages sent out,
//! `last_smeared_timestamp` is again in sync with the normal time.
//!
//! However, we do not do all this for the far future,
//! but at max `MAX_SECONDS_TO_LEND_FROM_FUTURE`

use std::cmp::{max, min};
use std::sync::atomic::{AtomicI64, Ordering};

pub(crate) const MAX_SECONDS_TO_LEND_FROM_FUTURE: i64 = 30;

/// Smeared timestamp generator.
#[derive(Debug)]
pub struct SmearedTimestamp {
    /// Next timestamp available for allocation.
    smeared_timestamp: AtomicI64,
}

impl SmearedTimestamp {
    /// Creates a new smeared timestamp generator.
    pub fn new() -> Self {
        Self {
            smeared_timestamp: AtomicI64::new(0),
        }
    }

    /// Allocates `count` unique timestamps.
    ///
    /// Returns the first allocated timestamp.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn create_n(&self, now: i64, count: i64) -> i64 {
        let mut prev = self.smeared_timestamp.load(Ordering::Relaxed);
        loop {
            // Advance the timestamp if it is in the past,
            // but keep `count - 1` timestamps from the past if possible.
            let t = max(prev, now - count + 1);

            // Rewind the time back if there is no room
            // to allocate `count` timestamps without going too far into the future.
            // Not going too far into the future
            // is more important than generating unique timestamps.
            let first = min(t, now + MAX_SECONDS_TO_LEND_FROM_FUTURE - count + 1);

            // Allocate `count` timestamps by advancing the current timestamp.
            let next = first + count;

            if let Err(x) = self.smeared_timestamp.compare_exchange_weak(
                prev,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                prev = x;
            } else {
                return first;
            }
        }
    }

    /// Creates a single timestamp.
    pub fn create(&self, now: i64) -> i64 {
        self.create_n(now, 1)
    }

    /// Returns the current smeared timestamp.
    pub fn current(&self) -> i64 {
        self.smeared_timestamp.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContext;
    use crate::tools::{
        SystemTime, create_smeared_timestamp, create_smeared_timestamps, smeared_time, time,
    };

    #[test]
    fn test_smeared_timestamp() {
        let smeared_timestamp = SmearedTimestamp::new();
        let now = time();

        assert_eq!(smeared_timestamp.current(), 0);

        for i in 0..MAX_SECONDS_TO_LEND_FROM_FUTURE {
            assert_eq!(smeared_timestamp.create(now), now + i);
        }
        assert_eq!(
            smeared_timestamp.create(now),
            now + MAX_SECONDS_TO_LEND_FROM_FUTURE
        );
        assert_eq!(
            smeared_timestamp.create(now),
            now + MAX_SECONDS_TO_LEND_FROM_FUTURE
        );

        // System time rewinds back by 1000 seconds.
        let now = now - 1000;
        assert_eq!(
            smeared_timestamp.create(now),
            now + MAX_SECONDS_TO_LEND_FROM_FUTURE
        );
        assert_eq!(
            smeared_timestamp.create(now),
            now + MAX_SECONDS_TO_LEND_FROM_FUTURE
        );
        assert_eq!(
            smeared_timestamp.create(now + 1),
            now + MAX_SECONDS_TO_LEND_FROM_FUTURE + 1
        );
        assert_eq!(smeared_timestamp.create(now + 100), now + 100);
        assert_eq!(smeared_timestamp.create(now + 100), now + 101);
        assert_eq!(smeared_timestamp.create(now + 100), now + 102);
    }

    #[test]
    fn test_create_n_smeared_timestamps() {
        let smeared_timestamp = SmearedTimestamp::new();
        let now = time();

        // Create a single timestamp to initialize the generator.
        assert_eq!(smeared_timestamp.create(now), now);

        // Wait a minute.
        let now = now + 60;

        // Simulate forwarding 7 messages.
        let forwarded_messages = 7;

        // We have not sent anything for a minute,
        // so we can take the current timestamp and take 6 timestamps from the past.
        assert_eq!(smeared_timestamp.create_n(now, forwarded_messages), now - 6);

        assert_eq!(smeared_timestamp.current(), now + 1);

        // Wait 4 seconds.
        // Now we have 3 free timestamps in the past.
        let now = now + 4;

        assert_eq!(smeared_timestamp.current(), now - 3);

        // Forward another 7 messages.
        // We can only lend 3 timestamps from the past.
        assert_eq!(smeared_timestamp.create_n(now, forwarded_messages), now - 3);

        // We had to borrow 3 timestamps from the future
        // because there were not enough timestamps in the past.
        assert_eq!(smeared_timestamp.current(), now + 4);

        // Forward another 32 messages.
        // We cannot use more than 30 timestamps from the future,
        // so we use 30 timestamps from the future,
        // the current timestamp and one timestamp from the past.
        assert_eq!(smeared_timestamp.create_n(now, 32), now - 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_create_smeared_timestamp() {
        let t = TestContext::new().await;
        assert_ne!(create_smeared_timestamp(&t), create_smeared_timestamp(&t));
        assert!(
            create_smeared_timestamp(&t)
                >= SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_create_smeared_timestamps() {
        let t = TestContext::new().await;
        let count = MAX_SECONDS_TO_LEND_FROM_FUTURE - 1;
        let start = create_smeared_timestamps(&t, count as usize);
        let next = smeared_time(&t);
        assert!((start + count - 1) < next);

        let count = MAX_SECONDS_TO_LEND_FROM_FUTURE + 30;
        let start = create_smeared_timestamps(&t, count as usize);
        let next = smeared_time(&t);
        assert!((start + count - 1) < next);
    }
}
