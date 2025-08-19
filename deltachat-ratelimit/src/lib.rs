//! # Rate limiting module.
//!
//! This module contains implementation of token bucket policy.
//! Its primary use is preventing Delta Chat from sending too many messages, especially automatic,
//! such as read receipts.

use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub struct Ratelimit {
    /// Time of the last update.
    last_update: SystemTime,

    /// Number of messages sent within the time window ending at `last_update`.
    current_value: f64,

    /// Time window size.
    window: Duration,

    /// Number of messages allowed to send within the time window.
    quota: f64,
}

impl Ratelimit {
    /// Returns a new rate limiter with the given constraints.
    ///
    /// Rate limiter will allow to send no more than `quota` messages within duration `window`.
    pub fn new(window: Duration, quota: f64) -> Self {
        Self::new_at(window, quota, SystemTime::now())
    }

    /// Returns a new rate limiter with given current time for testing purposes.
    fn new_at(window: Duration, quota: f64, now: SystemTime) -> Self {
        Self {
            last_update: now,
            current_value: 0.0,
            window,
            quota,
        }
    }

    /// Returns current number of sent messages.
    fn current_value_at(&self, now: SystemTime) -> f64 {
        let rate: f64 = self.quota / self.window.as_secs_f64();
        let elapsed = now
            .duration_since(self.last_update)
            .unwrap_or(Duration::ZERO)
            .as_secs_f64();
        f64::max(0.0, self.current_value - rate * elapsed)
    }

    /// Returns true if it is allowed to send a message.
    fn can_send_at(&self, now: SystemTime) -> bool {
        self.current_value_at(now) + 1.0 <= self.quota
    }

    /// Returns true if can send another message now.
    ///
    /// This method takes mutable reference
    pub fn can_send(&self) -> bool {
        self.can_send_at(SystemTime::now())
    }

    fn send_at(&mut self, now: SystemTime) {
        self.current_value = f64::min(self.quota, self.current_value_at(now) + 1.0);
        self.last_update = now;
    }

    /// Increases current usage value.
    ///
    /// It is possible to send message even if over quota, e.g. if the message sending is initiated
    /// by the user and should not be rate limited. However, sending messages when over quota
    /// further postpones the time when it will be allowed to send low priority messages.
    pub fn send(&mut self) {
        self.send_at(SystemTime::now())
    }

    fn until_can_send_at(&self, now: SystemTime) -> Duration {
        let current_value = self.current_value_at(now);
        if current_value + 1.0 <= self.quota {
            Duration::ZERO
        } else {
            let requirement = current_value + 1.0 - self.quota;
            let rate = self.quota / self.window.as_secs_f64();
            Duration::from_secs_f64(requirement / rate)
        }
    }

    /// Calculates the time until `can_send` will return `true`.
    pub fn until_can_send(&self) -> Duration {
        self.until_can_send_at(SystemTime::now())
    }

    /// Returns the minimum possible sending interval.
    pub fn min_send_interval(&self) -> Duration {
        self.window.div_f64(self.quota)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratelimit() {
        let now = SystemTime::now();

        let mut ratelimit = Ratelimit::new_at(Duration::new(60, 0), 3.0, now);
        assert!(ratelimit.can_send_at(now));
        assert_eq!(ratelimit.min_send_interval(), Duration::new(20, 0));

        // Send burst of 3 messages.
        ratelimit.send_at(now);
        assert!(ratelimit.can_send_at(now));
        ratelimit.send_at(now);
        assert!(ratelimit.can_send_at(now));
        ratelimit.send_at(now);

        // Can't send more messages now.
        assert!(!ratelimit.can_send_at(now));

        // Can send one more message 20 seconds later.
        assert_eq!(ratelimit.until_can_send_at(now), Duration::from_secs(20));
        let now = now + Duration::from_secs(20);
        assert!(ratelimit.can_send_at(now));
        ratelimit.send_at(now);
        assert!(!ratelimit.can_send_at(now));

        // Send one more message anyway, over quota.
        ratelimit.send_at(now);

        // Always can send another message after 20 seconds,
        // leaky bucket never overflows.
        let now = now + Duration::from_secs(20);
        assert!(ratelimit.can_send_at(now));

        // Test that we don't panic if time appears to move backwards
        assert!(!ratelimit.can_send_at(now - Duration::from_secs(20)));
    }
}
