#![allow(missing_docs)]

use std::sync::RwLock;
use std::time::{Duration, SystemTime};

static SYSTEM_TIME_SHIFT: RwLock<Duration> = RwLock::new(Duration::new(0, 0));

/// Fake struct for mocking `SystemTime::now()` for test purposes. You still need to use
/// `SystemTime` as a struct representing a system time.
pub struct SystemTimeTools();

impl SystemTimeTools {
    pub const UNIX_EPOCH: SystemTime = SystemTime::UNIX_EPOCH;

    pub fn now() -> SystemTime {
        return SystemTime::now() + *SYSTEM_TIME_SHIFT.read().unwrap();
    }

    /// Simulates a system clock forward adjustment by `duration`.
    pub fn shift(duration: Duration) {
        *SYSTEM_TIME_SHIFT.write().unwrap() += duration;
    }

    /// Simulates the system clock being rewound by `duration`.
    pub fn shift_back(duration: Duration) {
        *SYSTEM_TIME_SHIFT.write().unwrap() -= duration;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        SystemTimeTools::shift(Duration::from_secs(60));
        let t = SystemTimeTools::now();
        assert!(t > SystemTime::now());
    }
}
