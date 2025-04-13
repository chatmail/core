//! DC release info.

use chrono::NaiveDate;
use std::sync::LazyLock;

const DATE_STR: &str = include_str!("../release-date.in");

/// Last release date.
pub static DATE: LazyLock<NaiveDate> =
    LazyLock::new(|| NaiveDate::parse_from_str(DATE_STR, "%Y-%m-%d").unwrap());
