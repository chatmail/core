//! # Support for IMAP QUOTA extension.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use async_imap::types::{Quota, QuotaResource};

use crate::chat::add_device_msg_with_importance;
use crate::config::Config;
use crate::context::Context;
use crate::imap::scan_folders::get_watched_folders;
use crate::imap::session::Session as ImapSession;
use crate::log::warn;
use crate::message::Message;
use crate::tools::{self, time_elapsed};
use crate::{stock_str, EventType};

/// warn about a nearly full mailbox after this usage percentage is reached.
/// quota icon is "yellow".
pub const QUOTA_WARN_THRESHOLD_PERCENTAGE: u64 = 80;

/// warning again after this usage percentage is reached,
/// quota icon is "red".
pub const QUOTA_ERROR_THRESHOLD_PERCENTAGE: u64 = 95;

/// if quota is below this value (again),
/// QuotaExceeding is cleared.
///
/// This value should be a bit below QUOTA_WARN_THRESHOLD_PERCENTAGE to
/// avoid jittering and lots of warnings when quota is exactly at the warning threshold.
///
/// We do not repeat warnings on a daily base or so as some provider
/// providers report bad values and we would then spam the user.
pub const QUOTA_ALLCLEAR_PERCENTAGE: u64 = 75;

/// Server quota information with an update timestamp.
#[derive(Debug)]
pub struct QuotaInfo {
    /// Recently loaded quota information.
    /// set to `Err()` if the provider does not support quota or on other errors,
    /// set to `Ok()` for valid quota information.
    pub(crate) recent: Result<BTreeMap<String, Vec<QuotaResource>>>,

    /// When the structure was modified.
    pub(crate) modified: tools::Time,
}

async fn get_unique_quota_roots_and_usage(
    session: &mut ImapSession,
    folders: Vec<String>,
) -> Result<BTreeMap<String, Vec<QuotaResource>>> {
    let mut unique_quota_roots: BTreeMap<String, Vec<QuotaResource>> = BTreeMap::new();
    for folder in folders {
        let (quota_roots, quotas) = &session.get_quota_root(&folder).await?;
        // if there are new quota roots found in this imap folder, add them to the list
        for qr_entries in quota_roots {
            for quota_root_name in &qr_entries.quota_root_names {
                // the quota for that quota root
                let quota: Quota = quotas
                    .iter()
                    .find(|q| &q.root_name == quota_root_name)
                    .cloned()
                    .context("quota_root should have a quota")?;
                // replace old quotas, because between fetching quotaroots for folders,
                // messages could be received and so the usage could have been changed
                *unique_quota_roots
                    .entry(quota_root_name.clone())
                    .or_default() = quota.resources;
            }
        }
    }
    Ok(unique_quota_roots)
}

fn get_highest_usage<'t>(
    unique_quota_roots: &'t BTreeMap<String, Vec<QuotaResource>>,
) -> Result<(u64, &'t String, &'t QuotaResource)> {
    let mut highest: Option<(u64, &'t String, &QuotaResource)> = None;
    for (name, resources) in unique_quota_roots {
        for r in resources {
            let usage_percent = r.get_usage_percentage();
            match highest {
                None => {
                    highest = Some((usage_percent, name, r));
                }
                Some((up, ..)) => {
                    if up <= usage_percent {
                        highest = Some((usage_percent, name, r));
                    }
                }
            };
        }
    }

    highest.context("no quota_resource found, this is unexpected")
}

/// Checks if a quota warning is needed.
pub fn needs_quota_warning(curr_percentage: u64, warned_at_percentage: u64) -> bool {
    (curr_percentage >= QUOTA_WARN_THRESHOLD_PERCENTAGE
        && warned_at_percentage < QUOTA_WARN_THRESHOLD_PERCENTAGE)
        || (curr_percentage >= QUOTA_ERROR_THRESHOLD_PERCENTAGE
            && warned_at_percentage < QUOTA_ERROR_THRESHOLD_PERCENTAGE)
}

impl Context {
    /// Returns whether the quota value needs an update. If so, `update_recent_quota()` should be
    /// called.
    pub(crate) async fn quota_needs_update(&self, ratelimit_secs: u64) -> bool {
        let quota = self.quota.read().await;
        quota
            .as_ref()
            .filter(|quota| time_elapsed(&quota.modified) < Duration::from_secs(ratelimit_secs))
            .is_none()
    }

    /// Updates `quota.recent`, sets `quota.modified` to the current time
    /// and emits an event to let the UIs update connectivity view.
    ///
    /// Moreover, once each time quota gets larger than `QUOTA_WARN_THRESHOLD_PERCENTAGE`,
    /// a device message is added.
    /// As the message is added only once, the user is not spammed
    /// in case for some providers the quota is always at ~100%
    /// and new space is allocated as needed.
    pub(crate) async fn update_recent_quota(&self, session: &mut ImapSession) -> Result<()> {
        let quota = if session.can_check_quota() {
            let folders = get_watched_folders(self).await?;
            get_unique_quota_roots_and_usage(session, folders).await
        } else {
            Err(anyhow!(stock_str::not_supported_by_provider(self).await))
        };

        if let Ok(quota) = &quota {
            match get_highest_usage(quota) {
                Ok((highest, _, _)) => {
                    if needs_quota_warning(
                        highest,
                        self.get_config_int(Config::QuotaExceeding).await? as u64,
                    ) {
                        self.set_config_internal(
                            Config::QuotaExceeding,
                            Some(&highest.to_string()),
                        )
                        .await?;
                        let mut msg =
                            Message::new_text(stock_str::quota_exceeding(self, highest).await);
                        add_device_msg_with_importance(self, None, Some(&mut msg), true).await?;
                    } else if highest <= QUOTA_ALLCLEAR_PERCENTAGE {
                        self.set_config_internal(Config::QuotaExceeding, None)
                            .await?;
                    }
                }
                Err(err) => warn!(self, "cannot get highest quota usage: {:#}", err),
            }
        }

        *self.quota.write().await = Some(QuotaInfo {
            recent: quota,
            modified: tools::Time::now(),
        });

        self.emit_event(EventType::ConnectivityChanged);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContextManager;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_needs_quota_warning() -> Result<()> {
        assert!(!needs_quota_warning(0, 0));
        assert!(!needs_quota_warning(10, 0));
        assert!(!needs_quota_warning(70, 0));
        assert!(!needs_quota_warning(75, 0));
        assert!(!needs_quota_warning(79, 0));
        assert!(needs_quota_warning(80, 0));
        assert!(needs_quota_warning(81, 0));
        assert!(!needs_quota_warning(85, 80));
        assert!(!needs_quota_warning(85, 81));
        assert!(needs_quota_warning(95, 82));
        assert!(!needs_quota_warning(97, 95));
        assert!(!needs_quota_warning(97, 96));
        assert!(!needs_quota_warning(1000, 96));
        Ok(())
    }

    #[expect(clippy::assertions_on_constants)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quota_thresholds() -> anyhow::Result<()> {
        assert!(QUOTA_ALLCLEAR_PERCENTAGE > 50);
        assert!(QUOTA_ALLCLEAR_PERCENTAGE < QUOTA_WARN_THRESHOLD_PERCENTAGE);
        assert!(QUOTA_WARN_THRESHOLD_PERCENTAGE < QUOTA_ERROR_THRESHOLD_PERCENTAGE);
        assert!(QUOTA_ERROR_THRESHOLD_PERCENTAGE < 100);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quota_needs_update() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let t = &tcm.unconfigured().await;
        const TIMEOUT: u64 = 60;
        assert!(t.quota_needs_update(TIMEOUT).await);

        *t.quota.write().await = Some(QuotaInfo {
            recent: Ok(Default::default()),
            modified: tools::Time::now() - Duration::from_secs(TIMEOUT + 1),
        });
        assert!(t.quota_needs_update(TIMEOUT).await);

        *t.quota.write().await = Some(QuotaInfo {
            recent: Ok(Default::default()),
            modified: tools::Time::now(),
        });
        assert!(!t.quota_needs_update(TIMEOUT).await);

        t.evtracker.clear_events();
        t.set_primary_self_addr("new@addr").await?;
        assert!(t.quota.read().await.is_none());
        t.evtracker
            .get_matching(|evt| matches!(evt, EventType::ConnectivityChanged))
            .await;
        assert!(t.quota_needs_update(TIMEOUT).await);
        Ok(())
    }
}
