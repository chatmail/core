//! # Support for IMAP QUOTA extension.

use anyhow::{anyhow, Context as _, Result};
use async_imap::types::{Quota, QuotaResource};
use std::collections::BTreeMap;

use crate::chat::add_device_msg_with_importance;
use crate::config::Config;
use crate::context::Context;
use crate::dc_tools::time;
use crate::imap::scan_folders::get_watched_folders;
use crate::imap::Imap;
use crate::job::{Action, Status};
use crate::message::{Message, Viewtype};
use crate::param::Params;
use crate::{job, stock_str, EventType};

/// warn about a nearly full mailbox after this usage percentage is reached.
/// quota icon is "yellow".
pub const QUOTA_WARN_THRESHOLD_PERCENTAGE: u64 = 80;

// warning again after this usage percentage is reached,
// quota icon is "red".
pub const QUOTA_ERROR_THRESHOLD_PERCENTAGE: u64 = 95;

/// if quota is below this value (again),
/// QuotaExceeding is cleared.
/// This value should be a bit below QUOTA_WARN_THRESHOLD_PERCENTAGE to
/// avoid jittering and lots of warnings when quota is exactly at the warning threshold.
///
/// We do not repeat warnings on a daily base or so as some provider
/// providers report bad values and we would then spam the user.
pub const QUOTA_ALLCLEAR_PERCENTAGE: u64 = 75;

// if recent quota is older,
// it is re-fetched on dc_get_connectivity_html()
pub const QUOTA_MAX_AGE_SECONDS: i64 = 60;

#[derive(Debug)]
pub struct QuotaInfo {
    /// Recently loaded quota information.
    /// set to `Err()` if the provider does not support quota or on other errors,
    /// set to `Ok()` for valid quota information.
    /// Updated by `Action::UpdateRecentQuota`
    pub(crate) recent: Result<BTreeMap<String, Vec<QuotaResource>>>,

    /// Timestamp when structure was modified.
    pub(crate) modified: i64,
}

async fn get_unique_quota_roots_and_usage(
    folders: Vec<String>,
    imap: &mut Imap,
) -> Result<BTreeMap<String, Vec<QuotaResource>>> {
    let mut unique_quota_roots: BTreeMap<String, Vec<QuotaResource>> = BTreeMap::new();
    for folder in folders {
        let (quota_roots, quotas) = &imap.get_quota_roots(&folder).await?;
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
                // messages could be recieved and so the usage could have been changed
                *unique_quota_roots
                    .entry(quota_root_name.clone())
                    .or_insert_with(Vec::new) = quota.resources;
            }
        }
    }
    Ok(unique_quota_roots)
}

fn get_highest_usage<'t>(
    unique_quota_roots: &'t BTreeMap<String, Vec<QuotaResource>>,
) -> Result<(u64, &'t String, &QuotaResource)> {
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
    // Adds a job to update `quota.recent`
    pub(crate) async fn schedule_quota_update(&self) -> Result<()> {
        if !job::action_exists(self, Action::UpdateRecentQuota).await? {
            job::add(
                self,
                job::Job::new(Action::UpdateRecentQuota, 0, Params::new(), 0),
            )
            .await?;
        }
        Ok(())
    }

    /// Updates `quota.recent`, sets `quota.modified` to the current time
    /// and emits an event to let the UIs update connectivity view.
    ///
    /// Moreover, once each time quota gets larger than `QUOTA_WARN_THRESHOLD_PERCENTAGE`,
    /// a device message is added.
    /// As the message is added only once, the user is not spammed
    /// in case for some providers the quota is always at ~100%
    /// and new space is allocated as needed.
    ///
    /// Called in response to `Action::UpdateRecentQuota`.
    pub(crate) async fn update_recent_quota(&self, imap: &mut Imap) -> Result<Status> {
        if let Err(err) = imap.prepare(self).await {
            warn!(self, "could not connect: {:?}", err);
            return Ok(Status::RetryNow);
        }

        let quota = if imap.can_check_quota() {
            let folders = get_watched_folders(self).await?;
            get_unique_quota_roots_and_usage(folders, imap).await
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
                        self.set_config(Config::QuotaExceeding, Some(&highest.to_string()))
                            .await?;
                        let mut msg = Message::new(Viewtype::Text);
                        msg.text = Some(stock_str::quota_exceeding(self, highest).await);
                        add_device_msg_with_importance(self, None, Some(&mut msg), true).await?;
                    } else if highest <= QUOTA_ALLCLEAR_PERCENTAGE {
                        self.set_config(Config::QuotaExceeding, None).await?;
                    }
                }
                Err(err) => warn!(self, "cannot get highest quota usage: {:?}", err),
            }
        }

        *self.quota.write().await = Some(QuotaInfo {
            recent: quota,
            modified: time(),
        });

        self.emit_event(EventType::ConnectivityChanged);
        Ok(Status::Finished(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::{
        QUOTA_ALLCLEAR_PERCENTAGE, QUOTA_ERROR_THRESHOLD_PERCENTAGE,
        QUOTA_WARN_THRESHOLD_PERCENTAGE,
    };

    #[async_std::test]
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

    #[allow(clippy::assertions_on_constants)]
    #[async_std::test]
    async fn test_quota_thresholds() -> anyhow::Result<()> {
        assert!(QUOTA_ALLCLEAR_PERCENTAGE > 50);
        assert!(QUOTA_ALLCLEAR_PERCENTAGE < QUOTA_WARN_THRESHOLD_PERCENTAGE);
        assert!(QUOTA_WARN_THRESHOLD_PERCENTAGE < QUOTA_ERROR_THRESHOLD_PERCENTAGE);
        assert!(QUOTA_ERROR_THRESHOLD_PERCENTAGE < 100);
        Ok(())
    }
}
