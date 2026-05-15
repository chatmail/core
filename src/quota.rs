//! # Support for IMAP QUOTA extension.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context as _, Result};
use async_imap::types::{Quota, QuotaResource};

use crate::EventType;
use crate::context::Context;
use crate::imap::session::Session as ImapSession;
use crate::tools::{self, time_elapsed};

/// quota icon in connectivity is "yellow".
pub const QUOTA_WARN_THRESHOLD_PERCENTAGE: u64 = 80;

/// quota icon in connectivity is "red".
pub const QUOTA_ERROR_THRESHOLD_PERCENTAGE: u64 = 95;

/// [QuotaInfo] error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Quota info not supported by the provider
    #[error("Quota info not supported by the provider")]
    NotSupportedByProvider,

    /// Any other error: network, parsing, etc.
    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

/// Server quota information with an update timestamp.
#[derive(Debug)]
pub struct QuotaInfo {
    /// Recently loaded quota information.
    /// set to `Err()` if the provider does not support quota or on other errors,
    /// set to `Ok()` for valid quota information.
    pub(crate) recent: Result<BTreeMap<String, Vec<QuotaResource>>, Error>,

    /// When the structure was modified.
    pub(crate) modified: tools::Time,
}

async fn get_unique_quota_roots_and_usage(
    session: &mut ImapSession,
    folder: &str,
) -> Result<BTreeMap<String, Vec<QuotaResource>>> {
    let mut unique_quota_roots: BTreeMap<String, Vec<QuotaResource>> = BTreeMap::new();
    let (quota_roots, quotas) = &session.get_quota_root(folder).await?;
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
    Ok(unique_quota_roots)
}

impl Context {
    /// Returns whether the quota value needs an update. If so, `update_recent_quota()` should be
    /// called.
    pub(crate) async fn quota_needs_update(&self, transport_id: u32, ratelimit_secs: u64) -> bool {
        let quota = self.quota.read().await;
        quota.get(&transport_id).is_none_or(|quota| {
            time_elapsed(&quota.modified) >= Duration::from_secs(ratelimit_secs)
        })
    }

    /// Updates `quota.recent`, sets `quota.modified` to the current time
    /// and emits an event to let the UIs update connectivity view.
    pub(crate) async fn update_recent_quota(
        &self,
        session: &mut ImapSession,
        folder: &str,
    ) -> Result<()> {
        let transport_id = session.transport_id();

        info!(self, "Transport {transport_id}: Updating quota.");

        let quota = if session.can_check_quota() {
            get_unique_quota_roots_and_usage(session, folder)
                .await
                .map_err(Error::Other)
        } else {
            Err(Error::NotSupportedByProvider)
        };

        self.quota.write().await.insert(
            transport_id,
            QuotaInfo {
                recent: quota,
                modified: tools::Time::now(),
            },
        );

        info!(self, "Transport {transport_id}: Updated quota.");
        self.emit_event(EventType::ConnectivityChanged);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContextManager;

    #[expect(clippy::assertions_on_constants)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quota_thresholds() -> anyhow::Result<()> {
        assert!(0 < QUOTA_WARN_THRESHOLD_PERCENTAGE);
        assert!(QUOTA_WARN_THRESHOLD_PERCENTAGE < QUOTA_ERROR_THRESHOLD_PERCENTAGE);
        assert!(QUOTA_ERROR_THRESHOLD_PERCENTAGE < 100);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quota_needs_update() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let t = &tcm.unconfigured().await;
        const TIMEOUT: u64 = 60;
        assert!(t.quota_needs_update(0, TIMEOUT).await);

        *t.quota.write().await = {
            let mut map = BTreeMap::new();
            map.insert(
                0,
                QuotaInfo {
                    recent: Ok(Default::default()),
                    modified: tools::Time::now() - Duration::from_secs(TIMEOUT + 1),
                },
            );
            map
        };
        assert!(t.quota_needs_update(0, TIMEOUT).await);

        *t.quota.write().await = {
            let mut map = BTreeMap::new();
            map.insert(
                0,
                QuotaInfo {
                    recent: Ok(Default::default()),
                    modified: tools::Time::now(),
                },
            );
            map
        };
        assert!(!t.quota_needs_update(0, TIMEOUT).await);

        t.evtracker.clear_events();
        t.set_primary_self_addr("new@addr").await?;
        assert!(t.quota.read().await.is_empty());
        t.evtracker
            .get_matching(|evt| matches!(evt, EventType::ConnectivityChanged))
            .await;
        assert!(t.quota_needs_update(0, TIMEOUT).await);

        Ok(())
    }
}
