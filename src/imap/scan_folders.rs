use std::collections::BTreeMap;

use anyhow::{Context as _, Result};

use super::{get_folder_meaning_by_attrs, get_folder_meaning_by_name};
use crate::config::Config;
use crate::imap::{Imap, session::Session};
use crate::log::LogExt;
use crate::tools::{self, time_elapsed};
use crate::{context::Context, imap::FolderMeaning};

impl Imap {
    /// Returns true if folders were scanned, false if scanning was postponed.
    pub(crate) async fn scan_folders(
        &mut self,
        context: &Context,
        session: &mut Session,
    ) -> Result<bool> {
        // First of all, debounce to once per minute:
        {
            let mut last_scan = session.last_full_folder_scan.lock().await;
            if let Some(last_scan) = *last_scan {
                let elapsed_secs = time_elapsed(&last_scan).as_secs();
                let debounce_secs = context
                    .get_config_u64(Config::ScanAllFoldersDebounceSecs)
                    .await?;

                if elapsed_secs < debounce_secs {
                    return Ok(false);
                }
            }

            // Update the timestamp before scanning the folders
            // to avoid holding the lock for too long.
            // This means next scan is delayed even if
            // the current one fails.
            last_scan.replace(tools::Time::now());
        }
        info!(context, "Starting full folder scan");

        let folders = session.list_folders().await?;
        let watched_folders = get_watched_folders(context).await?;

        let mut folder_configs = BTreeMap::new();
        let mut folder_names = Vec::new();

        for folder in folders {
            let folder_meaning = get_folder_meaning_by_attrs(folder.attributes());
            if folder_meaning == FolderMeaning::Virtual {
                // Gmail has virtual folders that should be skipped. For example,
                // emails appear in the inbox and under "All Mail" as soon as it is
                // received. The code used to wrongly conclude that the email had
                // already been moved and left it in the inbox.
                continue;
            }
            folder_names.push(folder.name().to_string());
            let folder_name_meaning = get_folder_meaning_by_name(folder.name());

            if let Some(config) = folder_meaning.to_config() {
                // Always takes precedence
                folder_configs.insert(config, folder.name().to_string());
            } else if let Some(config) = folder_name_meaning.to_config() {
                // only set if none has been already set
                folder_configs
                    .entry(config)
                    .or_insert_with(|| folder.name().to_string());
            }

            let folder_meaning = match folder_meaning {
                FolderMeaning::Unknown => folder_name_meaning,
                _ => folder_meaning,
            };

            // Don't scan folders that are watched anyway
            if !watched_folders.contains(&folder.name().to_string())
                && folder_meaning != FolderMeaning::Trash
                && folder_meaning != FolderMeaning::Unknown
            {
                self.fetch_move_delete(context, session, folder.name(), folder_meaning)
                    .await
                    .context("Can't fetch new msgs in scanned folder")
                    .log_err(context)
                    .ok();
            }
        }

        info!(context, "Found folders: {folder_names:?}.");
        Ok(true)
    }
}

pub(crate) async fn get_watched_folder_configs(context: &Context) -> Result<Vec<Config>> {
    let mut res = vec![Config::ConfiguredInboxFolder];
    if context.should_watch_mvbox().await? {
        res.push(Config::ConfiguredMvboxFolder);
    }
    Ok(res)
}

pub(crate) async fn get_watched_folders(context: &Context) -> Result<Vec<String>> {
    let mut res = Vec::new();
    for folder_config in get_watched_folder_configs(context).await? {
        if let Some(folder) = context.get_config(folder_config).await? {
            res.push(folder);
        }
    }
    Ok(res)
}
