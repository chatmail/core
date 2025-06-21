//! # IMAP folder selection module.

use anyhow::Context as _;

use super::session::Session as ImapSession;
use super::{get_uid_next, get_uidvalidity, set_modseq, set_uid_next, set_uidvalidity};
use crate::context::Context;
use crate::log::{info, warn};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Got a NO response when trying to select {0}, usually this means that it doesn't exist: {1}")]
    NoFolder(String, String),

    #[error("IMAP other error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Error {
        Error::Other(format!("{err:#}"))
    }
}

impl ImapSession {
    /// Issues a CLOSE command if selected folder needs expunge,
    /// i.e. if Delta Chat marked a message there as deleted previously.
    ///
    /// CLOSE is considerably faster than an EXPUNGE
    /// because no EXPUNGE responses are sent, see
    /// <https://tools.ietf.org/html/rfc3501#section-6.4.2>
    pub(super) async fn maybe_close_folder(&mut self, context: &Context) -> anyhow::Result<()> {
        if let Some(folder) = &self.selected_folder {
            if self.selected_folder_needs_expunge {
                info!(context, "Expunge messages in {folder:?}.");

                self.close().await.context("IMAP close/expunge failed")?;
                info!(context, "Close/expunge succeeded.");
                self.selected_folder = None;
                self.selected_folder_needs_expunge = false;
                self.new_mail = false;
            }
        }
        Ok(())
    }

    /// Selects a folder, possibly updating uid_validity and, if needed,
    /// expunging the folder to remove delete-marked messages.
    /// Returns whether a new folder was selected.
    async fn select_folder(&mut self, context: &Context, folder: &str) -> Result<NewlySelected> {
        // if there is a new folder and the new folder is equal to the selected one, there's nothing to do.
        // if there is _no_ new folder, we continue as we might want to expunge below.
        if let Some(selected_folder) = &self.selected_folder {
            if folder == selected_folder {
                return Ok(NewlySelected::No);
            }
        }

        // deselect existing folder, if needed (it's also done implicitly by SELECT, however, without EXPUNGE then)
        self.maybe_close_folder(context).await?;

        // select new folder
        let res = if self.can_condstore() {
            self.select_condstore(folder).await
        } else {
            self.select(folder).await
        };

        // <https://tools.ietf.org/html/rfc3501#section-6.3.1>
        // says that if the server reports select failure we are in
        // authenticated (not-select) state.

        match res {
            Ok(mailbox) => {
                info!(context, "Selected folder {folder:?}.");
                self.selected_folder = Some(folder.to_string());
                self.selected_mailbox = Some(mailbox);
                Ok(NewlySelected::Yes)
            }
            Err(async_imap::error::Error::No(response)) => {
                Err(Error::NoFolder(folder.to_string(), response))
            }
            Err(err) => Err(Error::Other(err.to_string())),
        }
    }

    /// Selects a folder. Tries to create it once and select again if the folder does not exist.
    pub(super) async fn select_or_create_folder(
        &mut self,
        context: &Context,
        folder: &str,
    ) -> anyhow::Result<NewlySelected> {
        match self.select_folder(context, folder).await {
            Ok(newly_selected) => Ok(newly_selected),
            Err(err) => match err {
                Error::NoFolder(..) => {
                    info!(context, "Failed to select folder {folder:?} because it does not exist, trying to create it.");
                    let create_res = self.create(folder).await;
                    if let Err(ref err) = create_res {
                        info!(context, "Couldn't select folder, then create() failed: {err:#}.");
                        // Need to recheck, could have been created in parallel.
                    }
                    let select_res = self.select_folder(context, folder).await.with_context(|| format!("failed to select newely created folder {folder}"));
                    if select_res.is_err() {
                        create_res?;
                    }
                    select_res
                }
                _ => Err(err).with_context(|| format!("failed to select folder {folder} with error other than NO, not trying to create it")),
            },
        }
    }

    /// Selects a folder optionally creating it and takes care of UIDVALIDITY changes. Returns false
    /// iff `folder` doesn't exist.
    ///
    /// When selecting a folder for the first time, sets the uid_next to the current
    /// mailbox.uid_next so that no old emails are fetched.
    ///
    /// Updates `self.new_mail` if folder was previously unselected
    /// and new mails are detected after selecting,
    /// i.e. UIDNEXT advanced while the folder was closed.
    pub(crate) async fn select_with_uidvalidity(
        &mut self,
        context: &Context,
        folder: &str,
        create: bool,
    ) -> Result<bool> {
        let newly_selected = if create {
            self.select_or_create_folder(context, folder)
                .await
                .with_context(|| format!("Failed to select or create folder {folder:?}"))?
        } else {
            match self.select_folder(context, folder).await {
                Ok(newly_selected) => newly_selected,
                Err(err) => match err {
                    Error::NoFolder(..) => return Ok(false),
                    _ => {
                        return Err(err)
                            .with_context(|| format!("Failed to select folder {folder:?}"))?
                    }
                },
            }
        };
        let mailbox = self
            .selected_mailbox
            .as_mut()
            .with_context(|| format!("No mailbox selected, folder: {folder:?}"))?;

        let old_uid_validity = get_uidvalidity(context, folder)
            .await
            .with_context(|| format!("Failed to get old UID validity for folder {folder:?}"))?;
        let old_uid_next = get_uid_next(context, folder)
            .await
            .with_context(|| format!("Failed to get old UID NEXT for folder {folder:?}"))?;

        let new_uid_validity = mailbox
            .uid_validity
            .with_context(|| format!("No UIDVALIDITY for folder {folder}"))?;
        let new_uid_next = if let Some(uid_next) = mailbox.uid_next {
            Some(uid_next)
        } else {
            warn!(
                context,
                "SELECT response for IMAP folder {folder:?} has no UIDNEXT, fall back to STATUS command."
            );

            // RFC 3501 says STATUS command SHOULD NOT be used
            // on the currently selected mailbox because the same
            // information can be obtained by other means,
            // such as reading SELECT response.
            //
            // However, it also says that UIDNEXT is REQUIRED
            // in the SELECT response and if we are here,
            // it is actually not returned.
            //
            // In particular, Winmail Pro Mail Server 5.1.0616
            // never returns UIDNEXT in SELECT response,
            // but responds to "STATUS INBOX (UIDNEXT)" command.
            let status = self
                .inner
                .status(folder, "(UIDNEXT)")
                .await
                .with_context(|| format!("STATUS (UIDNEXT) error for {folder:?}"))?;

            if status.uid_next.is_none() {
                // This happens with mail.163.com as of 2023-11-26.
                // It does not return UIDNEXT on SELECT and returns invalid
                // `* STATUS "INBOX" ()` response on explicit request for UIDNEXT.
                warn!(context, "STATUS {folder} (UIDNEXT) did not return UIDNEXT.");
            }
            status.uid_next
        };
        mailbox.uid_next = new_uid_next;

        if new_uid_validity == old_uid_validity {
            if newly_selected == NewlySelected::Yes {
                if let Some(new_uid_next) = new_uid_next {
                    if new_uid_next < old_uid_next {
                        warn!(
                            context,
                            "The server illegally decreased the uid_next of folder {folder:?} from {old_uid_next} to {new_uid_next} without changing validity ({new_uid_validity}), resyncing UIDs...",
                        );
                        set_uid_next(context, folder, new_uid_next).await?;
                        context.schedule_resync().await?;
                    }

                    // If UIDNEXT changed, there are new emails.
                    self.new_mail |= new_uid_next != old_uid_next;
                } else {
                    warn!(context, "Folder {folder} was just selected but we failed to determine UIDNEXT, assume that it has new mail.");
                    self.new_mail = true;
                }
            }

            return Ok(true);
        }

        // UIDVALIDITY is modified, reset highest seen MODSEQ.
        set_modseq(context, folder, 0).await?;

        // ==============  uid_validity has changed or is being set the first time.  ==============

        let new_uid_next = new_uid_next.unwrap_or_default();
        set_uid_next(context, folder, new_uid_next).await?;
        set_uidvalidity(context, folder, new_uid_validity).await?;
        self.new_mail = true;

        // Collect garbage entries in `imap` table.
        context
            .sql
            .execute(
                "DELETE FROM imap WHERE folder=? AND uidvalidity!=?",
                (&folder, new_uid_validity),
            )
            .await?;

        if old_uid_validity != 0 || old_uid_next != 0 {
            context.schedule_resync().await?;
        }
        info!(
            context,
            "uid/validity change folder {}: new {}/{} previous {}/{}.",
            folder,
            new_uid_next,
            new_uid_validity,
            old_uid_next,
            old_uid_validity,
        );
        Ok(true)
    }
}

#[derive(PartialEq, Debug, Copy, Clone, Eq)]
pub(crate) enum NewlySelected {
    /// The folder was newly selected during this call to select_folder().
    Yes,
    /// No SELECT command was run because the folder already was selected
    /// and self.config.selected_mailbox was not updated (so, e.g. it may contain an outdated uid_next)
    No,
}
