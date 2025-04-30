//! # Functions to update timestamps.

use anyhow::Result;

use crate::chat::ChatId;
use crate::contact::ContactId;
use crate::context::Context;
use crate::param::{Param, Params};

impl Context {
    /// Updates a contact's timestamp, if reasonable.
    /// Returns true if the caller shall update the settings belonging to the scope.
    /// (if we have a ContactId type at some point, the function should go there)
    pub(crate) async fn update_contacts_timestamp(
        &self,
        contact_id: ContactId,
        scope: Param,
        new_timestamp: i64,
    ) -> Result<bool> {
        self.sql
            .transaction(|transaction| {
                let mut param: Params = transaction.query_row(
                    "SELECT param FROM contacts WHERE id=?",
                    [contact_id],
                    |row| {
                        let param: String = row.get(0)?;
                        Ok(param.parse().unwrap_or_default())
                    },
                )?;
                let update = param.update_timestamp(scope, new_timestamp)?;
                if update {
                    transaction.execute(
                        "UPDATE contacts SET param=? WHERE id=?",
                        (param.to_string(), contact_id),
                    )?;
                }
                Ok(update)
            })
            .await
    }
}

impl ChatId {
    /// Updates a chat id's timestamp on disk, if reasonable.
    /// Returns true if the caller shall update the settings belonging to the scope.
    pub(crate) async fn update_timestamp(
        &self,
        context: &Context,
        scope: Param,
        new_timestamp: i64,
    ) -> Result<bool> {
        context
            .sql
            .transaction(|transaction| {
                let mut param: Params =
                    transaction.query_row("SELECT param FROM chats WHERE id=?", [self], |row| {
                        let param: String = row.get(0)?;
                        Ok(param.parse().unwrap_or_default())
                    })?;
                let update = param.update_timestamp(scope, new_timestamp)?;
                if update {
                    transaction.execute(
                        "UPDATE chats SET param=? WHERE id=?",
                        (param.to_string(), self),
                    )?;
                }
                Ok(update)
            })
            .await
    }
}

impl Params {
    /// Updates a param's timestamp in memory, if reasonable.
    /// Returns true if the caller shall update the settings belonging to the scope.
    pub(crate) fn update_timestamp(&mut self, scope: Param, new_timestamp: i64) -> Result<bool> {
        let old_timestamp = self.get_i64(scope).unwrap_or_default();
        if new_timestamp >= old_timestamp {
            self.set_i64(scope, new_timestamp);
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::Chat;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::TestContext;
    use crate::tools::time;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_params_update_timestamp() -> Result<()> {
        let mut params = Params::new();
        let ts = time();

        assert!(params.update_timestamp(Param::LastSubject, ts)?);
        assert!(params.update_timestamp(Param::LastSubject, ts)?); // same timestamp -> update
        assert!(params.update_timestamp(Param::LastSubject, ts + 10)?);
        assert!(!params.update_timestamp(Param::LastSubject, ts)?); // `ts` is now too old
        assert!(!params.update_timestamp(Param::LastSubject, 0)?);
        assert_eq!(params.get_i64(Param::LastSubject).unwrap(), ts + 10);

        assert!(params.update_timestamp(Param::GroupNameTimestamp, 0)?); // stay unset -> update ...
        assert!(params.update_timestamp(Param::GroupNameTimestamp, 0)?); // ... also on multiple calls
        assert_eq!(params.get_i64(Param::GroupNameTimestamp).unwrap(), 0);

        assert!(!params.update_timestamp(Param::AvatarTimestamp, -1)?);
        assert_eq!(params.get_i64(Param::AvatarTimestamp), None);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_out_of_order_subject() -> Result<()> {
        let t = TestContext::new_alice().await;

        receive_imf(
            &t,
            b"From: Bob Authname <bob@example.org>\n\
                 To: alice@example.org\n\
                 Subject: updated subject\n\
                 Message-ID: <msg2@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2021 23:37:57 +0000\n\
                 \n\
                 second message\n",
            false,
        )
        .await?;
        receive_imf(
            &t,
            b"From: Bob Authname <bob@example.org>\n\
                 To: alice@example.org\n\
                 Subject: original subject\n\
                 Message-ID: <msg1@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2021 22:37:57 +0000\n\
                 \n\
                 first message\n",
            false,
        )
        .await?;

        let msg = t.get_last_msg().await;
        let chat = Chat::load_from_db(&t, msg.chat_id).await?;
        assert_eq!(
            chat.param.get(Param::LastSubject).unwrap(),
            "updated subject"
        );

        Ok(())
    }
}
