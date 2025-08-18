//! # Chat list module.

use anyhow::{Context as _, Result, ensure};
use std::sync::LazyLock;

use crate::chat::{Chat, ChatId, ChatVisibility, update_special_chat_names};
use crate::constants::{
    Blocked, Chattype, DC_CHAT_ID_ALLDONE_HINT, DC_CHAT_ID_ARCHIVED_LINK, DC_GCL_ADD_ALLDONE_HINT,
    DC_GCL_ARCHIVED_ONLY, DC_GCL_FOR_FORWARDING, DC_GCL_NO_SPECIALS,
};
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::log::warn;
use crate::message::{Message, MessageState, MsgId};
use crate::param::{Param, Params};
use crate::stock_str;
use crate::summary::Summary;
use crate::tools::IsNoneOrEmpty;

/// Regex to find out if a query should filter by unread messages.
pub static IS_UNREAD_FILTER: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\bis:unread\b").unwrap());

/// An object representing a single chatlist in memory.
///
/// Chatlist objects contain chat IDs and, if possible, message IDs belonging to them.
/// The chatlist object is not updated; if you want an update, you have to recreate the object.
///
/// For a **typical chat overview**, the idea is to get the list of all chats via dc_get_chatlist()
/// without any listflags (see below) and to implement a "virtual list" or so
/// (the count of chats is known by chatlist.len()).
///
/// Only for the items that are in view (the list may have several hundreds chats),
/// the UI should call chatlist.get_summary() then.
/// chatlist.get_summary() provides all elements needed for painting the item.
///
/// On a click of such an item, the UI should change to the chat view
/// and get all messages from this view via dc_get_chat_msgs().
/// Again, a "virtual list" is created (the count of messages is known)
/// and for each messages that is scrolled into view, dc_get_msg() is called then.
///
/// Why no listflags?
/// Without listflags, dc_get_chatlist() adds the archive "link" automatically as needed.
/// The UI can just render these items differently then.
#[derive(Debug)]
pub struct Chatlist {
    /// Stores pairs of `chat_id, message_id`
    ids: Vec<(ChatId, Option<MsgId>)>,
}

impl Chatlist {
    /// Get a list of chats.
    /// The list can be filtered by query parameters.
    ///
    /// The list is already sorted and starts with the most recent chat in use.
    /// The sorting takes care of invalid sending dates, drafts and chats without messages.
    /// Clients should not try to re-sort the list as this would be an expensive action
    /// and would result in inconsistencies between clients.
    ///
    /// To get information about each entry, use eg. chatlist.get_summary().
    ///
    /// By default, the function adds some special entries to the list.
    /// These special entries can be identified by the ID returned by chatlist.get_chat_id():
    /// - DC_CHAT_ID_ARCHIVED_LINK (6) - this special chat is present if the user has
    ///   archived *any* chat using dc_set_chat_visibility(). The UI should show a link as
    ///   "Show archived chats", if the user clicks this item, the UI should show a
    ///   list of all archived chats that can be created by this function hen using
    ///   the DC_GCL_ARCHIVED_ONLY flag.
    /// - DC_CHAT_ID_ALLDONE_HINT (7) - this special chat is present
    ///   if DC_GCL_ADD_ALLDONE_HINT is added to listflags
    ///   and if there are only archived chats.
    ///
    /// The `listflags` is a combination of flags:
    /// - if the flag DC_GCL_ARCHIVED_ONLY is set, only archived chats are returned.
    ///   if DC_GCL_ARCHIVED_ONLY is not set, only unarchived chats are returned and
    ///   the pseudo-chat DC_CHAT_ID_ARCHIVED_LINK is added if there are *any* archived
    ///   chats
    /// - the flag DC_GCL_FOR_FORWARDING sorts "Saved messages" to the top of the chatlist
    ///   and hides the device-chat and contact requests
    ///   typically used on forwarding, may be combined with DC_GCL_NO_SPECIALS
    /// - if the flag DC_GCL_NO_SPECIALS is set, archive link is not added
    ///   to the list (may be used eg. for selecting chats on forwarding, the flag is
    ///   not needed when DC_GCL_ARCHIVED_ONLY is already set)
    /// - if the flag DC_GCL_ADD_ALLDONE_HINT is set, DC_CHAT_ID_ALLDONE_HINT
    ///   is added as needed.
    ///
    /// `query`: An optional query for filtering the list. Only chats matching this query
    /// are returned. When `is:unread` is contained in the query, the chatlist is
    /// filtered such that only chats with unread messages show up.
    ///
    /// `query_contact_id`: An optional contact ID for filtering the list. Only chats including this contact ID
    /// are returned.
    pub async fn try_load(
        context: &Context,
        listflags: usize,
        query: Option<&str>,
        query_contact_id: Option<ContactId>,
    ) -> Result<Self> {
        let flag_archived_only = 0 != listflags & DC_GCL_ARCHIVED_ONLY;
        let flag_for_forwarding = 0 != listflags & DC_GCL_FOR_FORWARDING;
        let flag_no_specials = 0 != listflags & DC_GCL_NO_SPECIALS;
        let flag_add_alldone_hint = 0 != listflags & DC_GCL_ADD_ALLDONE_HINT;

        let process_row = |row: &rusqlite::Row| {
            let chat_id: ChatId = row.get(0)?;
            let msg_id: Option<MsgId> = row.get(1)?;
            Ok((chat_id, msg_id))
        };

        let process_rows = |rows: rusqlite::MappedRows<_>| {
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        };

        let skip_id = if flag_for_forwarding {
            ChatId::lookup_by_contact(context, ContactId::DEVICE)
                .await?
                .unwrap_or_default()
        } else {
            ChatId::new(0)
        };

        // select with left join and minimum:
        //
        // - the inner select must use `hidden` and _not_ `m.hidden`
        //   which would refer the outer select and take a lot of time
        // - `GROUP BY` is needed several messages may have the same
        //   timestamp
        // - the list starts with the newest chats
        //
        // The query shows messages from blocked contacts in
        // groups. Otherwise it would be hard to follow conversations.
        let ids = if let Some(query_contact_id) = query_contact_id {
            // show chats shared with a given contact
            context.sql.query_map(
                "SELECT c.id, m.id
                 FROM chats c
                 LEFT JOIN msgs m
                        ON c.id=m.chat_id
                       AND m.id=(
                               SELECT id
                                 FROM msgs
                                WHERE chat_id=c.id
                                  AND (hidden=0 OR state=?1)
                                  ORDER BY timestamp DESC, id DESC LIMIT 1)
                 WHERE c.id>9
                   AND c.blocked!=1
                   AND c.id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=?2 AND add_timestamp >= remove_timestamp)
                 GROUP BY c.id
                 ORDER BY c.archived=?3 DESC, IFNULL(m.timestamp,c.created_timestamp) DESC, m.id DESC;",
                (MessageState::OutDraft, query_contact_id, ChatVisibility::Pinned),
                process_row,
                process_rows,
            ).await?
        } else if flag_archived_only {
            // show archived chats
            // (this includes the archived device-chat; we could skip it,
            // however, then the number of archived chats do not match, which might be even more irritating.
            // and adapting the number requires larger refactorings and seems not to be worth the effort)
            context
                .sql
                .query_map(
                    "SELECT c.id, m.id
                 FROM chats c
                 LEFT JOIN msgs m
                        ON c.id=m.chat_id
                       AND m.id=(
                               SELECT id
                                 FROM msgs
                                WHERE chat_id=c.id
                                  AND (hidden=0 OR state=?)
                                  ORDER BY timestamp DESC, id DESC LIMIT 1)
                 WHERE c.id>9
                   AND c.blocked!=1
                   AND c.archived=1
                 GROUP BY c.id
                 ORDER BY IFNULL(m.timestamp,c.created_timestamp) DESC, m.id DESC;",
                    (MessageState::OutDraft,),
                    process_row,
                    process_rows,
                )
                .await?
        } else if let Some(query) = query {
            let mut query = query.trim().to_string();
            ensure!(!query.is_empty(), "query mustn't be empty");
            let only_unread = IS_UNREAD_FILTER.find(&query).is_some();
            query = IS_UNREAD_FILTER.replace(&query, "").trim().to_string();

            // allow searching over special names that may change at any time
            // when the ui calls set_stock_translation()
            if let Err(err) = update_special_chat_names(context).await {
                warn!(context, "Cannot update special chat names: {err:#}.")
            }

            let str_like_cmd = format!("%{query}%");
            context
                .sql
                .query_map(
                    "SELECT c.id, m.id
                 FROM chats c
                 LEFT JOIN msgs m
                        ON c.id=m.chat_id
                       AND m.id=(
                               SELECT id
                                 FROM msgs
                                WHERE chat_id=c.id
                                  AND (hidden=0 OR state=?1)
                                  ORDER BY timestamp DESC, id DESC LIMIT 1)
                 WHERE c.id>9 AND c.id!=?2
                   AND c.blocked!=1
                   AND c.name LIKE ?3
                   AND (NOT ?4 OR EXISTS (SELECT 1 FROM msgs m WHERE m.chat_id = c.id AND m.state == ?5 AND hidden=0))
                 GROUP BY c.id
                 ORDER BY IFNULL(m.timestamp,c.created_timestamp) DESC, m.id DESC;",
                    (MessageState::OutDraft, skip_id, str_like_cmd, only_unread, MessageState::InFresh),
                    process_row,
                    process_rows,
                )
                .await?
        } else {
            let mut ids = if flag_for_forwarding {
                let sort_id_up = ChatId::lookup_by_contact(context, ContactId::SELF)
                    .await?
                    .unwrap_or_default();
                let process_row = |row: &rusqlite::Row| {
                    let chat_id: ChatId = row.get(0)?;
                    let typ: Chattype = row.get(1)?;
                    let param: Params = row.get::<_, String>(2)?.parse().unwrap_or_default();
                    let msg_id: Option<MsgId> = row.get(3)?;
                    Ok((chat_id, typ, param, msg_id))
                };
                let process_rows = |rows: rusqlite::MappedRows<_>| {
                    rows.filter_map(|row: std::result::Result<(_, _, Params, _), _>| match row {
                        Ok((chat_id, typ, param, msg_id)) => {
                            if typ == Chattype::Mailinglist
                                && param.get(Param::ListPost).is_none_or_empty()
                            {
                                None
                            } else {
                                Some(Ok((chat_id, msg_id)))
                            }
                        }
                        Err(e) => Some(Err(e)),
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
                };
                context.sql.query_map(
                    "SELECT c.id, c.type, c.param, m.id
                     FROM chats c
                     LEFT JOIN msgs m
                            ON c.id=m.chat_id
                           AND m.id=(
                                   SELECT id
                                     FROM msgs
                                    WHERE chat_id=c.id
                                      AND (hidden=0 OR state=?)
                                      ORDER BY timestamp DESC, id DESC LIMIT 1)
                     WHERE c.id>9 AND c.id!=?
                       AND c.blocked=0
                       AND NOT c.archived=?
                       AND (c.type!=? OR c.id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=? AND add_timestamp >= remove_timestamp))
                     GROUP BY c.id
                     ORDER BY c.id=? DESC, c.archived=? DESC, IFNULL(m.timestamp,c.created_timestamp) DESC, m.id DESC;",
                    (
                        MessageState::OutDraft, skip_id, ChatVisibility::Archived,
                        Chattype::Group, ContactId::SELF,
                        sort_id_up, ChatVisibility::Pinned,
                    ),
                    process_row,
                    process_rows,
                ).await?
            } else {
                //  show normal chatlist
                context.sql.query_map(
                    "SELECT c.id, m.id
                     FROM chats c
                     LEFT JOIN msgs m
                            ON c.id=m.chat_id
                           AND m.id=(
                                   SELECT id
                                     FROM msgs
                                    WHERE chat_id=c.id
                                      AND (hidden=0 OR state=?)
                                      ORDER BY timestamp DESC, id DESC LIMIT 1)
                     WHERE c.id>9 AND c.id!=?
                       AND (c.blocked=0 OR c.blocked=2)
                       AND NOT c.archived=?
                     GROUP BY c.id
                     ORDER BY c.id=0 DESC, c.archived=? DESC, IFNULL(m.timestamp,c.created_timestamp) DESC, m.id DESC;",
                    (MessageState::OutDraft, skip_id, ChatVisibility::Archived, ChatVisibility::Pinned),
                    process_row,
                    process_rows,
                ).await?
            };
            if !flag_no_specials && get_archived_cnt(context).await? > 0 {
                if ids.is_empty() && flag_add_alldone_hint {
                    ids.push((DC_CHAT_ID_ALLDONE_HINT, None));
                }
                ids.insert(0, (DC_CHAT_ID_ARCHIVED_LINK, None));
            }
            ids
        };

        Ok(Chatlist { ids })
    }

    /// Converts list of chat IDs to a chatlist.
    pub(crate) async fn from_chat_ids(context: &Context, chat_ids: &[ChatId]) -> Result<Self> {
        let mut ids = Vec::new();
        for &chat_id in chat_ids {
            let msg_id: Option<MsgId> = context
                .sql
                .query_get_value(
                    "SELECT id
                   FROM msgs
                  WHERE chat_id=?1
                    AND (hidden=0 OR state=?2)
                  ORDER BY timestamp DESC, id DESC LIMIT 1",
                    (chat_id, MessageState::OutDraft),
                )
                .await
                .with_context(|| format!("failed to get msg ID for chat {chat_id}"))?;
            ids.push((chat_id, msg_id));
        }
        Ok(Chatlist { ids })
    }

    /// Find out the number of chats.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns true if chatlist is empty.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Get a single chat ID of a chatlist.
    ///
    /// To get the message object from the message ID, use dc_get_chat().
    pub fn get_chat_id(&self, index: usize) -> Result<ChatId> {
        let (chat_id, _msg_id) = self
            .ids
            .get(index)
            .context("chatlist index is out of range")?;
        Ok(*chat_id)
    }

    /// Get a single message ID of a chatlist.
    ///
    /// To get the message object from the message ID, use dc_get_msg().
    pub fn get_msg_id(&self, index: usize) -> Result<Option<MsgId>> {
        let (_chat_id, msg_id) = self
            .ids
            .get(index)
            .context("chatlist index is out of range")?;
        Ok(*msg_id)
    }

    /// Returns a summary for a given chatlist index.
    pub async fn get_summary(
        &self,
        context: &Context,
        index: usize,
        chat: Option<&Chat>,
    ) -> Result<Summary> {
        // The summary is created by the chat, not by the last message.
        // This is because we may want to display drafts here or stuff as
        // "is typing".
        // Also, sth. as "No messages" would not work if the summary comes from a message.
        let (chat_id, lastmsg_id) = self
            .ids
            .get(index)
            .context("chatlist index is out of range")?;
        Chatlist::get_summary2(context, *chat_id, *lastmsg_id, chat).await
    }

    /// Returns a summary for a given chatlist item.
    pub async fn get_summary2(
        context: &Context,
        chat_id: ChatId,
        lastmsg_id: Option<MsgId>,
        chat: Option<&Chat>,
    ) -> Result<Summary> {
        let chat_loaded: Chat;
        let chat = if let Some(chat) = chat {
            chat
        } else {
            let chat = Chat::load_from_db(context, chat_id).await?;
            chat_loaded = chat;
            &chat_loaded
        };

        let lastmsg = if let Some(lastmsg_id) = lastmsg_id {
            // Message may be deleted by the time we try to load it,
            // so use `load_from_db_optional` instead of `load_from_db`.
            Message::load_from_db_optional(context, lastmsg_id)
                .await
                .context("Loading message failed")?
        } else {
            None
        };

        let lastcontact = if let Some(lastmsg) = &lastmsg {
            if lastmsg.from_id == ContactId::SELF {
                None
            } else if chat.typ == Chattype::Group
                || chat.typ == Chattype::OutBroadcast
                || chat.typ == Chattype::InBroadcast
                || chat.typ == Chattype::Mailinglist
                || chat.is_self_talk()
            {
                let lastcontact = Contact::get_by_id(context, lastmsg.from_id)
                    .await
                    .context("loading contact failed")?;
                Some(lastcontact)
            } else {
                None
            }
        } else {
            None
        };

        if chat.id.is_archived_link() {
            Ok(Default::default())
        } else if let Some(lastmsg) = lastmsg.filter(|msg| msg.from_id != ContactId::UNDEFINED) {
            Summary::new_with_reaction_details(context, &lastmsg, chat, lastcontact.as_ref()).await
        } else {
            Ok(Summary {
                text: stock_str::no_messages(context).await,
                ..Default::default()
            })
        }
    }

    /// Returns chatlist item position for the given chat ID.
    pub fn get_index_for_id(&self, id: ChatId) -> Option<usize> {
        self.ids.iter().position(|(chat_id, _)| chat_id == &id)
    }

    /// An iterator visiting all chatlist items.
    pub fn iter(&self) -> impl Iterator<Item = &(ChatId, Option<MsgId>)> {
        self.ids.iter()
    }
}

/// Returns the number of archived chats
pub async fn get_archived_cnt(context: &Context) -> Result<usize> {
    let count = context
        .sql
        .count(
            "SELECT COUNT(*) FROM chats WHERE blocked!=? AND archived=?;",
            (Blocked::Yes, ChatVisibility::Archived),
        )
        .await?;
    Ok(count)
}

/// Gets the last message of a chat, the message that would also be displayed in the ChatList
/// Used for passing to `deltachat::chatlist::Chatlist::get_summary2`
pub async fn get_last_message_for_chat(
    context: &Context,
    chat_id: ChatId,
) -> Result<Option<MsgId>> {
    context
        .sql
        .query_get_value(
            "SELECT id
                FROM msgs
                WHERE chat_id=?2
                AND (hidden=0 OR state=?1)
                ORDER BY timestamp DESC, id DESC LIMIT 1",
            (MessageState::OutDraft, chat_id),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::save_msgs;
    use crate::chat::{
        ProtectionStatus, add_contact_to_chat, create_group_chat, get_chat_contacts,
        remove_contact_from_chat, send_text_msg,
    };
    use crate::receive_imf::receive_imf;
    use crate::stock_str::StockMessage;
    use crate::test_utils::TestContext;
    use crate::test_utils::TestContextManager;
    use crate::tools::SystemTime;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_try_load() {
        let mut tcm = TestContextManager::new();
        let bob = &tcm.bob().await;
        let chat_id1 = create_group_chat(bob, ProtectionStatus::Unprotected, "a chat")
            .await
            .unwrap();
        let chat_id2 = create_group_chat(bob, ProtectionStatus::Unprotected, "b chat")
            .await
            .unwrap();
        let chat_id3 = create_group_chat(bob, ProtectionStatus::Unprotected, "c chat")
            .await
            .unwrap();

        // check that the chatlist starts with the most recent message
        let chats = Chatlist::try_load(bob, 0, None, None).await.unwrap();
        assert_eq!(chats.len(), 3);
        assert_eq!(chats.get_chat_id(0).unwrap(), chat_id3);
        assert_eq!(chats.get_chat_id(1).unwrap(), chat_id2);
        assert_eq!(chats.get_chat_id(2).unwrap(), chat_id1);

        SystemTime::shift(Duration::from_secs(5));

        // New drafts are sorted to the top
        // We have to set a draft on the other two messages, too, as
        // chat timestamps are only exact to the second and sorting by timestamp
        // would not work.
        // Message timestamps are "smeared" and unique, so we don't have this problem
        // if we have any message (can be a draft) in all chats.
        // Instead of setting drafts for chat_id1 and chat_id3, we could also sleep
        // 2s here.
        for chat_id in &[chat_id1, chat_id3, chat_id2] {
            let mut msg = Message::new_text("hello".to_string());
            chat_id.set_draft(bob, Some(&mut msg)).await.unwrap();
        }

        let chats = Chatlist::try_load(bob, 0, None, None).await.unwrap();
        assert_eq!(chats.get_chat_id(0).unwrap(), chat_id2);

        // check chatlist query and archive functionality
        let chats = Chatlist::try_load(bob, 0, Some("b"), None).await.unwrap();
        assert_eq!(chats.len(), 1);

        // receive a message from alice
        let alice = &tcm.alice().await;
        let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "alice chat")
            .await
            .unwrap();
        add_contact_to_chat(
            alice,
            alice_chat_id,
            alice.add_or_lookup_contact_id(bob).await,
        )
        .await
        .unwrap();
        send_text_msg(alice, alice_chat_id, "hi".into())
            .await
            .unwrap();
        let sent_msg = alice.pop_sent_msg().await;

        bob.recv_msg(&sent_msg).await;
        let chats = Chatlist::try_load(bob, 0, Some("is:unread"), None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 1);

        let chats = Chatlist::try_load(bob, DC_GCL_ARCHIVED_ONLY, None, None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 0);

        chat_id1
            .set_visibility(bob, ChatVisibility::Archived)
            .await
            .ok();
        let chats = Chatlist::try_load(bob, DC_GCL_ARCHIVED_ONLY, None, None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sort_self_talk_up_on_forward() {
        let t = TestContext::new_alice().await;
        t.update_device_chats().await.unwrap();
        create_group_chat(&t, ProtectionStatus::Unprotected, "a chat")
            .await
            .unwrap();

        let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
        assert_eq!(chats.len(), 3);
        assert!(
            !Chat::load_from_db(&t, chats.get_chat_id(0).unwrap())
                .await
                .unwrap()
                .is_self_talk()
        );

        let chats = Chatlist::try_load(&t, DC_GCL_FOR_FORWARDING, None, None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 2); // device chat cannot be written and is skipped on forwarding
        assert!(
            Chat::load_from_db(&t, chats.get_chat_id(0).unwrap())
                .await
                .unwrap()
                .is_self_talk()
        );

        remove_contact_from_chat(&t, chats.get_chat_id(1).unwrap(), ContactId::SELF)
            .await
            .unwrap();
        let chats = Chatlist::try_load(&t, DC_GCL_FOR_FORWARDING, None, None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_search_special_chat_names() {
        let t = TestContext::new_alice().await;
        t.update_device_chats().await.unwrap();

        let chats = Chatlist::try_load(&t, 0, Some("t-1234-s"), None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 0);
        let chats = Chatlist::try_load(&t, 0, Some("t-5678-b"), None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 0);

        t.set_stock_translation(StockMessage::SavedMessages, "test-1234-save".to_string())
            .await
            .unwrap();
        let chats = Chatlist::try_load(&t, 0, Some("t-1234-s"), None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 1);

        t.set_stock_translation(StockMessage::DeviceMessages, "test-5678-babbel".to_string())
            .await
            .unwrap();
        let chats = Chatlist::try_load(&t, 0, Some("t-5678-b"), None)
            .await
            .unwrap();
        assert_eq!(chats.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_search_single_chat() -> anyhow::Result<()> {
        let t = TestContext::new_alice().await;

        // receive a one-to-one-message
        receive_imf(
            &t,
            b"From: Bob Authname <bob@example.org>\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <msg1234@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2021 22:37:57 +0000\n\
                 \n\
                 hello foo\n",
            false,
        )
        .await?;

        let chats = Chatlist::try_load(&t, 0, Some("Bob Authname"), None).await?;
        // Contact request should be searchable
        assert_eq!(chats.len(), 1);

        let msg = t.get_last_msg().await;
        let chat_id = msg.get_chat_id();
        chat_id.accept(&t).await.unwrap();

        let contacts = get_chat_contacts(&t, chat_id).await?;
        let contact_id = *contacts.first().unwrap();
        let chat = Chat::load_from_db(&t, chat_id).await?;
        assert_eq!(chat.get_name(), "Bob Authname");

        // check, the one-to-one-chat can be found using chatlist search query
        let chats = Chatlist::try_load(&t, 0, Some("bob authname"), None).await?;
        assert_eq!(chats.len(), 1);
        assert_eq!(chats.get_chat_id(0).unwrap(), chat_id);

        // change the name of the contact; this also changes the name of the one-to-one-chat
        let test_id = Contact::create(&t, "Bob Nickname", "bob@example.org").await?;
        assert_eq!(contact_id, test_id);
        let chat = Chat::load_from_db(&t, chat_id).await?;
        assert_eq!(chat.get_name(), "Bob Nickname");
        let chats = Chatlist::try_load(&t, 0, Some("bob authname"), None).await?;
        assert_eq!(chats.len(), 0);
        let chats = Chatlist::try_load(&t, 0, Some("bob nickname"), None).await?;
        assert_eq!(chats.len(), 1);

        // revert contact to authname, this again changes the name of the one-to-one-chat
        let test_id = Contact::create(&t, "", "bob@example.org").await?;
        assert_eq!(contact_id, test_id);
        let chat = Chat::load_from_db(&t, chat_id).await?;
        assert_eq!(chat.get_name(), "Bob Authname");
        let chats = Chatlist::try_load(&t, 0, Some("bob authname"), None).await?;
        assert_eq!(chats.len(), 1);
        let chats = Chatlist::try_load(&t, 0, Some("bob nickname"), None).await?;
        assert_eq!(chats.len(), 0);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_search_single_chat_without_authname() -> anyhow::Result<()> {
        let t = TestContext::new_alice().await;

        // receive a one-to-one-message without authname set
        receive_imf(
            &t,
            b"From: bob@example.org\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <msg5678@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2021 22:38:57 +0000\n\
                 \n\
                 hello foo\n",
            false,
        )
        .await?;

        let msg = t.get_last_msg().await;
        let chat_id = msg.get_chat_id();
        chat_id.accept(&t).await.unwrap();
        let contacts = get_chat_contacts(&t, chat_id).await?;
        let contact_id = *contacts.first().unwrap();
        let chat = Chat::load_from_db(&t, chat_id).await?;
        assert_eq!(chat.get_name(), "bob@example.org");

        // check, the one-to-one-chat can be found using chatlist search query
        let chats = Chatlist::try_load(&t, 0, Some("bob@example.org"), None).await?;
        assert_eq!(chats.len(), 1);
        assert_eq!(chats.get_chat_id(0)?, chat_id);

        // change the name of the contact; this also changes the name of the one-to-one-chat
        let test_id = Contact::create(&t, "Bob Nickname", "bob@example.org").await?;
        assert_eq!(contact_id, test_id);
        let chat = Chat::load_from_db(&t, chat_id).await?;
        assert_eq!(chat.get_name(), "Bob Nickname");
        let chats = Chatlist::try_load(&t, 0, Some("bob@example.org"), None).await?;
        assert_eq!(chats.len(), 0); // email-addresses are searchable in contacts, not in chats
        let chats = Chatlist::try_load(&t, 0, Some("Bob Nickname"), None).await?;
        assert_eq!(chats.len(), 1);
        assert_eq!(chats.get_chat_id(0)?, chat_id);

        // revert name change, this again changes the name of the one-to-one-chat to the email-address
        let test_id = Contact::create(&t, "", "bob@example.org").await?;
        assert_eq!(contact_id, test_id);
        let chat = Chat::load_from_db(&t, chat_id).await?;
        assert_eq!(chat.get_name(), "bob@example.org");
        let chats = Chatlist::try_load(&t, 0, Some("bob@example.org"), None).await?;
        assert_eq!(chats.len(), 1);
        let chats = Chatlist::try_load(&t, 0, Some("bob nickname"), None).await?;
        assert_eq!(chats.len(), 0);

        // finally, also check that a simple substring-search is working with email-addresses
        let chats = Chatlist::try_load(&t, 0, Some("b@exa"), None).await?;
        assert_eq!(chats.len(), 1);
        let chats = Chatlist::try_load(&t, 0, Some("b@exac"), None).await?;
        assert_eq!(chats.len(), 0);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_summary_unwrap() {
        let t = TestContext::new().await;
        let chat_id1 = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat")
            .await
            .unwrap();

        let mut msg = Message::new_text("foo:\nbar \r\n test".to_string());
        chat_id1.set_draft(&t, Some(&mut msg)).await.unwrap();

        let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
        let summary = chats.get_summary(&t, 0, None).await.unwrap();
        assert_eq!(summary.text, "foo: bar test"); // the linebreak should be removed from summary
    }

    /// Tests that summary does not fail to load
    /// if the draft was deleted after loading the chatlist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_summary_deleted_draft() {
        let t = TestContext::new().await;

        let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat")
            .await
            .unwrap();
        let mut msg = Message::new_text("Foobar".to_string());
        chat_id.set_draft(&t, Some(&mut msg)).await.unwrap();

        let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
        chat_id.set_draft(&t, None).await.unwrap();

        let summary_res = chats.get_summary(&t, 0, None).await;
        assert!(summary_res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_summary_for_saved_messages() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let chat_alice = alice.create_chat(&bob).await;

        send_text_msg(&alice, chat_alice.id, "hi".into()).await?;
        let sent1 = alice.pop_sent_msg().await;
        save_msgs(&alice, &[sent1.sender_msg_id]).await?;
        let chatlist = Chatlist::try_load(&alice, 0, None, None).await?;
        let summary = chatlist.get_summary(&alice, 0, None).await?;
        assert_eq!(summary.prefix.unwrap().to_string(), "Me");
        assert_eq!(summary.text, "hi");

        let msg = bob.recv_msg(&sent1).await;
        save_msgs(&bob, &[msg.id]).await?;
        let chatlist = Chatlist::try_load(&bob, 0, None, None).await?;
        let summary = chatlist.get_summary(&bob, 0, None).await?;
        assert_eq!(summary.prefix.unwrap().to_string(), "alice@example.org");
        assert_eq!(summary.text, "hi");

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_load_broken() {
        let t = TestContext::new_bob().await;
        let chat_id1 = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat")
            .await
            .unwrap();
        create_group_chat(&t, ProtectionStatus::Unprotected, "b chat")
            .await
            .unwrap();
        create_group_chat(&t, ProtectionStatus::Unprotected, "c chat")
            .await
            .unwrap();

        // check that the chatlist starts with the most recent message
        let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
        assert_eq!(chats.len(), 3);

        // obfuscated one chat
        t.sql
            .execute("UPDATE chats SET type=10 WHERE id=?", (chat_id1,))
            .await
            .unwrap();

        // obfuscated chat can't be loaded
        assert!(Chat::load_from_db(&t, chat_id1).await.is_err());

        // chatlist loads fine
        let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();

        // only corrupted chat fails to create summary
        assert!(chats.get_summary(&t, 0, None).await.is_ok());
        assert!(chats.get_summary(&t, 1, None).await.is_ok());
        assert!(chats.get_summary(&t, 2, None).await.is_err());
        assert_eq!(chats.get_index_for_id(chat_id1).unwrap(), 2);
    }
}
