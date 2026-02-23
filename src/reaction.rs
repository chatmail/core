//! # Reactions.
//!
//! Reactions are short messages consisting of emojis sent in reply to
//! messages. Unlike normal messages which are added to the end of the chat,
//! reactions are supposed to be displayed near the original messages.
//!
//! RFC 9078 specifies how reactions are transmitted in MIME messages.
//!
//! Reaction update semantics is not well-defined in RFC 9078, so
//! Delta Chat uses the same semantics as in
//! [XEP-0444](https://xmpp.org/extensions/xep-0444.html) section
//! "3.2 Updating reactions to a message". Received reactions override
//! all previously received reactions from the same user and it is
//! possible to remove all reactions by sending an empty string as a reaction,
//! even though RFC 9078 requires at least one emoji to be sent.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::chat::{Chat, ChatId, send_msg};
use crate::chatlist_events;
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::message::{Message, MsgId, rfc724_mid_exists};
use crate::param::Param;

/// A single reaction consisting of multiple emoji sequences.
///
/// It is guaranteed to have all emojis sorted and deduplicated inside.
#[derive(Debug, Default, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reaction {
    /// Canonical representation of reaction as a string of space-separated emojis.
    reaction: String,
}

// We implement From<&str> instead of std::str::FromStr, because
// FromStr requires error type and reaction parsing never returns an
// error.
impl From<&str> for Reaction {
    /// Parses a string containing a reaction.
    ///
    /// Reaction string is separated by spaces or tabs (`WSP` in ABNF),
    /// but this function accepts any ASCII whitespace, so even a CRLF at
    /// the end of string is acceptable.
    ///
    /// Any short enough string is accepted as a reaction to avoid the
    /// complexity of validating emoji sequences as required by RFC
    /// 9078. On the sender side UI is responsible to provide only
    /// valid emoji sequences via reaction picker. On the receiver
    /// side, abuse of the possibility to use arbitrary strings as
    /// reactions is not different from other kinds of spam attacks
    /// such as sending large numbers of large messages, and should be
    /// dealt with the same way, e.g. by blocking the user.
    fn from(reaction: &str) -> Self {
        let mut emojis: Vec<&str> = reaction
            .split_ascii_whitespace()
            .filter(|&emoji| emoji.len() < 30)
            .collect();
        emojis.sort_unstable();
        emojis.dedup();
        let reaction = emojis.join(" ");
        Self { reaction }
    }
}

impl Reaction {
    /// Returns true if reaction contains no emojis.
    pub fn is_empty(&self) -> bool {
        self.reaction.is_empty()
    }

    /// Returns a vector of emojis composing a reaction.
    pub fn emojis(&self) -> Vec<&str> {
        self.reaction.split(' ').collect()
    }

    /// Returns space-separated string of emojis
    pub fn as_str(&self) -> &str {
        &self.reaction
    }

    /// Appends emojis from another reaction to this reaction.
    pub fn add(&self, other: Self) -> Self {
        let mut emojis: Vec<&str> = self.emojis();
        emojis.append(&mut other.emojis());
        emojis.sort_unstable();
        emojis.dedup();
        let reaction = emojis.join(" ");
        Self { reaction }
    }
}

/// Structure representing all reactions to a particular message.
#[derive(Debug)]
pub struct Reactions {
    /// Map from a contact to its reaction to message.
    reactions: BTreeMap<ContactId, Reaction>,
}

impl Reactions {
    /// Returns vector of contacts that reacted to the message.
    pub fn contacts(&self) -> Vec<ContactId> {
        self.reactions.keys().copied().collect()
    }

    /// Returns reaction of a given contact to message.
    ///
    /// If contact did not react to message or removed the reaction,
    /// this method returns an empty reaction.
    pub fn get(&self, contact_id: ContactId) -> Reaction {
        self.reactions.get(&contact_id).cloned().unwrap_or_default()
    }

    /// Returns true if the message has no reactions.
    pub fn is_empty(&self) -> bool {
        self.reactions.is_empty()
    }

    /// Returns a map from emojis to their frequencies.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn emoji_frequencies(&self) -> BTreeMap<String, usize> {
        let mut emoji_frequencies: BTreeMap<String, usize> = BTreeMap::new();
        for reaction in self.reactions.values() {
            for emoji in reaction.emojis() {
                emoji_frequencies
                    .entry(emoji.to_string())
                    .and_modify(|x| *x += 1)
                    .or_insert(1);
            }
        }
        emoji_frequencies
    }

    /// Returns a vector of emojis
    /// sorted in descending order of frequencies.
    ///
    /// This function can be used to display the reactions in
    /// the message bubble in the UIs.
    pub fn emoji_sorted_by_frequency(&self) -> Vec<(String, usize)> {
        let mut emoji_frequencies: Vec<(String, usize)> =
            self.emoji_frequencies().into_iter().collect();
        emoji_frequencies.sort_by(|(a, a_count), (b, b_count)| {
            match a_count.cmp(b_count).reverse() {
                Ordering::Equal => a.cmp(b),
                other => other,
            }
        });
        emoji_frequencies
    }
}

impl fmt::Display for Reactions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let emoji_frequencies = self.emoji_sorted_by_frequency();
        let mut first = true;
        for (emoji, frequency) in emoji_frequencies {
            if !first {
                write!(f, " ")?;
            }
            first = false;
            write!(f, "{emoji}{frequency}")?;
        }
        Ok(())
    }
}

async fn set_msg_id_reaction(
    context: &Context,
    msg_id: MsgId,
    chat_id: ChatId,
    contact_id: ContactId,
    timestamp: i64,
    reaction: &Reaction,
) -> Result<()> {
    if reaction.is_empty() {
        // Simply remove the record instead of setting it to empty string.
        context
            .sql
            .execute(
                "DELETE FROM reactions
                 WHERE msg_id = ?1
                 AND contact_id = ?2",
                (msg_id, contact_id),
            )
            .await?;
    } else {
        context
            .sql
            .execute(
                "INSERT INTO reactions (msg_id, contact_id, reaction)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(msg_id, contact_id)
                 DO UPDATE SET reaction=excluded.reaction",
                (msg_id, contact_id, reaction.as_str()),
            )
            .await?;
        let mut chat = Chat::load_from_db(context, chat_id).await?;
        if chat
            .param
            .update_timestamp(Param::LastReactionTimestamp, timestamp)?
        {
            chat.param
                .set_i64(Param::LastReactionMsgId, i64::from(msg_id.to_u32()));
            chat.param
                .set_i64(Param::LastReactionContactId, i64::from(contact_id.to_u32()));
            chat.update_param(context).await?;
        }
    }

    context.emit_event(EventType::ReactionsChanged {
        chat_id,
        msg_id,
        contact_id,
    });
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    Ok(())
}

/// Sends a reaction to message `msg_id`, overriding previously sent reactions.
///
/// `reaction` is a string consisting of space-separated emoji. Use
/// empty string to retract a reaction.
pub async fn send_reaction(context: &Context, msg_id: MsgId, reaction: &str) -> Result<MsgId> {
    let msg = Message::load_from_db(context, msg_id).await?;
    let chat_id = msg.chat_id;

    let reaction: Reaction = reaction.into();
    let mut reaction_msg = Message::new_text(reaction.as_str().to_string());
    reaction_msg.set_reaction();
    reaction_msg.in_reply_to = Some(msg.rfc724_mid);
    reaction_msg.hidden = true;

    // Send message first.
    let reaction_msg_id = send_msg(context, chat_id, &mut reaction_msg).await?;

    // Only set reaction if we successfully sent the message.
    set_msg_id_reaction(
        context,
        msg_id,
        msg.chat_id,
        ContactId::SELF,
        reaction_msg.timestamp_sort,
        &reaction,
    )
    .await?;
    Ok(reaction_msg_id)
}

/// Adds given reaction to message `msg_id` and sends an update.
///
/// This can be used to implement advanced clients that allow reacting
/// with multiple emojis. For a simple messenger UI, you probably want
/// to use [`send_reaction()`] instead so reacting with a new emoji
/// removes previous emoji at the same time.
pub async fn add_reaction(context: &Context, msg_id: MsgId, reaction: &str) -> Result<MsgId> {
    let self_reaction = get_self_reaction(context, msg_id).await?;
    let reaction = self_reaction.add(Reaction::from(reaction));
    send_reaction(context, msg_id, reaction.as_str()).await
}

/// Updates reaction of `contact_id` on the message with `in_reply_to`
/// Message-ID. If no such message is found in the database, reaction
/// is ignored.
///
/// `reaction` is a space-separated string of emojis. It can be empty
/// if contact wants to remove all reactions.
pub(crate) async fn set_msg_reaction(
    context: &Context,
    in_reply_to: &str,
    chat_id: ChatId,
    contact_id: ContactId,
    timestamp: i64,
    reaction: Reaction,
    is_incoming_fresh: bool,
) -> Result<()> {
    if let Some(msg_id) = rfc724_mid_exists(context, in_reply_to).await? {
        set_msg_id_reaction(context, msg_id, chat_id, contact_id, timestamp, &reaction).await?;

        if is_incoming_fresh
            && !reaction.is_empty()
            && msg_id.get_state(context).await?.is_outgoing()
        {
            context.emit_event(EventType::IncomingReaction {
                chat_id,
                contact_id,
                msg_id,
                reaction,
            });
        }
    } else {
        info!(
            context,
            "Can't assign reaction to unknown message with Message-ID {}", in_reply_to
        );
    }
    Ok(())
}

/// Get our own reaction for a given message.
async fn get_self_reaction(context: &Context, msg_id: MsgId) -> Result<Reaction> {
    let reaction_str: Option<String> = context
        .sql
        .query_get_value(
            "SELECT reaction
             FROM reactions
             WHERE msg_id=? AND contact_id=?",
            (msg_id, ContactId::SELF),
        )
        .await?;
    Ok(reaction_str
        .as_deref()
        .map(Reaction::from)
        .unwrap_or_default())
}

/// Returns a structure containing all reactions to the message.
pub async fn get_msg_reactions(context: &Context, msg_id: MsgId) -> Result<Reactions> {
    let reactions: BTreeMap<ContactId, Reaction> = context
        .sql
        .query_map_collect(
            "SELECT contact_id, reaction FROM reactions WHERE msg_id=?",
            (msg_id,),
            |row| {
                let contact_id: ContactId = row.get(0)?;
                let reaction: String = row.get(1)?;
                Ok((contact_id, Reaction::from(reaction.as_str())))
            },
        )
        .await?;
    Ok(Reactions { reactions })
}

impl Chat {
    /// Check if there is a reaction newer than the given timestamp.
    ///
    /// If so, reaction details are returned and can be used to create a summary string.
    pub async fn get_last_reaction_if_newer_than(
        &self,
        context: &Context,
        timestamp: i64,
    ) -> Result<Option<(Message, ContactId, String)>> {
        if self
            .param
            .get_i64(Param::LastReactionTimestamp)
            .filter(|&reaction_timestamp| reaction_timestamp > timestamp)
            .is_none()
        {
            return Ok(None);
        };
        let reaction_msg_id = MsgId::new(
            self.param
                .get_int(Param::LastReactionMsgId)
                .unwrap_or_default() as u32,
        );
        let Some(reaction_msg) = Message::load_from_db_optional(context, reaction_msg_id).await?
        else {
            // The message reacted to may be deleted.
            // These are no errors as `Param::LastReaction*` are just weak pointers.
            // Instead, just return `Ok(None)` and let the caller create another summary.
            return Ok(None);
        };
        let reaction_contact_id = ContactId::new(
            self.param
                .get_int(Param::LastReactionContactId)
                .unwrap_or_default() as u32,
        );
        if let Some(reaction) = context
            .sql
            .query_get_value(
                "SELECT reaction FROM reactions WHERE msg_id=? AND contact_id=?",
                (reaction_msg.id, reaction_contact_id),
            )
            .await?
        {
            Ok(Some((reaction_msg, reaction_contact_id, reaction)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use deltachat_contact_tools::ContactAddress;

    use super::*;
    use crate::chat::{forward_msgs, get_chat_msgs, marknoticed_chat, send_text_msg};
    use crate::chatlist::Chatlist;
    use crate::config::Config;
    use crate::contact::{Contact, Origin};
    use crate::message::{MessageState, Viewtype, delete_msgs};
    use crate::receive_imf::receive_imf;
    use crate::sql::housekeeping;
    use crate::test_utils::E2EE_INFO_MSGS;
    use crate::test_utils::TestContext;
    use crate::test_utils::TestContextManager;
    use crate::tools::SystemTime;
    use std::time::Duration;

    #[test]
    fn test_parse_reaction() {
        // Check that basic set of emojis from RFC 9078 is supported.
        assert_eq!(Reaction::from("👍").emojis(), vec!["👍"]);
        assert_eq!(Reaction::from("👎").emojis(), vec!["👎"]);
        assert_eq!(Reaction::from("😀").emojis(), vec!["😀"]);
        assert_eq!(Reaction::from("☹").emojis(), vec!["☹"]);
        assert_eq!(Reaction::from("😢").emojis(), vec!["😢"]);

        // Empty string can be used to remove all reactions.
        assert!(Reaction::from("").is_empty());

        // Short strings can be used as emojis, could be used to add
        // support for custom emojis via emoji shortcodes.
        assert_eq!(Reaction::from(":deltacat:").emojis(), vec![":deltacat:"]);

        // Check that long strings are not valid emojis.
        assert!(
            Reaction::from(":foobarbazquuxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:").is_empty()
        );

        // Multiple reactions separated by spaces or tabs are supported.
        assert_eq!(Reaction::from("👍 ❤").emojis(), vec!["❤", "👍"]);
        assert_eq!(Reaction::from("👍\t❤").emojis(), vec!["❤", "👍"]);

        // Invalid emojis are removed, but valid emojis are retained.
        assert_eq!(
            Reaction::from("👍\t:foo: ❤").emojis(),
            vec![":foo:", "❤", "👍"]
        );
        assert_eq!(Reaction::from("👍\t:foo: ❤").as_str(), ":foo: ❤ 👍");

        // Duplicates are removed.
        assert_eq!(Reaction::from("👍 👍").emojis(), vec!["👍"]);
    }

    #[test]
    fn test_add_reaction() {
        let reaction1 = Reaction::from("👍 😀");
        let reaction2 = Reaction::from("❤");
        let reaction_sum = reaction1.add(reaction2);

        assert_eq!(reaction_sum.emojis(), vec!["❤", "👍", "😀"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_reaction() -> Result<()> {
        let alice = TestContext::new_alice().await;

        // Alice receives BCC-self copy of a message sent to Bob.
        receive_imf(
            &alice,
            "To: bob@example.net\n\
From: alice@example.org\n\
Date: Today, 29 February 2021 00:00:00 -800\n\
Message-ID: 12345@example.org\n\
Subject: Meeting\n\
\n\
Can we chat at 1pm pacific, today?"
                .as_bytes(),
            false,
        )
        .await?;
        let msg = alice.get_last_msg().await;
        assert_eq!(msg.state, MessageState::OutDelivered);
        let reactions = get_msg_reactions(&alice, msg.id).await?;
        let contacts = reactions.contacts();
        assert_eq!(contacts.len(), 0);

        let bob_id = Contact::add_or_lookup(
            &alice,
            "",
            &ContactAddress::new("bob@example.net")?,
            Origin::ManuallyCreated,
        )
        .await?
        .0;
        let bob_reaction = reactions.get(bob_id);
        assert!(bob_reaction.is_empty()); // Bob has not reacted to message yet.

        // Alice receives reaction to her message from Bob.
        receive_imf(
            &alice,
            "To: alice@example.org\n\
From: bob@example.net\n\
Date: Today, 29 February 2021 00:00:10 -800\n\
Message-ID: 56789@example.net\n\
In-Reply-To: 12345@example.org\n\
Subject: Meeting\n\
Mime-Version: 1.0 (1.0)\n\
Content-Type: text/plain; charset=utf-8\n\
Content-Disposition: reaction\n\
\n\
\u{1F44D}"
                .as_bytes(),
            false,
        )
        .await?;

        let reactions = get_msg_reactions(&alice, msg.id).await?;
        assert_eq!(reactions.to_string(), "👍1");

        let contacts = reactions.contacts();
        assert_eq!(contacts.len(), 1);

        assert_eq!(contacts.first(), Some(&bob_id));
        let bob_reaction = reactions.get(bob_id);
        assert_eq!(bob_reaction.is_empty(), false);
        assert_eq!(bob_reaction.emojis(), vec!["👍"]);
        assert_eq!(bob_reaction.as_str(), "👍");

        // Alice receives reaction to her message from Bob with a footer.
        receive_imf(
            &alice,
            "To: alice@example.org\n\
From: bob@example.net\n\
Date: Today, 29 February 2021 00:00:10 -800\n\
Message-ID: 56790@example.net\n\
In-Reply-To: 12345@example.org\n\
Subject: Meeting\n\
Mime-Version: 1.0 (1.0)\n\
Content-Type: text/plain; charset=utf-8\n\
Content-Disposition: reaction\n\
\n\
😀\n\
\n\
--\n\
_______________________________________________\n\
Here's my footer -- bob@example.net"
                .as_bytes(),
            false,
        )
        .await?;

        let reactions = get_msg_reactions(&alice, msg.id).await?;
        assert_eq!(reactions.to_string(), "😀1");

        // Alice receives a message with reaction to her message from Bob.
        let msg_bob = receive_imf(
            &alice,
            "To: alice@example.org\n\
From: bob@example.net\n\
Date: Today, 29 February 2021 00:00:10 -800\n\
Message-ID: 56791@example.net\n\
In-Reply-To: 12345@example.org\n\
Mime-Version: 1.0\n\
Content-Type: multipart/mixed; boundary=\"YiEDa0DAkWCtVeE4\"\n\
Content-Disposition: inline\n\
\n\
--YiEDa0DAkWCtVeE4\n\
Content-Type: text/plain; charset=utf-8\n\
Content-Disposition: inline\n\
\n\
Reply + reaction\n\
\n\
--YiEDa0DAkWCtVeE4\n\
Content-Type: text/plain; charset=utf-8\n\
Content-Disposition: reaction\n\
\n\
\u{1F44D}\n\
\n\
--YiEDa0DAkWCtVeE4--"
                .as_bytes(),
            false,
        )
        .await?
        .unwrap();
        let msg_bob = Message::load_from_db(&alice, msg_bob.msg_ids[0]).await?;
        assert_eq!(msg_bob.from_id, bob_id);
        assert_eq!(msg_bob.chat_id, msg.chat_id);
        assert_eq!(msg_bob.viewtype, Viewtype::Text);
        assert_eq!(msg_bob.state, MessageState::InFresh);
        assert_eq!(msg_bob.hidden, false);
        assert_eq!(msg_bob.text, "Reply + reaction");
        let reactions = get_msg_reactions(&alice, msg.id).await?;
        assert_eq!(reactions.to_string(), "👍1");

        Ok(())
    }

    async fn expect_reactions_changed_event(
        t: &TestContext,
        expected_chat_id: ChatId,
        expected_msg_id: MsgId,
        expected_contact_id: ContactId,
    ) -> Result<()> {
        let event = t
            .evtracker
            .get_matching(|evt| {
                matches!(
                    evt,
                    EventType::ReactionsChanged { .. } | EventType::IncomingMsg { .. }
                )
            })
            .await;
        match event {
            EventType::ReactionsChanged {
                chat_id,
                msg_id,
                contact_id,
            } => {
                assert_eq!(chat_id, expected_chat_id);
                assert_eq!(msg_id, expected_msg_id);
                assert_eq!(contact_id, expected_contact_id);
            }
            _ => panic!("Unexpected event {event:?}."),
        }
        Ok(())
    }

    async fn expect_incoming_reactions_event(
        t: &TestContext,
        expected_chat_id: ChatId,
        expected_msg_id: MsgId,
        expected_contact_id: ContactId,
        expected_reaction: &str,
    ) -> Result<()> {
        let event = t
            .evtracker
            // Check for absence of `IncomingMsg` events -- it appeared that it's quite easy to make
            // bugs when `IncomingMsg` is issued for reactions.
            .get_matching(|evt| {
                matches!(
                    evt,
                    EventType::IncomingReaction { .. } | EventType::IncomingMsg { .. }
                )
            })
            .await;
        match event {
            EventType::IncomingReaction {
                chat_id,
                msg_id,
                contact_id,
                reaction,
            } => {
                assert_eq!(chat_id, expected_chat_id);
                assert_eq!(msg_id, expected_msg_id);
                assert_eq!(contact_id, expected_contact_id);
                assert_eq!(reaction, Reaction::from(expected_reaction));
            }
            _ => panic!("Unexpected event {event:?}."),
        }
        Ok(())
    }

    /// Checks that no unwanted events remain after expecting "wanted" reaction events.
    async fn expect_no_unwanted_events(t: &TestContext) {
        let ev = t
            .evtracker
            .get_matching_opt(t, |evt| {
                matches!(
                    evt,
                    EventType::IncomingReaction { .. }
                        | EventType::IncomingMsg { .. }
                        | EventType::MsgsChanged { .. }
                )
            })
            .await;
        if let Some(ev) = ev {
            panic!("Unwanted event {ev:?}.")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_reaction() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let bob = TestContext::new_bob().await;

        // Test that the status does not get mixed up into reactions.
        alice
            .set_config(
                Config::Selfstatus,
                Some("Buy Delta Chat today and make this banner go away!"),
            )
            .await?;
        bob.set_config(Config::Selfstatus, Some("Sent from my Delta Chat Pro. 👍"))
            .await?;

        let chat_alice = alice.create_chat(&bob).await;
        let alice_msg = alice.send_text(chat_alice.id, "Hi!").await;
        let bob_msg = bob.recv_msg(&alice_msg).await;
        assert_eq!(
            get_chat_msgs(&alice, chat_alice.id).await?.len(),
            E2EE_INFO_MSGS + 1
        );
        assert_eq!(
            get_chat_msgs(&bob, bob_msg.chat_id).await?.len(),
            E2EE_INFO_MSGS + 1
        );

        let alice_msg2 = alice.send_text(chat_alice.id, "Hi again!").await;
        bob.recv_msg(&alice_msg2).await;
        assert_eq!(
            get_chat_msgs(&alice, chat_alice.id).await?.len(),
            E2EE_INFO_MSGS + 2
        );
        assert_eq!(
            get_chat_msgs(&bob, bob_msg.chat_id).await?.len(),
            E2EE_INFO_MSGS + 2
        );

        bob_msg.chat_id.accept(&bob).await?;

        bob.evtracker.clear_events();
        send_reaction(&bob, bob_msg.id, "👍").await.unwrap();
        expect_reactions_changed_event(&bob, bob_msg.chat_id, bob_msg.id, ContactId::SELF).await?;
        expect_no_unwanted_events(&bob).await;
        assert_eq!(
            get_chat_msgs(&bob, bob_msg.chat_id).await?.len(),
            E2EE_INFO_MSGS + 2
        );

        let bob_reaction_msg = bob.pop_sent_msg().await;
        let alice_reaction_msg = alice.recv_msg_hidden(&bob_reaction_msg).await;
        assert_eq!(alice_reaction_msg.state, MessageState::InFresh);
        assert_eq!(
            get_chat_msgs(&alice, chat_alice.id).await?.len(),
            E2EE_INFO_MSGS + 2
        );

        let reactions = get_msg_reactions(&alice, alice_msg.sender_msg_id).await?;
        assert_eq!(reactions.to_string(), "👍1");
        let contacts = reactions.contacts();
        assert_eq!(contacts.len(), 1);
        let bob_id = contacts.first().unwrap();
        let bob_reaction = reactions.get(*bob_id);
        assert_eq!(bob_reaction.is_empty(), false);
        assert_eq!(bob_reaction.emojis(), vec!["👍"]);
        assert_eq!(bob_reaction.as_str(), "👍");
        expect_reactions_changed_event(&alice, chat_alice.id, alice_msg.sender_msg_id, *bob_id)
            .await?;
        expect_incoming_reactions_event(
            &alice,
            chat_alice.id,
            alice_msg.sender_msg_id,
            *bob_id,
            "👍",
        )
        .await?;
        expect_no_unwanted_events(&alice).await;

        marknoticed_chat(&alice, chat_alice.id).await?;
        assert_eq!(
            alice_reaction_msg.id.get_state(&alice).await?,
            MessageState::InSeen
        );
        // Reactions don't request MDNs, but an MDN to self is sent.
        assert_eq!(
            alice
                .sql
                .count("SELECT COUNT(*) FROM smtp_mdns", ())
                .await?,
            1
        );
        assert_eq!(
            alice
                .sql
                .count(
                    "SELECT COUNT(*) FROM smtp_mdns WHERE from_id=?",
                    (ContactId::SELF,)
                )
                .await?,
            1
        );

        // Alice reacts to own message.
        send_reaction(&alice, alice_msg.sender_msg_id, "👍 😀")
            .await
            .unwrap();
        let reactions = get_msg_reactions(&alice, alice_msg.sender_msg_id).await?;
        assert_eq!(reactions.to_string(), "👍2 😀1");

        assert_eq!(
            reactions.emoji_sorted_by_frequency(),
            vec![("👍".to_string(), 2), ("😀".to_string(), 1)]
        );

        Ok(())
    }

    async fn assert_summary(t: &TestContext, expected: &str) {
        let chatlist = Chatlist::try_load(t, 0, None, None).await.unwrap();
        let summary = chatlist.get_summary(t, 0, None).await.unwrap();
        assert_eq!(summary.text, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction_summary() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        alice.set_config(Config::Displayname, Some("ALICE")).await?;
        bob.set_config(Config::Displayname, Some("BOB")).await?;
        let alice_bob_id = alice.add_or_lookup_contact_id(&bob).await;

        // Alice sends message to Bob
        let alice_chat = alice.create_chat(&bob).await;
        let alice_msg1 = alice.send_text(alice_chat.id, "Party?").await;
        let bob_msg1 = bob.recv_msg(&alice_msg1).await;

        // Bob reacts to Alice's message, this is shown in the summaries
        SystemTime::shift(Duration::from_secs(10));
        bob_msg1.chat_id.accept(&bob).await?;
        send_reaction(&bob, bob_msg1.id, "👍").await?;
        let bob_send_reaction = bob.pop_sent_msg().await;
        alice.recv_msg_hidden(&bob_send_reaction).await;
        expect_incoming_reactions_event(
            &alice,
            alice_chat.id,
            alice_msg1.sender_msg_id,
            alice_bob_id,
            "👍",
        )
        .await?;
        expect_no_unwanted_events(&alice).await;

        let chatlist = Chatlist::try_load(&bob, 0, None, None).await?;
        let summary = chatlist.get_summary(&bob, 0, None).await?;
        assert_eq!(summary.text, "You reacted 👍 to \"Party?\"");
        assert_eq!(summary.timestamp, bob_msg1.get_timestamp()); // time refers to message, not to reaction
        assert_eq!(summary.state, MessageState::InFresh); // state refers to message, not to reaction
        assert!(summary.prefix.is_none());
        assert!(summary.thumbnail_path.is_none());
        assert_summary(&alice, "BOB reacted 👍 to \"Party?\"").await;

        // Alice reacts to own message as well
        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice, alice_msg1.sender_msg_id, "🍿").await?;
        let alice_send_reaction = alice.pop_sent_msg().await;
        bob.evtracker.clear_events();
        bob.recv_msg_opt(&alice_send_reaction).await;
        expect_no_unwanted_events(&bob).await;

        assert_summary(&alice, "You reacted 🍿 to \"Party?\"").await;
        assert_summary(&bob, "ALICE reacted 🍿 to \"Party?\"").await;

        // Alice sends a newer message, this overwrites reaction summaries
        SystemTime::shift(Duration::from_secs(10));
        let alice_msg2 = alice.send_text(alice_chat.id, "kewl").await;
        bob.recv_msg(&alice_msg2).await;

        assert_summary(&alice, "kewl").await;
        assert_summary(&bob, "kewl").await;

        // Reactions to older messages still overwrite newer messages
        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice, alice_msg1.sender_msg_id, "🤘").await?;
        let alice_send_reaction = alice.pop_sent_msg().await;
        bob.recv_msg_opt(&alice_send_reaction).await;

        assert_summary(&alice, "You reacted 🤘 to \"Party?\"").await;
        assert_summary(&bob, "ALICE reacted 🤘 to \"Party?\"").await;

        // Retracted reactions remove all summary reactions
        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice, alice_msg1.sender_msg_id, "").await?;
        let alice_remove_reaction = alice.pop_sent_msg().await;
        bob.recv_msg_opt(&alice_remove_reaction).await;

        assert_summary(&alice, "kewl").await;
        assert_summary(&bob, "kewl").await;

        // Alice adds another reaction and then deletes the message reacted to; this will also delete reaction summary
        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice, alice_msg1.sender_msg_id, "🧹").await?;
        assert_summary(&alice, "You reacted 🧹 to \"Party?\"").await;

        delete_msgs(&alice, &[alice_msg1.sender_msg_id]).await?; // this will leave a tombstone
        assert_summary(&alice, "kewl").await;
        housekeeping(&alice).await?; // this will delete the tombstone
        assert_summary(&alice, "kewl").await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction_forwarded_summary() -> Result<()> {
        let alice = TestContext::new_alice().await;

        // Alice adds a message to "Saved Messages"
        let self_chat = alice.get_self_chat().await;
        let msg_id = send_text_msg(&alice, self_chat.id, "foo".to_string()).await?;
        assert_summary(&alice, "foo").await;

        // Alice reacts to that message
        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice, msg_id, "🐫").await?;
        assert_summary(&alice, "You reacted 🐫 to \"foo\"").await;
        let reactions = get_msg_reactions(&alice, msg_id).await?;
        assert_eq!(reactions.reactions.len(), 1);

        // Alice forwards that message to Bob: Reactions are not forwarded, the message is prefixed by "Forwarded".
        let bob_id = Contact::create(&alice, "", "bob@example.net").await?;
        let bob_chat_id = ChatId::create_for_contact(&alice, bob_id).await?;
        forward_msgs(&alice, &[msg_id], bob_chat_id).await?;
        assert_summary(&alice, "Forwarded: foo").await; // forwarded messages are prefixed
        let chatlist = Chatlist::try_load(&alice, 0, None, None).await.unwrap();
        let forwarded_msg_id = chatlist.get_msg_id(0)?.unwrap();
        let reactions = get_msg_reactions(&alice, forwarded_msg_id).await?;
        assert!(reactions.reactions.is_empty()); // reactions are not forwarded

        // Alice reacts to forwarded message:
        // For reaction summary neither original message author nor "Forwarded" prefix is shown
        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice, forwarded_msg_id, "🐳").await?;
        assert_summary(&alice, "You reacted 🐳 to \"foo\"").await;
        let reactions = get_msg_reactions(&alice, msg_id).await?;
        assert_eq!(reactions.reactions.len(), 1);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction_self_chat_multidevice_summary() -> Result<()> {
        let alice0 = TestContext::new_alice().await;
        let alice1 = TestContext::new_alice().await;
        let chat = alice0.get_self_chat().await;

        let msg_id = send_text_msg(&alice0, chat.id, "mom's birthday!".to_string()).await?;
        alice1.recv_msg(&alice0.pop_sent_msg().await).await;

        SystemTime::shift(Duration::from_secs(10));
        send_reaction(&alice0, msg_id, "👆").await?;
        let sync = alice0.pop_sent_msg().await;
        receive_imf(&alice1, sync.payload().as_bytes(), false).await?;

        assert_summary(&alice0, "You reacted 👆 to \"mom's birthday!\"").await;
        assert_summary(&alice1, "You reacted 👆 to \"mom's birthday!\"").await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_reaction_multidevice() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice0 = tcm.alice().await;
        let alice1 = tcm.alice().await;
        let bob = tcm.bob().await;
        let chat_id = alice0.create_chat(&bob).await.id;

        let alice0_msg_id = send_text_msg(&alice0, chat_id, "foo".to_string()).await?;
        let alice1_msg = alice1.recv_msg(&alice0.pop_sent_msg().await).await;

        send_reaction(&alice0, alice0_msg_id, "👀").await?;
        alice1.recv_msg_hidden(&alice0.pop_sent_msg().await).await;

        expect_reactions_changed_event(&alice0, chat_id, alice0_msg_id, ContactId::SELF).await?;
        expect_reactions_changed_event(&alice1, alice1_msg.chat_id, alice1_msg.id, ContactId::SELF)
            .await?;
        for a in [&alice0, &alice1] {
            expect_no_unwanted_events(a).await;
        }
        Ok(())
    }
}
