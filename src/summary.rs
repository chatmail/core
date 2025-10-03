//! # Message summary for chatlist.

use std::borrow::Cow;
use std::fmt;
use std::str;

use crate::calls::{CallState, call_state};
use crate::chat::Chat;
use crate::constants::Chattype;
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::message::{Message, MessageState, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::stock_str;
use crate::stock_str::msg_reacted;
use crate::tools::truncate;
use anyhow::Result;

/// Prefix displayed before message and separated by ":" in the chatlist.
#[derive(Debug)]
pub enum SummaryPrefix {
    /// Username.
    Username(String),

    /// Stock string saying "Draft".
    Draft(String),

    /// Stock string saying "Me".
    Me(String),
}

impl fmt::Display for SummaryPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SummaryPrefix::Username(username) => write!(f, "{username}"),
            SummaryPrefix::Draft(text) => write!(f, "{text}"),
            SummaryPrefix::Me(text) => write!(f, "{text}"),
        }
    }
}

/// Message summary.
#[derive(Debug, Default)]
pub struct Summary {
    /// Part displayed before ":", such as an username or a string "Draft".
    pub prefix: Option<SummaryPrefix>,

    /// Summary text, always present.
    pub text: String,

    /// Message timestamp.
    pub timestamp: i64,

    /// Message state.
    pub state: MessageState,

    /// Message preview image path
    pub thumbnail_path: Option<String>,
}

impl Summary {
    /// Constructs chatlist summary
    /// from the provided message, chat and message author contact snapshots.
    pub async fn new_with_reaction_details(
        context: &Context,
        msg: &Message,
        chat: &Chat,
        contact: Option<&Contact>,
    ) -> Result<Summary> {
        if let Some((reaction_msg, reaction_contact_id, reaction)) = chat
            .get_last_reaction_if_newer_than(context, msg.timestamp_sort)
            .await?
        {
            // there is a reaction newer than the latest message, show that.
            // sorting and therefore date is still the one of the last message,
            // the reaction is is more sth. that overlays temporarily.
            let summary = reaction_msg.get_summary_text_without_prefix(context).await;
            return Ok(Summary {
                prefix: None,
                text: msg_reacted(context, reaction_contact_id, &reaction, &summary).await,
                timestamp: msg.get_timestamp(), // message timestamp (not reaction) to make timestamps more consistent with chats ordering
                state: msg.state, // message state (not reaction) - indicating if it was me sending the last message
                thumbnail_path: None,
            });
        }
        Self::new(context, msg, chat, contact).await
    }

    /// Constructs search result summary
    /// from the provided message, chat and message author contact snapshots.
    pub async fn new(
        context: &Context,
        msg: &Message,
        chat: &Chat,
        contact: Option<&Contact>,
    ) -> Result<Summary> {
        let prefix = if msg.state == MessageState::OutDraft {
            Some(SummaryPrefix::Draft(stock_str::draft(context).await))
        } else if msg.from_id == ContactId::SELF {
            if msg.is_info() || msg.viewtype == Viewtype::Call {
                None
            } else {
                Some(SummaryPrefix::Me(stock_str::self_msg(context).await))
            }
        } else if chat.typ == Chattype::Group
            || chat.typ == Chattype::OutBroadcast
            || chat.typ == Chattype::InBroadcast
            || chat.typ == Chattype::Mailinglist
            || chat.is_self_talk()
        {
            if msg.is_info() || contact.is_none() {
                None
            } else {
                msg.get_override_sender_name()
                    .or_else(|| contact.map(|contact| msg.get_sender_name(contact)))
                    .map(SummaryPrefix::Username)
            }
        } else {
            None
        };

        let mut text = msg.get_summary_text(context).await;

        if text.is_empty() && msg.quoted_text().is_some() {
            text = stock_str::reply_noun(context).await
        }

        let thumbnail_path = if msg.viewtype == Viewtype::Image
            || msg.viewtype == Viewtype::Gif
            || msg.viewtype == Viewtype::Sticker
        {
            msg.get_file(context)
                .and_then(|path| path.to_str().map(|p| p.to_owned()))
        } else if msg.viewtype == Viewtype::Webxdc {
            Some("webxdc-icon://last-msg-id".to_string())
        } else {
            None
        };

        Ok(Summary {
            prefix,
            text,
            timestamp: msg.get_timestamp(),
            state: msg.state,
            thumbnail_path,
        })
    }

    /// Returns the [`Summary::text`] attribute truncated to an approximate length.
    pub fn truncated_text(&self, approx_chars: usize) -> Cow<'_, str> {
        truncate(&self.text, approx_chars)
    }
}

impl Message {
    /// Returns a summary text.
    pub(crate) async fn get_summary_text(&self, context: &Context) -> String {
        let summary = self.get_summary_text_without_prefix(context).await;

        if self.is_forwarded() {
            format!("{}: {}", stock_str::forwarded(context).await, summary)
        } else {
            summary
        }
    }

    /// Returns a summary text without "Forwarded:" prefix.
    async fn get_summary_text_without_prefix(&self, context: &Context) -> String {
        let (emoji, type_name, type_file, append_text);
        match self.viewtype {
            Viewtype::Image => {
                emoji = Some("📷");
                type_name = Some(stock_str::image(context).await);
                type_file = None;
                append_text = true;
            }
            Viewtype::Gif => {
                emoji = None;
                type_name = Some(stock_str::gif(context).await);
                type_file = None;
                append_text = true;
            }
            Viewtype::Sticker => {
                emoji = None;
                type_name = Some(stock_str::sticker(context).await);
                type_file = None;
                append_text = true;
            }
            Viewtype::Video => {
                emoji = Some("🎥");
                type_name = Some(stock_str::video(context).await);
                type_file = None;
                append_text = true;
            }
            Viewtype::Voice => {
                emoji = Some("🎤");
                type_name = Some(stock_str::voice_message(context).await);
                type_file = None;
                append_text = true;
            }
            Viewtype::Audio => {
                emoji = Some("🎵");
                type_name = Some(stock_str::audio(context).await);
                type_file = self.get_filename();
                append_text = true
            }
            Viewtype::File => {
                emoji = Some("📎");
                type_name = Some(stock_str::file(context).await);
                type_file = self.get_filename();
                append_text = true
            }
            Viewtype::Webxdc => {
                emoji = None;
                type_name = None;
                type_file = Some(
                    self.get_webxdc_info(context)
                        .await
                        .map(|info| info.name)
                        .unwrap_or_else(|_| "ErrWebxdcName".to_string()),
                );
                append_text = true;
            }
            Viewtype::Vcard => {
                emoji = Some("👤");
                type_name = None;
                type_file = self.param.get(Param::Summary1).map(|s| s.to_string());
                append_text = true;
            }
            Viewtype::Call => {
                let call_state = call_state(context, self.id)
                    .await
                    .unwrap_or(CallState::Alerting);
                emoji = Some("📞");
                type_name = Some(match call_state {
                    CallState::Alerting | CallState::Active | CallState::Completed { .. } => {
                        if self.from_id == ContactId::SELF {
                            stock_str::outgoing_call(context).await
                        } else {
                            stock_str::incoming_call(context).await
                        }
                    }
                    CallState::Missed => stock_str::missed_call(context).await,
                    CallState::Declined => stock_str::declined_call(context).await,
                    CallState::Canceled => stock_str::canceled_call(context).await,
                });
                type_file = None;
                append_text = false
            }
            Viewtype::Text | Viewtype::Unknown => {
                emoji = None;
                if self.param.get_cmd() == SystemMessage::LocationOnly {
                    type_name = Some(stock_str::location(context).await);
                    type_file = None;
                    append_text = false;
                } else {
                    type_name = None;
                    type_file = None;
                    append_text = true;
                }
            }
        };

        let text = self.text.clone();

        let summary = if let Some(type_file) = type_file {
            if append_text && !text.is_empty() {
                format!("{type_file} – {text}")
            } else {
                type_file
            }
        } else if append_text && !text.is_empty() {
            if emoji.is_some() {
                text
            } else if let Some(type_name) = type_name {
                format!("{type_name} – {text}")
            } else {
                text
            }
        } else if let Some(type_name) = type_name {
            type_name
        } else {
            "".to_string()
        };

        let summary = if let Some(emoji) = emoji {
            format!("{emoji} {summary}")
        } else {
            summary
        };

        summary.split_whitespace().collect::<Vec<&str>>().join(" ")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::chat::ChatId;
    use crate::param::Param;
    use crate::test_utils::TestContext;

    async fn assert_summary_texts(msg: &Message, ctx: &Context, expected: &str) {
        assert_eq!(msg.get_summary_text(ctx).await, expected);
        assert_eq!(msg.get_summary_text_without_prefix(ctx).await, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_summary_text() {
        let d = TestContext::new_alice().await;
        let ctx = &d.ctx;
        let chat_id = ChatId::create_for_contact(ctx, ContactId::SELF)
            .await
            .unwrap();
        let some_text = " bla \t\n\tbla\n\t".to_string();

        async fn write_file_to_blobdir(d: &TestContext) -> PathBuf {
            let bytes = &[38, 209, 39, 29]; // Just some random bytes
            let file = d.get_blobdir().join("random_filename_392438");
            tokio::fs::write(&file, bytes).await.unwrap();
            file
        }

        let msg = Message::new_text(some_text.to_string());
        assert_summary_texts(&msg, ctx, "bla bla").await; // for simple text, the type is not added to the summary

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Image);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.jpg"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "📷 Image").await; // file names are not added for images

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Image);
        msg.set_text(some_text.to_string());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.jpg"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "📷 bla bla").await; // type is visible by emoji if text is set

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Video);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.mp4"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "🎥 Video").await; // file names are not added for videos

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Video);
        msg.set_text(some_text.to_string());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.mp4"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "🎥 bla bla").await; // type is visible by emoji if text is set

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Gif);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.gif"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "GIF").await; // file names are not added for GIFs

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Gif);
        msg.set_text(some_text.to_string());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.gif"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "GIF \u{2013} bla bla").await; // file names are not added for GIFs

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Sticker);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.png"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "Sticker").await; // file names are not added for stickers

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Voice);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.mp3"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "🎤 Voice message").await; // file names are not added for voice messages

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Voice);
        msg.set_text(some_text.clone());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.mp3"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "🎤 bla bla").await;

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Audio);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.mp3"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "🎵 foo.mp3").await; // file name is added for audio

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::Audio);
        msg.set_text(some_text.clone());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.mp3"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "🎵 foo.mp3 \u{2013} bla bla").await; // file name and text added for audio

        let mut msg = Message::new(Viewtype::File);
        let bytes = include_bytes!("../test-data/webxdc/with-minimal-manifest.xdc");
        msg.set_file_from_bytes(ctx, "foo.xdc", bytes, None)
            .unwrap();
        chat_id.set_draft(ctx, Some(&mut msg)).await.unwrap();
        assert_eq!(msg.viewtype, Viewtype::Webxdc);
        assert_summary_texts(&msg, ctx, "nice app!").await;
        msg.set_text(some_text.clone());
        chat_id.set_draft(ctx, Some(&mut msg)).await.unwrap();
        assert_summary_texts(&msg, ctx, "nice app! \u{2013} bla bla").await;

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::File);
        msg.set_file_and_deduplicate(&d, &file, Some("foo.bar"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "📎 foo.bar").await; // file name is added for files

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::File);
        msg.set_text(some_text.clone());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.bar"), None)
            .unwrap();
        assert_summary_texts(&msg, ctx, "📎 foo.bar \u{2013} bla bla").await; // file name is added for files

        let mut msg = Message::new(Viewtype::Vcard);
        msg.set_file_from_bytes(ctx, "foo.vcf", b"", None).unwrap();
        chat_id.set_draft(ctx, Some(&mut msg)).await.unwrap();
        // If a vCard can't be parsed, the message becomes `Viewtype::File`.
        assert_eq!(msg.viewtype, Viewtype::File);
        assert_summary_texts(&msg, ctx, "📎 foo.vcf").await;
        msg.set_text(some_text.clone());
        assert_summary_texts(&msg, ctx, "📎 foo.vcf \u{2013} bla bla").await;

        for vt in [Viewtype::Vcard, Viewtype::File] {
            let mut msg = Message::new(vt);
            msg.set_file_from_bytes(
                ctx,
                "alice.vcf",
                b"BEGIN:VCARD\n\
                  VERSION:4.0\n\
                  FN:Alice Wonderland\n\
                  EMAIL;TYPE=work:alice@example.org\n\
                  END:VCARD",
                None,
            )
            .unwrap();
            chat_id.set_draft(ctx, Some(&mut msg)).await.unwrap();
            assert_eq!(msg.viewtype, Viewtype::Vcard);
            assert_summary_texts(&msg, ctx, "👤 Alice Wonderland").await;
        }

        // Forwarded
        let mut msg = Message::new_text(some_text.clone());
        msg.param.set_int(Param::Forwarded, 1);
        assert_eq!(msg.get_summary_text(ctx).await, "Forwarded: bla bla"); // for simple text, the type is not added to the summary
        assert_eq!(msg.get_summary_text_without_prefix(ctx).await, "bla bla"); // skipping prefix used for reactions summaries

        let file = write_file_to_blobdir(&d).await;
        let mut msg = Message::new(Viewtype::File);
        msg.set_text(some_text.clone());
        msg.set_file_and_deduplicate(&d, &file, Some("foo.bar"), None)
            .unwrap();
        msg.param.set_int(Param::Forwarded, 1);
        assert_eq!(
            msg.get_summary_text(ctx).await,
            "Forwarded: 📎 foo.bar \u{2013} bla bla"
        );
        assert_eq!(
            msg.get_summary_text_without_prefix(ctx).await,
            "📎 foo.bar \u{2013} bla bla"
        ); // skipping prefix used for reactions summaries

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(ctx, "autocrypt-setup-message.html", b"data", None)
            .unwrap();
        msg.param.set_cmd(SystemMessage::AutocryptSetupMessage);
        assert_summary_texts(&msg, ctx, "📎 autocrypt-setup-message.html").await;
        // no special handling of ASM
    }
}
