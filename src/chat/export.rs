//! # Export a single chat as a ZIP-file.
//!
//! Scope of the export is to have a long-living archive of the chat
//! as a focused snapshot with most important, non-dynamic things.
//! message text, attached images and files, quotes, info messages,
//! names, avatars, times and the chat description or contact's bio.
//! Target group is the end user, being able to access their data detached from an chatmail app.
//!
//! The ZIP-file contains:
//! - `index.html`, the messages in a layout similar to the one of the UIs.
//!   The file is well-formed XML so that it can be processed with a simple XML parser.
//! - `style.css`
//! - `files/`, all attachments and avatars referenced by `index.html`
//!
//! Non-goal is to get in contact again via an export, to bundle keys etc.;
//! for that, use a chatmail app.
//! Non-goal is to replicate all data that are in the database;
//! for that, use a backup.
//! Non-goal is to add dynamic data that as delivery state, reactions or apps.
//! Non-goal is to export everything that the UIs show on top of the messages;
//! apps, audio and videos are exported as files, without a player or preview.
//! Non-goal is to make the file more complex than needed,
//! we rely on the browser wherever possible to keep things slick and fast,
//! e.g. images can be enlarged by a right click or the zoom gesture
//! and there is already a search in the browser.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context as _, Result};
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipDateTime, ZipDateTimeBuilder, ZipEntryBuilder};
use chrono::{DateTime, Datelike as _, Local, Timelike as _};
use quick_xml::escape::escape;
use regex::regex;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::TokioAsyncReadCompatExt as _;

use crate::chat::{self, Chat, ChatId, ChatItem, MessageListOptions};
use crate::constants::Chattype;
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::log::warn;
use crate::message::{Message, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::stock_str;
use crate::tools::time;

/// Exports a chat as a ZIP-file.
/// If destination exists, it is overwritten.
pub async fn export_chat(context: &Context, chat_id: ChatId, dest: &Path) -> Result<()> {
    let res = export_chat_inner(context, chat_id, dest).await;
    if res.is_err() {
        fs::remove_file(dest).await.ok();
    }
    res
}

async fn export_chat_inner(context: &Context, chat_id: ChatId, dest: &Path) -> Result<()> {
    let chat = Chat::load_from_db(context, chat_id).await?;
    let file = File::create(dest)
        .await
        .with_context(|| format!("Cannot create {}", dest.display()))?;
    let mut exporter = Exporter {
        zip: ZipFileWriter::with_tokio(file),
        export_date: zip_datetime(time()),
        show_senders: chat.typ != Chattype::Single,
        rendered_contact_avatars: HashMap::new(),
        added_files: HashSet::new(),
    };

    let chat_name = text_to_html(chat.get_name());
    let chat_avatar = exporter
        .render_avatar(
            context,
            chat.get_profile_image(context).await?.as_deref(),
            chat.get_color(context).await?,
            chat.get_name(),
        )
        .await?;
    let description = if chat.typ == Chattype::Single {
        match chat::get_chat_contacts(context, chat_id).await?.first() {
            Some(contact_id) => Contact::get_by_id(context, *contact_id)
                .await?
                .get_status()
                .to_string(),
            None => String::new(),
        }
    } else {
        chat::get_chat_description(context, chat_id).await?
    };
    let description = if description.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"description\">{}</div>",
            text_to_linkified_html(&description)
        )
    };
    let mut html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>{chat_name}</title>
<link rel="stylesheet" href="style.css" />
</head>
<body>
<div class="chat">
<div class="header">{chat_avatar}<h1>{chat_name}</h1>{description}</div>
"#
    );

    let items = chat::get_chat_msgs_ext(
        context,
        chat_id,
        MessageListOptions {
            add_daymarker: true,
        },
    )
    .await?;
    for item in items {
        match item {
            ChatItem::DayMarker { timestamp } => {
                let day = local_time(timestamp).format("%Y-%m-%d");
                html += &format!("<div class=\"day\">{day}</div>\n");
            }
            ChatItem::Message { msg_id } => {
                let msg = Message::load_from_db(context, msg_id).await?;
                if msg.is_info() {
                    let archivable_info = !matches!(
                        msg.get_info_type(),
                        SystemMessage::ChatE2ee
                            | SystemMessage::SecurejoinWait
                            | SystemMessage::SecurejoinWaitTimeout
                    );
                    if archivable_info {
                        html += &exporter.render_info(context, &msg).await?;
                    }
                } else {
                    html += &exporter.render_bubble(context, &msg).await?;
                }
            }
        }
    }
    html += "</div>\n</body>\n</html>\n";
    exporter.add_bytes("index.html", html.as_bytes()).await?;

    let css = include_str!("../../assets/chat-export.css");
    exporter.add_bytes("style.css", css.as_bytes()).await?;

    let mut file = exporter.zip.close().await?.into_inner();
    file.flush().await?;
    Ok(())
}

struct Exporter {
    zip: ZipFileWriter<File>,
    export_date: ZipDateTime,
    show_senders: bool,
    rendered_contact_avatars: HashMap<ContactId, String>,

    /// Names of the entries below `files/` that are already written.
    added_files: HashSet<String>,
}

impl Exporter {
    fn new_entry(&self, name: &str, compression: Compression) -> ZipEntryBuilder {
        ZipEntryBuilder::new(name.to_string().into(), compression)
            .last_modification_date(self.export_date)
    }

    async fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let entry = self.new_entry(name, Compression::Deflate);
        self.zip.write_entry_whole(entry, data).await?;
        Ok(())
    }

    /// Adds a file to the archive and returns the path inside the archive.
    /// Returns the existing path if the file was already added.
    /// Returns `None` if the file cannot be read, e.g. if it was not downloaded.
    async fn add_file(
        &mut self,
        context: &Context,
        path: &Path,
        modified: ZipDateTime,
        compression: Compression,
    ) -> Result<Option<String>> {
        let Some(name) = path.file_name() else {
            return Ok(None);
        };
        let name = format!("files/{}", name.to_string_lossy());
        if !self.added_files.contains(&name) {
            let src = match File::open(path).await {
                Ok(src) => src,
                Err(err) => {
                    warn!(
                        context,
                        "Chat export: skipping {}: {err:#}.",
                        path.display()
                    );
                    return Ok(None);
                }
            };
            let entry = self
                .new_entry(&name, compression)
                .last_modification_date(modified);
            let mut entry = self.zip.write_entry_stream(entry).await?;
            futures::io::copy(src.compat(), &mut entry).await?;
            entry.close().await?;
            self.added_files.insert(name.clone());
        }
        Ok(Some(name))
    }

    /// Returns avatar as HTML, either image or first-letter-fallback
    async fn render_avatar(
        &mut self,
        context: &Context,
        image: Option<&Path>,
        color: u32,
        name: &str,
    ) -> Result<String> {
        if let Some(image) = image
            && let Some(src) = self
                .add_file(context, image, self.export_date, Compression::Stored)
                .await?
        {
            return Ok(format!(r#"<img class="avatar" src="{src}" alt="" />"#));
        }
        let letter = name
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_default();
        Ok(format!(
            r#"<div class="avatar" style="background: #{color:06x}">{}</div>"#,
            text_to_html(&letter)
        ))
    }

    async fn render_contact_avatar(
        &mut self,
        context: &Context,
        contact: &Contact,
    ) -> Result<String> {
        if let Some(avatar) = self.rendered_contact_avatars.get(&contact.id) {
            return Ok(avatar.clone());
        }
        let avatar = self
            .render_avatar(
                context,
                contact.get_profile_image(context).await?.as_deref(),
                contact.get_color(),
                contact.get_display_name(),
            )
            .await?;
        self.rendered_contact_avatars
            .insert(contact.id, avatar.clone());
        Ok(avatar)
    }

    async fn render_info(&mut self, context: &Context, msg: &Message) -> Result<String> {
        let id = msg.get_id().to_u32();
        let text = text_to_html(&msg.get_text());
        let target = match msg.get_info_type() {
            SystemMessage::MessagePinned | SystemMessage::MessageUnpinned => {
                linkable(msg, msg.parent(context).await?.as_ref())
            }
            _ => None,
        };
        Ok(match target {
            Some(target) => {
                format!("<a class=\"row info\" id=\"m{id}\" href=\"#m{target}\">{text}</a>\n")
            }
            None => format!("<div class=\"row info\" id=\"m{id}\">{text}</div>\n"),
        })
    }

    async fn render_bubble(&mut self, context: &Context, msg: &Message) -> Result<String> {
        let id = msg.get_id().to_u32();
        let from_id = msg.get_from_id();
        let outgoing = from_id == ContactId::SELF;
        let show_sender = self.show_senders && !outgoing;
        let contact = Contact::get_by_id(context, from_id).await?;
        let direction = if outgoing { "out" } else { "in" };
        let mut html = format!("<div class=\"row msg {direction}\" id=\"m{id}\">\n");

        if show_sender {
            html += &self.render_contact_avatar(context, &contact).await?;
            html += "\n";
        }

        html += "<div class=\"bubble\">\n";
        if show_sender {
            let sender = text_to_html(&msg.get_sender_name(&contact));
            let color = contact.get_color();
            html +=
                &format!("<div class=\"sender\" style=\"color: #{color:06x}\">{sender}</div>\n");
        }
        if msg.is_forwarded() {
            let forwarded = text_to_html(&stock_str::forwarded(context));
            html += &format!("<div class=\"forwarded\">{forwarded}</div>\n");
        }
        if let Some(quoted_text) = msg.quoted_text() {
            let quoted_msg = msg.quoted_message(context).await?;
            let mut style = String::new();
            let mut author = String::new();
            if let Some(quoted_msg) = &quoted_msg {
                let contact = Contact::get_by_id(context, quoted_msg.get_from_id()).await?;
                let name = text_to_html(&quoted_msg.get_sender_name(&contact));
                let color = contact.get_color();
                style = format!(" style=\"border-left-color: #{color:06x}\"");
                author =
                    format!("<div class=\"author\" style=\"color: #{color:06x}\">{name}</div>");
            }
            let quote = text_to_html(&quoted_text);
            html += &match linkable(msg, quoted_msg.as_ref()) {
                Some(target) => {
                    format!("<a class=\"quote\" href=\"#m{target}\"{style}>{author}{quote}</a>\n")
                }
                None => format!("<div class=\"quote\"{style}>{author}{quote}</div>\n"),
            };
        }

        if let Some(path) = msg.get_file(context) {
            let compression = match msg.get_viewtype() {
                Viewtype::Image
                | Viewtype::Gif
                | Viewtype::Sticker
                | Viewtype::Video
                | Viewtype::Webxdc
                | Viewtype::Audio
                | Viewtype::Voice => Compression::Stored, // speed up export by not trying to compress already compressed files
                _ => Compression::Deflate,
            };
            if let Some(src) = self
                .add_file(
                    context,
                    &path,
                    zip_datetime(msg.get_timestamp()),
                    compression,
                )
                .await?
            {
                if matches!(
                    msg.get_viewtype(),
                    Viewtype::Image | Viewtype::Gif | Viewtype::Sticker
                ) {
                    html += &format!("<img src=\"{src}\" alt=\"\" />\n");
                } else {
                    let filename = text_to_html(&msg.get_filename().unwrap_or_default());
                    html += &format!("<a href=\"{src}\">{filename}</a>\n");
                }
            }
        }

        let text = msg.get_text();
        if !text.is_empty() {
            html += &format!(
                "<div class=\"text\">{}</div>\n",
                text_to_linkified_html(&text)
            );
        }
        let time = local_time(msg.get_timestamp());
        html += &format!(
            "<time datetime=\"{}\">{}</time>\n</div>\n</div>\n",
            time.to_rfc3339(),
            time.format("%H:%M")
        );
        Ok(html)
    }
}

/// Returns the ID of `target` if it is in the same chat as `msg`
/// and therefore part of the export, so that `msg` can link to it.
fn linkable(msg: &Message, target: Option<&Message>) -> Option<u32> {
    target
        .filter(|target| target.get_chat_id() == msg.get_chat_id())
        .map(|target| target.get_id().to_u32())
}

/// Returns `timestamp` as `ZipDateTime`.
fn zip_datetime(timestamp: i64) -> ZipDateTime {
    let time = local_time(timestamp);
    // ZIP can store local time of the years 1980 to 2107 only.
    ZipDateTimeBuilder::new()
        .year(time.year().clamp(1980, 2107))
        .month(time.month())
        .day(time.day())
        .hour(time.hour())
        .minute(time.minute())
        .second(time.second())
        .build()
}

fn local_time(timestamp: i64) -> DateTime<Local> {
    DateTime::from_timestamp(timestamp, 0)
        .unwrap_or_default()
        .with_timezone(&Local)
}

/// Escapes text for use in XML.
/// Replaces newlines by `<br />` and removes control characters.
fn text_to_html(text: &str) -> String {
    let text: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    escape(&text).replace('\n', "<br />")
}

/// Like [`text_to_html()`] and additionally turns detected URLs into links.
fn text_to_linkified_html(text: &str) -> String {
    let url_re = regex!(r"\b((http|https|ftp|ftps):[\w.,:;$/@!?&%\-~=#+]+)");
    let mut html = String::new();
    let mut end = 0;
    for m in url_re.find_iter(text) {
        // Trailing punctuation is more likely to be part of the sentence than of the URL.
        let url = m.as_str().trim_end_matches(['.', ',', ':', ';', '!', '?']);
        let escaped = text_to_html(url);
        html += &text_to_html(text.get(end..m.start()).unwrap_or_default());
        html += &format!("<a href=\"{escaped}\">{escaped}</a>");
        end = m.start().saturating_add(url.len());
    }
    html + &text_to_html(text.get(end..).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use async_zip::base::read::mem::ZipFileReader;
    use quick_xml::events::Event;

    use super::*;
    use crate::message::MessageState;
    use crate::pinned_messages::set_pinned_state;
    use crate::test_utils::{TestContext, TestContextManager, create_test_image};

    // exports and reads the archive back, returning html and all file names
    async fn export_chat_and_return_content(
        t: &TestContext,
        chat_id: ChatId,
    ) -> Result<(String, Vec<String>)> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("chat.zip");
        export_chat(t, chat_id, &dest).await?;

        let zip = ZipFileReader::new(fs::read(&dest).await?).await?;
        let names: Vec<String> = zip
            .file()
            .entries()
            .iter()
            .map(|e| e.filename().as_str().map(|s| s.to_string()))
            .collect::<Result<_, _>>()?;
        let index = names.iter().position(|n| n == "index.html").unwrap();
        let mut html = Vec::new();
        zip.reader_with_entry(index)
            .await?
            .read_to_end_checked(&mut html)
            .await?;
        let html = String::from_utf8(html)?;

        // `index.html` has to be well-formed XML.
        let mut reader = quick_xml::Reader::from_str(&html);
        while reader.read_event()? != Event::Eof {}

        Ok((html, names))
    }

    #[test]
    fn test_zip_datetime_with_unusual_timestamps() {
        // The ZIP date builder panics for years that cannot be stored.
        for timestamp in [i64::MIN, -1, 0, 4_500_000_000, i64::MAX] {
            zip_datetime(timestamp);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        let alice_chat_id = alice.create_chat(bob).await.id;
        let bob_chat_id = bob.create_chat(alice).await.id;

        let sent = alice
            .send_text(alice_chat_id, "<b>Hi</b> & \"bye\"\nsecond line")
            .await;
        bob.recv_msg(&sent).await;
        let sent = bob.send_text(bob_chat_id, "Hi Alice").await;
        let hi_alice = alice.recv_msg(&sent).await;

        let mut msg = Message::new(Viewtype::Image);
        msg.set_file_from_bytes(alice, "image.png", &create_test_image(10, 10)?, None)?;
        chat::send_msg(alice, alice_chat_id, &mut msg).await?;
        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "doc.txt", b"content", None)?;
        chat::send_msg(alice, alice_chat_id, &mut msg).await?;
        alice
            .send_text(alice_chat_id, "See https://example.org/a?b=1&c=2. Done")
            .await;
        let mut msg = Message::new_text("reply".to_string());
        msg.set_quote(alice, Some(&hi_alice)).await?;
        chat::send_msg(alice, alice_chat_id, &mut msg).await?;
        chat::add_info_msg(alice, alice_chat_id, "An <info>").await?;
        set_pinned_state(alice, hi_alice.get_id(), true).await?;
        let pin_info_id = alice.get_last_msg_id_in(alice_chat_id).await;

        let (html, names) = export_chat_and_return_content(alice, alice_chat_id).await?;
        assert!(!html.contains("<b>Hi</b>"));
        assert!(html.contains("&lt;b&gt;Hi&lt;/b&gt; &amp; &quot;bye&quot;<br />second line"));
        assert!(html.contains(
            r#"See <a href="https://example.org/a?b=1&amp;c=2">https://example.org/a?b=1&amp;c=2</a>. Done"#
        ));
        assert!(html.contains(r#"<div class="row msg in" id="m"#));
        assert!(html.contains(r#"<div class="row msg out" id="m"#));
        assert!(html.contains(r#"<div class="row info" id="m"#));
        assert!(html.contains("An &lt;info&gt;"));
        assert!(html.contains(&format!(
            r##"<a class="row info" id="m{}" href="#m{}">"##,
            pin_info_id.to_u32(),
            hi_alice.get_id().to_u32()
        )));
        assert!(!html.contains("end-to-end encrypted"));
        // The quote is a link to the quoted message, with its author on top.
        assert!(html.contains(&format!(
            r##"<a class="quote" href="#m{}" style="border-left-color: #"##,
            hi_alice.get_id().to_u32()
        )));
        assert!(html.contains(r#"<div class="author" style="color: #"#));
        assert!(html.contains("</div>Hi Alice</a>"));
        assert!(html.contains(r#"<a href="files/"#));
        assert!(html.contains("doc.txt</a>"));
        assert!(html.contains(r#"<img src="files/"#));
        assert!(names.contains(&"style.css".to_string()));

        // The image and the file, no avatars in a one-to-one chat.
        assert_eq!(names.iter().filter(|n| n.starts_with("files/")).count(), 2);
        for name in names.iter().filter(|n| n.starts_with("files/")) {
            assert!(html.contains(&format!("\"{name}\"")));
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_group() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        let alice_chat_id = chat::create_group(alice, "Group <1>").await?;
        let bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
        chat::add_contact_to_chat(alice, alice_chat_id, bob_contact_id).await?;

        let sent = alice.send_text(alice_chat_id, "Hi from Alice").await;
        let msg = bob.recv_msg(&sent).await;
        assert_eq!(msg.get_state(), MessageState::InFresh);

        let (html, names) = export_chat_and_return_content(bob, msg.get_chat_id()).await?;
        assert!(html.contains("<h1>Group &lt;1&gt;</h1>"));
        assert!(!html.contains(r#"class="description""#));
        assert!(html.contains(r#"<div class="sender" style="color: #"#));
        // Avatars without an image are replaced by the first letter.
        assert!(html.contains(r#"<div class="avatar" style="background: #"#));
        assert_eq!(names.len(), 2);

        chat::set_chat_description(alice, alice_chat_id, "About <us>").await?;
        let (html, _) = export_chat_and_return_content(alice, alice_chat_id).await?;
        assert!(html.contains(r#"<div class="description">About &lt;us&gt;</div>"#));
        Ok(())
    }
}
