//! # Export a single chat as a ZIP-file.
//!
//! Scope of the export is to have a long-living archive of non-ephemeral chat messages.
//! Target group is the end user, being able to access their data detached from a chatmail app.
//!
//! The ZIP-file contains:
//! - `index.html` with the messages.
//!   The file is well-formed and can be processed with a simple XML parser as well.
//!   As browsers cannot handle arbitrary large pages,
//!   large chats are continued in `index-2.html`, `index-3.html` and so on.
//! - `style.css`
//! - `files/`, all attachments and avatars referenced by `index.html`
//!
//! Non-goal is to export non-chat data (eg. contacts) or dynamic data (eg. apps or delivery state);
//! for that, use a backup.
//! Non-goal is to make the file more complex than needed,
//! we rely on the browser wherever possible to keep things slick and fast,
//! e.g. images can be enlarged by a right click or the zoom gesture
//! and there is already a search and a video player in the browser.
//!
//! Some performance notes:
//! - Performance attribute "content-visibility: auto" is not used
//!   as it makes layout harder, eg. clip the reactions,
//!   which is not worth the effort or may even result in the opposite.
//!   Similar for lazy loading of images. keep it simple.
//!   Instead, we offer pagination, so that html files do not get arbitrarily big.
//!   This also lowers memory usage when exporting huge chats
//! - We do not try to re-compress potentially compressed files

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
use crate::ephemeral::Timer as EphemeralTimer;
use crate::log::warn;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::reaction::get_msg_reactions;
use crate::stock_str;
use crate::tools::{time, truncate};

/// Pages larger than `MAX_PAGE_BYTES` are continued on the next page.
///
/// Browsers need time and memory for rendering
/// e.g. chromium on a desktop needs 2 second and 350mb for 5mb of HTML (about 20k messages),
/// phones are often slower.
const MAX_PAGE_BYTES: usize = 1_000_000;

/// Exports a chat as a ZIP-file.
/// If destination exists, it is overwritten.
///
/// `include_images` (images, sticker, gif)
/// and `include_files` (video, apps, files, vcards etc.) define what should be part of the export;
/// avatars are always added.
pub async fn export_chat(
    context: &Context,
    chat_id: ChatId,
    dest: &Path,
    include_images: bool,
    include_files: bool,
) -> Result<()> {
    let res = export_chat_inner(
        context,
        chat_id,
        dest,
        include_images,
        include_files,
        MAX_PAGE_BYTES,
    )
    .await;
    if res.is_err() {
        fs::remove_file(dest).await.ok();
    }
    res
}

async fn export_chat_inner(
    context: &Context,
    chat_id: ChatId,
    dest: &Path,
    include_images: bool,
    include_files: bool,
    max_page_bytes: usize,
) -> Result<()> {
    let file = File::create(dest)
        .await
        .with_context(|| format!("Cannot create {}", dest.display()))?;

    let mut exporter = ChatExporter {
        chat: Chat::load_from_db(context, chat_id).await?,
        zip: ZipFileWriter::with_tokio(file),
        export_date: zip_datetime(time()),
        include_images,
        include_files,
        current_page: 1,
        rendered_contact_avatars: HashMap::new(),
        added_files: HashSet::new(),
        message_pages: HashMap::new(),
    };

    let css = include_str!("../../assets/chat-export.css");
    exporter.add_bytes("style.css", css.as_bytes()).await?;

    let mut html = exporter.render_page_start(1);
    html += &exporter.render_header(context).await?;

    let items = chat::get_chat_msgs_ext(
        context,
        chat_id,
        MessageListOptions {
            add_daymarker: true,
        },
    )
    .await?;

    let mut day = String::new();
    let mut day_added = false;
    for item in items {
        let msg_id = match item {
            ChatItem::DayMarker { timestamp } => {
                // render day headlines only if there is actually a message -
                // and not if all messages of that day are skipped because being ephemeral
                let date = local_time(timestamp).format("%Y-%m-%d");
                day = format!("<div class=\"day\">{date}</div>\n\n");
                day_added = false;
                continue;
            }
            ChatItem::Message { msg_id } => msg_id,
        };

        let msg = Message::load_from_db(context, msg_id).await?;
        if msg.get_ephemeral_timer() != EphemeralTimer::Disabled {
            continue;
        }

        if html.len() >= max_page_bytes {
            // page is full: finish it with a link to the next page ...
            let previous = page_name(exporter.current_page);
            let next = page_name(exporter.current_page.saturating_add(1));
            html += &format!("<div class=\"nav\"><a href=\"{next}\">{next} →</a></div>\n");
            html += &exporter.render_page_end();
            exporter.add_bytes(&previous, html.as_bytes()).await?;

            // ... and start the next page
            exporter.current_page = exporter.current_page.saturating_add(1);
            html = exporter.render_page_start(exporter.current_page);
            html +=
                &format!("<div class=\"nav\"><a href=\"{previous}\">← {previous}</a></div>\n\n");
            day_added = false;
        }

        if !day_added {
            html += &day;
            day_added = true;
        }

        if msg.is_info() {
            html += &exporter.render_info(context, &msg).await?;
        } else {
            html += &exporter.render_bubble(context, &msg).await?;
        }
        exporter.message_pages.insert(msg_id, exporter.current_page);
        html += "\n";
    }

    // finalize last page, close zip and flush everything
    html += &exporter.render_page_end();
    exporter
        .add_bytes(&page_name(exporter.current_page), html.as_bytes())
        .await?;

    let mut file = exporter.zip.close().await?.into_inner();
    file.flush().await?;
    Ok(())
}

struct ChatExporter {
    chat: Chat,
    zip: ZipFileWriter<File>,
    export_date: ZipDateTime,

    /// Number of the page that is currently written, starting with 1.
    current_page: u32,

    /// Add images, stickers and GIFs; avatars are always added.
    include_images: bool,

    /// Add other attachments such as documents, videos and audio.
    include_files: bool,

    rendered_contact_avatars: HashMap<ContactId, String>,

    /// Names of the entries below `files/` that are already written.
    added_files: HashSet<String>,

    /// Pages of the messages that are written already.
    /// Used for links between messages on different pages.
    message_pages: HashMap<MsgId, u32>,
}

impl ChatExporter {
    fn render_page_start(&self, page: u32) -> String {
        let chat_name = text_to_html(self.chat.get_name());

        let title = if page == 1 {
            chat_name.to_string()
        } else {
            format!("{chat_name} ({page})")
        };
        // `\` at the end of a line skips the indentation of the next one
        format!(
            "<!DOCTYPE html>\n\
             <html>\n\
             <head>\n\
             <meta charset=\"utf-8\" />\n\
             <title>{title}</title>\n\
             <link rel=\"stylesheet\" href=\"style.css\" />\n\
             </head>\n\
             <body>\n\
             <div class=\"chat\">\n"
        )
    }

    fn render_page_end(&self) -> String {
        "</div>\n</body>\n</html>\n".to_string()
    }

    async fn render_header(&mut self, context: &Context) -> Result<String> {
        let image = self.chat.get_profile_image(context).await?;
        let color = self.chat.get_color(context).await?;
        let chat_name = self.chat.get_name().to_string();
        let avatar = self
            .render_avatar(context, image.as_deref(), color, &chat_name)
            .await?;
        let headline = text_to_html(&chat_name);

        let description = if self.chat.typ == Chattype::Single {
            match chat::get_chat_contacts(context, self.chat.id)
                .await?
                .first()
            {
                Some(contact_id) => Contact::get_by_id(context, *contact_id)
                    .await?
                    .get_status()
                    .to_string(),
                None => String::new(),
            }
        } else {
            chat::get_chat_description(context, self.chat.id).await?
        };

        let description = if description.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"description\">{}</div>",
                text_to_linkified_html(&description)
            )
        };

        Ok(format!(
            "<div class=\"header\">\n{avatar}\n<h1>{headline}</h1>\n{description}\n</div>\n\n"
        ))
    }

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
            return Ok(format!(r#"<img class="avatar" src="{src}" alt="" />"#)); // return image
        }
        let letter = name
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_default();
        Ok(format!(
            r#"<div class="avatar" style="background: #{color:06x}">{}</div>"#, // return fallback with letter
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

    async fn render_info(&self, context: &Context, msg: &Message) -> Result<String> {
        let id = msg.get_id().to_u32();
        let text = text_to_html(&msg.get_text());
        let target = match msg.get_info_type() {
            SystemMessage::MessagePinned | SystemMessage::MessageUnpinned => {
                self.message_link(msg, msg.parent(context).await?.as_ref())
            }
            _ => None,
        };
        Ok(match target {
            Some(link) => {
                format!("<a class=\"msg info\" id=\"m{id}\" href=\"{link}\">{text}</a>\n")
            }
            None => format!("<div class=\"msg info\" id=\"m{id}\">{text}</div>\n"),
        })
    }

    async fn render_bubble(&mut self, context: &Context, msg: &Message) -> Result<String> {
        let id = msg.get_id().to_u32();
        let from_id = msg.get_from_id();
        let outgoing = from_id == ContactId::SELF;
        let show_sender = self.chat.typ != Chattype::Single && !outgoing;
        let contact = Contact::get_by_id(context, from_id).await?;
        let direction = if outgoing { "out" } else { "in" };
        let mut html = format!("<div class=\"msg {direction}\" id=\"m{id}\">\n");

        if show_sender {
            html += &self.render_contact_avatar(context, &contact).await?;
            html += "\n";
        }

        html += "<div class=\"bubble\">\n";
        if msg.is_forwarded() {
            let sender = text_to_html(&stock_str::forwarded(context));
            html += &format!("<div class=\"sender\" style=\"color: #888\">{sender}</div>\n");
        } else if show_sender {
            let sender = text_to_html(&msg.get_sender_name(&contact));
            let color = contact.get_color();
            html +=
                &format!("<div class=\"sender\" style=\"color: #{color:06x}\">{sender}</div>\n");
        }

        if let Some(quoted_text) = msg.quoted_text() {
            let quoted_msg = msg.quoted_message(context).await?;
            let mut style = String::new();
            let mut author = String::new();
            if let Some(quoted_msg) = &quoted_msg {
                if quoted_msg.is_forwarded() {
                    if !msg.is_forwarded() {
                        let sender = text_to_html(&stock_str::forwarded(context));
                        author = format!("<div class=\"sender\">{sender}</div>");
                    }
                } else {
                    let contact = Contact::get_by_id(context, quoted_msg.get_from_id()).await?;
                    let sender = text_to_html(&quoted_msg.get_sender_name(&contact));
                    let color = contact.get_color();
                    style = format!(" style=\"border-left-color: #{color:06x}\"");
                    author = format!(
                        "<div class=\"sender\" style=\"color: #{color:06x}\">{sender}</div>"
                    );
                }
            }

            let approx_chars = 180; // cut the quote hard, it is just a hint for the quoted message
            let quoted_text = if let Some(quoted_msg) = &quoted_msg {
                let add_forwarded = false; // "Forwarded" is shown above already
                let add_emoji = true;
                quoted_msg
                    .get_summary_text_ext(context, add_forwarded, add_emoji, approx_chars)
                    .await
            } else {
                truncate(&quoted_text, approx_chars).to_string()
            };

            let quote = text_to_html(&quoted_text);
            html += &match self.message_link(msg, quoted_msg.as_ref()) {
                Some(link) => {
                    format!("<a class=\"quote\" href=\"{link}\"{style}>{author}{quote}</a>\n")
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

            let is_image = matches!(
                msg.get_viewtype(),
                Viewtype::Image | Viewtype::Gif | Viewtype::Sticker
            );

            let copy_to_archive = if is_image {
                self.include_images
            } else {
                self.include_files
            };

            let src = if copy_to_archive {
                self.add_file(
                    context,
                    &path,
                    zip_datetime(msg.get_timestamp()),
                    compression,
                )
                .await?
            } else {
                None
            };

            let filename = text_to_html(&msg.get_filename().unwrap_or_default());
            html += &match src {
                Some(src) if is_image => format!("<img src=\"{src}\" alt=\"\" />\n"),
                Some(src) => format!("<a class=\"file\" href=\"{src}\">{filename}</a>\n"),
                None => format!("<div class=\"file\">{filename}</div>\n"),
            };
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
            "<time datetime=\"{}\">{}</time>\n",
            time.to_rfc3339(),
            time.format("%H:%M")
        );

        let reactions = get_msg_reactions(context, msg.get_id()).await?;
        if !reactions.is_empty() {
            let pills: Vec<String> = reactions
                .frequencies
                .iter()
                .map(|f| {
                    let class = if f.is_from_self {
                        " class=\"self\""
                    } else {
                        ""
                    };
                    format!(
                        "<span{class}>{} {}</span>",
                        text_to_html(f.reaction.as_str()),
                        f.count
                    )
                })
                .collect();
            html += &format!("<div class=\"reactions\">{}</div>\n", pills.join(" "));
        }

        html += "</div>\n</div>\n";
        Ok(html)
    }

    fn new_entry(&self, name: &str, compression: Compression) -> ZipEntryBuilder {
        ZipEntryBuilder::new(name.to_string().into(), compression)
            .last_modification_date(self.export_date)
            .unix_permissions(0o644) // otherwise unzip may create unreadable files (mode 000)
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
                    warn!(context, "Export skipped {}: {err:#}.", path.display());
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

    /// Returns the link to the target message.
    /// - if the target message was not written `None` is returned (usually, newer messages reference older ones)
    /// - if the target message is on the same page, a link as `#m1234` is returned
    /// - if the target message is on a previous page, a links as `index.html#m1234`, `index-2.html#m5678` etc. are returned
    fn message_link(&self, msg: &Message, target: Option<&Message>) -> Option<String> {
        let target = target.filter(|target| target.get_chat_id() == msg.get_chat_id())?;
        let page = *self.message_pages.get(&target.get_id())?;
        let file = if page == self.current_page {
            String::new()
        } else {
            page_name(page)
        };
        Some(format!("{file}#m{}", target.get_id().to_u32()))
    }
}

/// Returns the name of the file of the page `page`: `index.html`, `index-2.html`, `index-3.html`.
fn page_name(page: u32) -> String {
    if page == 1 {
        "index.html".to_string()
    } else {
        format!("index-{page}.html")
    }
}

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

/// Like text_to_html() plus turning detected URLs into links.
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
    use std::collections::BTreeMap;
    use std::num::NonZero;
    use std::time::Duration;

    use async_zip::base::read::mem::ZipFileReader;
    use quick_xml::events::Event;

    use super::*;
    use crate::config::Config;
    use crate::message::MessageState;
    use crate::pinned_messages::set_pinned_state;
    use crate::reaction::send_reaction;
    use crate::test_utils::{
        AVATAR_64x64_BYTES, TestContext, TestContextManager, TimeShiftFalsePositiveNote,
        create_test_image,
    };
    use crate::tools::SystemTime;

    #[test]
    fn test_zip_datetime_with_unusual_timestamps() {
        // the ZIP date builder panics for years that cannot be stored.
        for timestamp in [i64::MIN, -1, 0, 4_500_000_000, i64::MAX] {
            zip_datetime(timestamp);
        }
    }

    fn assert_well_formed_xml(html: &str) -> Result<()> {
        let mut reader = quick_xml::Reader::from_str(html);
        while reader.read_event()? != Event::Eof {} // this bubbles up any parsing error and let tests fail
        Ok(())
    }

    // exports and reads the archive back, returning html and all file names
    async fn export_and_read_back(
        t: &TestContext,
        chat_id: ChatId,
        include_images: bool,
        include_files: bool,
    ) -> Result<(String, Vec<String>)> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("chat.zip");
        export_chat(t, chat_id, &dest, include_images, include_files).await?;

        let zip = ZipFileReader::new(fs::read(&dest).await?).await?;
        let names: Vec<String> = zip
            .file()
            .entries()
            .iter()
            .map(|e| e.filename().as_str().map(|s| s.to_string()))
            .collect::<Result<_, _>>()?;
        for entry in zip.file().entries() {
            assert_eq!(entry.unix_permissions(), Some(0o644));
        }
        let index = names.iter().position(|n| n == "index.html").unwrap();
        let mut html = Vec::new();
        zip.reader_with_entry(index)
            .await?
            .read_to_end_checked(&mut html)
            .await?;
        let html = String::from_utf8(html)?;
        assert_well_formed_xml(&html)?;
        Ok((html, names))
    }

    // exports and reads the archive back, returning a map of index names and content
    async fn export_and_read_back_pages(
        t: &TestContext,
        chat_id: ChatId,
        max_page_bytes: usize,
    ) -> Result<BTreeMap<String, String>> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("chat.zip");
        export_chat_inner(t, chat_id, &dest, true, true, max_page_bytes).await?;

        let zip = ZipFileReader::new(fs::read(&dest).await?).await?;
        let mut pages = BTreeMap::new();
        for (i, entry) in zip.file().entries().iter().enumerate() {
            let name = entry.filename().as_str()?.to_string();
            if name.starts_with("index") {
                let mut html = Vec::new();
                zip.reader_with_entry(i)
                    .await?
                    .read_to_end_checked(&mut html)
                    .await?;
                let html = String::from_utf8(html)?;
                assert_well_formed_xml(&html)?;
                pages.insert(name, html);
            }
        }
        Ok(pages)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_chat_in_pages() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let chat_id = alice.create_chat(bob).await.id;

        // add a number of messages to be split over several pages
        let mut msg_ids = Vec::new();
        for i in 0..40 {
            let sent = alice
                .send_text(chat_id, &format!("message number {i}"))
                .await;
            msg_ids.push(sent.sender_msg_id);
        }

        // add another message that will be on the last page and quotes a message on the first page
        let first_msg = Message::load_from_db(alice, msg_ids[0]).await?;
        let mut msg = Message::new_text("reply to the first one".to_string());
        msg.set_quote(alice, Some(&first_msg)).await?;
        msg_ids.push(chat::send_msg(alice, chat_id, &mut msg).await?);

        // force everything on one page: no navigation will be present
        let pages = export_and_read_back_pages(alice, chat_id, 1_000_000).await?;
        assert_eq!(pages.len(), 1);
        assert!(!pages["index.html"].contains("class=\"nav\""));

        // force smaller page sizes and a split
        let max_page_bytes = 3000; // The checks below need at least 3 pages, so the limit has to be small enough
        let pages = export_and_read_back_pages(alice, chat_id, max_page_bytes).await?;
        let count = pages.len();
        assert!(
            count >= 3,
            "only {count} pages, messages got smaller, lower max_page_bytes to fix the test"
        );
        let names: Vec<&String> = pages.keys().collect();
        for n in 2..=count {
            assert!(names.contains(&&format!("index-{n}.html")));
        }

        assert!(pages["index.html"].contains(r#"<a href="index-2.html">index-2.html →</a>"#));
        assert!(!pages["index.html"].contains("←"));
        assert!(pages["index-2.html"].contains(r#"<a href="index.html">← index.html</a>"#));
        assert!(pages["index-2.html"].contains(r#"<a href="index-3.html">index-3.html →</a>"#));
        let last = &pages[&format!("index-{count}.html")];
        assert!(!last.contains("→"));
        assert!(last.contains(&format!(
            r#"<a href="{}">← {0}</a>"#,
            page_name(count as u32 - 1)
        )));
        assert!(
            pages["index-2.html"].contains(&format!("<title>{} (2)</title>", "bob@example.net"))
        );

        // test that no message is on multiple pages
        for msg_id in &msg_ids {
            let anchor = format!("id=\"m{}\"", msg_id.to_u32());
            assert_eq!(pages.values().filter(|p| p.contains(&anchor)).count(), 1);
        }

        // a continuation page starts with a day marker, so the date is not lost
        let page2 = &pages["index-2.html"];
        assert!(page2.find("class=\"day\"").unwrap() < page2.find("id=\"m").unwrap());

        // check that the quote on the last page links correctly to the first page
        let link = format!("href=\"index.html#m{}\"", msg_ids[0].to_u32());
        assert!(last.contains(&link));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_chat_content() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let chat_id = alice.create_chat(bob).await.id;

        let mut msg = Message::new(Viewtype::Image);
        msg.set_file_from_bytes(alice, "image.png", &create_test_image(10, 10)?, None)?;
        chat::send_msg(alice, chat_id, &mut msg).await?;

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "doc.txt", b"content", None)?;
        chat::send_msg(alice, chat_id, &mut msg).await?;

        alice.send_text(chat_id, "Some text").await;

        // tool to check the number of written files
        let check = |names: &[String], files: usize| {
            assert_eq!(
                names.iter().filter(|n| n.starts_with("files/")).count(),
                files
            );
        };

        // everything
        let (html, names) = export_and_read_back(alice, chat_id, true, true).await?;
        check(&names, 2);
        assert!(html.contains(r#"<img src="files/"#));
        assert!(html.contains(r#"<a class="file" href="files/"#));
        assert!(!html.contains(r#"<div class="file""#));

        // text and images
        let (html, names) = export_and_read_back(alice, chat_id, true, false).await?;
        check(&names, 1);
        assert!(html.contains(r#"<img src="files/"#));
        assert!(!html.contains(r#"<a class="file" href="files/"#));
        assert!(html.contains(r#"<div class="file">doc.txt</div>"#));

        // text only: the attachments are still mentioned
        let (html, names) = export_and_read_back(alice, chat_id, false, false).await?;
        check(&names, 0);
        assert!(!html.contains("files/"));
        assert!(html.contains(r#"<div class="file">image_"#));
        assert!(html.contains(r#"<div class="file">doc.txt</div>"#));
        assert!(html.contains("Some text"));

        // other files without images
        let (html, names) = export_and_read_back(alice, chat_id, false, true).await?;
        check(&names, 1);
        assert!(html.contains(r#"<a class="file" href="files/"#));
        assert!(html.contains(r#"<div class="file">image_"#));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        let alice_chat_id = alice.create_chat(bob).await.id;
        let bob_chat_id = bob.create_chat(alice).await.id;

        // create a little chat between Alice and Bob, including reactions, quotes, images and a "pinned" info message
        let sent = alice
            .send_text(alice_chat_id, "<b>Hi</b> & \"bye\"\nsecond line")
            .await;
        let bob_msg = bob.recv_msg(&sent).await;

        send_reaction(bob, bob_msg.id, "👍").await?;
        let reaction = bob.pop_sent_msg().await;
        alice.recv_msg_hidden(&reaction).await;

        send_reaction(alice, sent.sender_msg_id, "❤").await?;

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

        // check the export
        let (html, names) = export_and_read_back(alice, alice_chat_id, true, true).await?;
        assert!(!html.contains("<b>Hi</b>"));
        assert!(html.contains("&lt;b&gt;Hi&lt;/b&gt; &amp; &quot;bye&quot;<br />second line"));
        assert!(html.contains(
            r#"See <a href="https://example.org/a?b=1&amp;c=2">https://example.org/a?b=1&amp;c=2</a>. Done"#
        ));
        assert!(html.contains(r#"<div class="msg in" id="m"#));
        assert!(html.contains(r#"<div class="msg out" id="m"#));
        assert!(html.contains(r#"<div class="msg info" id="m"#));
        assert!(html.contains("An &lt;info&gt;"));
        assert!(html.contains(&format!(
            r##"<a class="msg info" id="m{}" href="#m{}">"##,
            pin_info_id.to_u32(),
            hi_alice.get_id().to_u32()
        )));
        // The quote is a link to the quoted message, with its author on top.
        assert!(html.contains(&format!(
            r##"<a class="quote" href="#m{}" style="border-left-color: #"##,
            hi_alice.get_id().to_u32()
        )));
        assert!(html.contains(r#"<div class="sender" style="color: #"#)); // for the quote
        assert!(html.contains("</div>Hi Alice</a>"));
        assert!(html.contains(r#"<div class="reactions">"#));
        assert!(html.contains("<span>👍 1</span>"));
        assert!(html.contains(r#"<span class="self">❤ 1</span>"#));
        assert!(html.contains(r#"<a class="file" href="files/"#));
        assert!(html.contains("doc.txt</a>"));
        assert!(html.contains(r#"<img src="files/"#));
        assert!(names.contains(&"style.css".to_string()));

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

        let chat_id = chat::create_group(alice, "Group <1>").await?;
        let bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
        chat::add_contact_to_chat(alice, chat_id, bob_contact_id).await?;

        let sent = alice.send_text(chat_id, "Hi from Alice").await;
        let msg = bob.recv_msg(&sent).await;
        assert_eq!(msg.get_state(), MessageState::InFresh);

        let (html, names) = export_and_read_back(bob, msg.get_chat_id(), true, true).await?;
        assert!(html.contains(r#"<div class="header">"#));
        assert!(html.contains("<h1>Group &lt;1&gt;</h1>"));
        assert!(!html.contains(r#"class="description""#));
        assert!(html.contains(r#"<div class="sender" style="color: #"#));
        assert!(html.contains(r#"<div class="avatar" style="background: #"#)); // avatars without images use color+letter
        assert_eq!(names.len(), 2);

        chat::set_chat_description(alice, chat_id, "About <us>").await?;
        let (html, _) = export_and_read_back(alice, chat_id, true, true).await?;
        assert!(html.contains(r#"<div class="description">About &lt;us&gt;</div>"#));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_chat_avatars() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        let dir = tempfile::tempdir()?;
        let avatar = dir.path().join("avatar.png");
        fs::write(&avatar, AVATAR_64x64_BYTES).await?;
        alice
            .set_config(Config::Selfavatar, avatar.to_str())
            .await?;
        let chat_id = chat::create_group(alice, "Group").await?;
        let bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
        chat::add_contact_to_chat(alice, chat_id, bob_contact_id).await?;
        let sent = alice.send_text(chat_id, "Hi from Alice").await;
        let msg = bob.recv_msg(&sent).await;

        // the avatar of Alice is shown on Bob's side, also if the export does not include message's images
        for (include_images, include_files) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let (html, _) =
                export_and_read_back(bob, msg.get_chat_id(), include_images, include_files).await?;
            assert!(html.contains(r#"<img class="avatar" src="files/"#));
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_export_skips_ephemeral_messages() -> Result<()> {
        let _n = TimeShiftFalsePositiveNote;
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let chat_id = alice.create_chat(bob).await.id;

        let kept = alice.send_text(chat_id, "kept message").await;

        let duration = NonZero::new(3600).unwrap();
        chat_id
            .set_ephemeral_timer(alice, EphemeralTimer::Enabled { duration })
            .await?;

        // the ephemeral message is on a day of its own
        SystemTime::shift(Duration::from_secs(2 * 24 * 60 * 60));
        let ephemeral = alice.send_text(chat_id, "ephemeral message").await;

        let (html, _) = export_and_read_back(alice, chat_id, true, true).await?;
        assert!(html.contains("kept message"));
        assert!(html.contains(&format!("id=\"m{}\"", kept.sender_msg_id.to_u32())));
        assert!(!html.contains("ephemeral message"));
        assert!(!html.contains(&format!("id=\"m{}\"", ephemeral.sender_msg_id.to_u32())));

        // a day with ephemeral messages only gets no day marker
        assert_eq!(html.matches("class=\"day\"").count(), 1);
        Ok(())
    }
}
