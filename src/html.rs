//! # Get message as HTML.
//!
//! Use `Message.has_html()` to check if the UI shall render a
//! corresponding button and `MsgId.get_html()` to get the full message.
//!
//! Even when the original mime-message is not HTML,
//! `MsgId.get_html()` will return HTML -
//! this allows nice quoting, handling linebreaks properly etc.

use std::mem;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use mailparse::ParsedContentType;
use mime::Mime;

use crate::context::Context;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::log::warn;
use crate::message::{self, Message, MsgId};
use crate::mimeparser::parse_message_id;
use crate::param::Param::SendHtml;
use crate::plaintext::PlainText;

impl Message {
    /// Check if the message can be retrieved as HTML.
    /// Typically, this is the case, when the mime structure of a Message is modified,
    /// meaning that some text is cut or the original message
    /// is in HTML and `simplify()` may hide some maybe important information.
    /// The corresponding ffi-function is `dc_msg_has_html()`.
    /// To get the HTML-code of the message, use `MsgId.get_html()`.
    pub fn has_html(&self) -> bool {
        self.mime_modified
    }

    /// Set HTML-part part of a message that is about to be sent.
    /// The HTML-part is written to the database before sending and
    /// used as the `text/html` part in the MIME-structure.
    ///
    /// Received HTML parts are handled differently,
    /// they are saved together with the whole MIME-structure
    /// in `mime_headers` and the HTML-part is extracted using `MsgId::get_html()`.
    /// (To underline this asynchronicity, we are using the wording "SendHtml")
    pub fn set_html(&mut self, html: Option<String>) {
        if let Some(html) = html {
            self.param.set(SendHtml, html);
            self.mime_modified = true;
        } else {
            self.param.remove(SendHtml);
            self.mime_modified = false;
        }
    }
}

/// Type defining a rough mime-type.
/// This is mainly useful on iterating
/// to decide whether a mime-part has subtypes.
enum MimeMultipartType {
    Multiple,
    Single,
    Message,
}

/// Function takes a content type from a ParsedMail structure
/// and checks and returns the rough mime-type.
fn get_mime_multipart_type(ctype: &ParsedContentType) -> MimeMultipartType {
    let mimetype = ctype.mimetype.to_lowercase();
    if mimetype.starts_with("multipart") && ctype.params.contains_key("boundary") {
        MimeMultipartType::Multiple
    } else if mimetype == "message/rfc822" {
        MimeMultipartType::Message
    } else {
        MimeMultipartType::Single
    }
}

/// HtmlMsgParser converts a mime-message to HTML.
#[derive(Debug)]
struct HtmlMsgParser {
    pub html: String,
    pub plain: Option<PlainText>,
    pub(crate) msg_html: String,
}

impl HtmlMsgParser {
    /// Function takes a raw mime-message string,
    /// searches for the main-text part
    /// and returns that as parser.html
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn from_bytes<'a>(
        context: &Context,
        rawmime: &'a [u8],
    ) -> Result<(Self, mailparse::ParsedMail<'a>)> {
        let mut parser = HtmlMsgParser {
            html: "".to_string(),
            plain: None,
            msg_html: "".to_string(),
        };

        let parsedmail = mailparse::parse_mail(rawmime).context("Failed to parse mail")?;

        parser.collect_texts_recursive(context, &parsedmail).await?;

        if parser.html.is_empty() {
            if let Some(plain) = &parser.plain {
                parser.html = plain.to_html();
            }
        } else {
            parser.cid_to_data_recursive(context, &parsedmail).await?;
        }
        parser.html += &mem::take(&mut parser.msg_html);
        Ok((parser, parsedmail))
    }

    /// Function iterates over all mime-parts
    /// and searches for text/plain and text/html parts and saves the
    /// first one found.
    /// in the corresponding structure fields.
    ///
    /// Usually, there is at most one plain-text and one HTML-text part,
    /// multiple plain-text parts might be used for mailinglist-footers,
    /// therefore we use the first one.
    #[expect(clippy::arithmetic_side_effects)]
    async fn collect_texts_recursive<'a>(
        &'a mut self,
        context: &'a Context,
        mail: &'a mailparse::ParsedMail<'a>,
    ) -> Result<()> {
        match get_mime_multipart_type(&mail.ctype) {
            MimeMultipartType::Multiple => {
                for cur_data in &mail.subparts {
                    Box::pin(self.collect_texts_recursive(context, cur_data)).await?
                }
                Ok(())
            }
            MimeMultipartType::Message => {
                let raw = mail.get_body_raw()?;
                if raw.is_empty() {
                    return Ok(());
                }
                let (parser, mail) = Box::pin(HtmlMsgParser::from_bytes(context, &raw)).await?;
                if !parser.html.is_empty() {
                    let mut text = "\r\n\r\n".to_string();
                    for h in mail.headers {
                        let key = h.get_key();
                        if matches!(
                            key.to_lowercase().as_str(),
                            "date"
                                | "from"
                                | "sender"
                                | "reply-to"
                                | "to"
                                | "cc"
                                | "bcc"
                                | "subject"
                        ) {
                            text += &format!("{key}: {}\r\n", h.get_value());
                        }
                    }
                    text += "\r\n";
                    self.msg_html += &PlainText {
                        text,
                        flowed: false,
                        delsp: false,
                    }
                    .to_html();
                    self.msg_html += &parser.html;
                }
                Ok(())
            }
            MimeMultipartType::Single => {
                let mimetype = mail.ctype.mimetype.parse::<Mime>()?;
                if mimetype == mime::TEXT_HTML {
                    if self.html.is_empty()
                        && let Ok(decoded_data) = mail.get_body()
                    {
                        self.html = decoded_data;
                    }
                } else if mimetype == mime::TEXT_PLAIN
                    && self.plain.is_none()
                    && let Ok(decoded_data) = mail.get_body()
                {
                    self.plain = Some(PlainText {
                        text: decoded_data,
                        flowed: if let Some(format) = mail.ctype.params.get("format") {
                            format.as_str().eq_ignore_ascii_case("flowed")
                        } else {
                            false
                        },
                        delsp: if let Some(delsp) = mail.ctype.params.get("delsp") {
                            delsp.as_str().eq_ignore_ascii_case("yes")
                        } else {
                            false
                        },
                    });
                }
                Ok(())
            }
        }
    }

    /// Replace cid:-protocol by the data:-protocol where appropriate.
    /// This allows the final html-file to be self-contained.
    async fn cid_to_data_recursive<'a>(
        &'a mut self,
        context: &'a Context,
        mail: &'a mailparse::ParsedMail<'a>,
    ) -> Result<()> {
        match get_mime_multipart_type(&mail.ctype) {
            MimeMultipartType::Multiple => {
                for cur_data in &mail.subparts {
                    Box::pin(self.cid_to_data_recursive(context, cur_data)).await?;
                }
                Ok(())
            }
            MimeMultipartType::Message => Ok(()),
            MimeMultipartType::Single => {
                let mimetype = mail.ctype.mimetype.parse::<Mime>()?;
                if mimetype.type_() == mime::IMAGE
                    && let Some(cid) = mail.headers.get_header_value(HeaderDef::ContentId)
                    && let Ok(cid) = parse_message_id(&cid)
                    && let Ok(replacement) = mimepart_to_data_url(mail)
                {
                    let re_string = format!(
                        "(<img[^>]*src[^>]*=[^>]*)(cid:{})([^>]*>)",
                        regex::escape(&cid)
                    );
                    match regex::Regex::new(&re_string) {
                        Ok(re) => {
                            self.html = re
                                .replace_all(
                                    &self.html,
                                    format!("${{1}}{replacement}${{3}}").as_str(),
                                )
                                .as_ref()
                                .to_string()
                        }
                        Err(e) => warn!(
                            context,
                            "Cannot create regex for cid: {} throws {}", re_string, e
                        ),
                    }
                }
                Ok(())
            }
        }
    }
}

/// Convert a mime part to a data: url as defined in [RFC 2397](https://tools.ietf.org/html/rfc2397).
fn mimepart_to_data_url(mail: &mailparse::ParsedMail<'_>) -> Result<String> {
    let data = mail.get_body_raw()?;
    let data = base64::engine::general_purpose::STANDARD.encode(data);
    Ok(format!("data:{};base64,{}", mail.ctype.mimetype, data))
}

impl MsgId {
    /// Get HTML by database message id.
    /// Returns `Some` at least if `Message.has_html()` is true.
    /// NB: we do not save raw mime unconditionally in the database to save space.
    /// The corresponding ffi-function is `dc_get_msg_html()`.
    pub async fn get_html(self, context: &Context) -> Result<Option<String>> {
        // If there are many concurrent db readers, going to the queue earlier makes sense.
        let (param, rawmime) = tokio::join!(
            self.get_param(context),
            message::get_mime_headers(context, self)
        );
        if let Some(html) = param?.get(SendHtml) {
            return Ok(Some(html.to_string()));
        }

        let rawmime = rawmime?;
        if !rawmime.is_empty() {
            match HtmlMsgParser::from_bytes(context, &rawmime).await {
                Err(err) => {
                    warn!(context, "get_html: parser error: {:#}", err);
                    Ok(None)
                }
                Ok((parser, _)) => Ok(Some(parser.html)),
            }
        } else {
            warn!(context, "get_html: no mime for {}", self);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{self, Chat, forward_msgs, save_msgs};
    use crate::config::Config;
    use crate::constants;
    use crate::contact::ContactId;
    use crate::message::{MessengerMessage, Viewtype};
    use crate::receive_imf::receive_imf;
    use crate::test_utils::{TestContext, TestContextManager};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_plain_unspecified() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_plain_unspecified.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
This message does not have Content-Type nor Subject.<br/>
</body></html>
"#
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_plain_iso88591() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_plain_iso88591.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
message with a non-UTF-8 encoding: äöüßÄÖÜ<br/>
</body></html>
"#
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_plain_flowed() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_plain_flowed.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert!(parser.plain.unwrap().flowed);
        assert_eq!(
            parser.html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
This line ends with a space and will be merged with the next one due to format=flowed.<br/>
<br/>
This line does not end with a space<br/>
and will be wrapped as usual.<br/>
</body></html>
"#
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_alt_plain() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_alt_plain.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
mime-modified should not be set set as there is no html and no special stuff;<br/>
although not being a delta-message.<br/>
test some special html-characters as &lt; &gt; and &amp; but also &quot; and &#x27; :)<br/>
</body></html>
"#
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_html() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_html.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();

        // on windows, `\r\n` linends are returned from mimeparser,
        // however, rust multiline-strings use just `\n`;
        // therefore, we just remove `\r` before comparison.
        assert_eq!(
            parser.html.replace('\r', ""),
            r##"
<html>
  <p>mime-modified <b>set</b>; simplify is always regarded as lossy.</p>
</html>"##
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_alt_html() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_alt_html.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html.replace('\r', ""), // see comment in test_htmlparse_html()
            r##"<html>
  <p>mime-modified <b>set</b>; simplify is always regarded as lossy.</p>
</html>
"##
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_alt_plain_html() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_alt_plain_html.eml");
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html.replace('\r', ""), // see comment in test_htmlparse_html()
            r##"<html>
  <p>
    this is <b>html</b>
  </p>
</html>
"##
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_htmlparse_apple_cid_jpg() {
        // load raw mime html-data with related image-part (cid:)
        // and make sure, Content-Id has angle-brackets that are removed correctly.
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/apple_cid_jpg.eml");
        let test = String::from_utf8_lossy(raw);
        assert!(test.contains("Content-Id: <8AE052EF-BC90-486F-BB78-58D3590308EC@fritz.box>"));
        assert!(test.contains("cid:8AE052EF-BC90-486F-BB78-58D3590308EC@fritz.box"));
        assert!(test.find("data:").is_none());

        // parsing converts cid: to data:
        let (parser, _) = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert!(parser.html.contains("<html>"));
        assert!(!parser.html.contains("Content-Id:"));
        assert!(parser.html.contains("data:image/jpeg;base64,/9j/4AAQ"));
        assert!(!parser.html.contains("cid:"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_html_invalid_msgid() {
        let t = TestContext::new().await;
        let msg_id = MsgId::new(100);
        assert!(msg_id.get_html(&t).await.is_err())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_html_forwarding() -> Result<()> {
        // alice receives a non-delta html-message
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let chat = alice
            .create_chat_with_contact("", "sender@testrun.org")
            .await;
        let raw = include_bytes!("../test-data/message/text_alt_plain_html.eml");
        receive_imf(alice, raw, false).await.unwrap();
        let msg = alice.get_last_msg_in(chat.get_id()).await;
        assert_ne!(msg.get_from_id(), ContactId::SELF);
        assert_eq!(msg.is_dc_message, MessengerMessage::No);
        assert!(!msg.is_forwarded());
        assert!(msg.get_text().contains("this is plain"));
        assert!(msg.has_html());
        let html = msg.get_id().get_html(alice).await.unwrap().unwrap();
        assert!(html.contains("this is <b>html</b>"));

        // alice: create chat with bob and forward received html-message there
        let chat_alice = alice.create_chat_with_contact("", "bob@example.net").await;
        forward_msgs(alice, &[msg.get_id()], chat_alice.get_id())
            .await
            .unwrap();
        async fn check_sender(ctx: &TestContext, chat: &Chat) {
            let msg = ctx.get_last_msg_in(chat.get_id()).await;
            assert_eq!(msg.get_from_id(), ContactId::SELF);
            assert_eq!(msg.is_dc_message, MessengerMessage::Yes);
            assert!(msg.is_forwarded());
            assert!(msg.get_text().contains("this is plain"));
            assert!(msg.has_html());
            let html = msg.get_id().get_html(ctx).await.unwrap().unwrap();
            assert!(html.contains("this is <b>html</b>"));
        }
        check_sender(alice, &chat_alice).await;

        // bob: check that bob also got the html-part of the forwarded message
        let bob = &tcm.bob().await;
        let chat_bob = bob.create_chat_with_contact("", "alice@example.org").await;
        async fn check_receiver(ctx: &TestContext, chat: &Chat, sender: &TestContext) {
            let msg = ctx.recv_msg(&sender.pop_sent_msg().await).await;
            assert_eq!(chat.id, msg.chat_id);
            assert_ne!(msg.get_from_id(), ContactId::SELF);
            assert_eq!(msg.is_dc_message, MessengerMessage::Yes);
            assert!(msg.is_forwarded());
            assert!(msg.get_text().contains("this is plain"));
            assert!(msg.has_html());
            let html = msg.get_id().get_html(ctx).await.unwrap().unwrap();
            assert!(html.contains("this is <b>html</b>"));
        }
        check_receiver(bob, &chat_bob, alice).await;

        // Let's say that the alice and bob profiles are on the same device,
        // so alice can forward the message to herself via bob profile!
        chat::forward_msgs_2ctx(alice, &[msg.get_id()], bob, chat_bob.get_id()).await?;
        check_sender(bob, &chat_bob).await;
        check_receiver(alice, &chat_alice, bob).await;

        // Check cross-profile forwarding of long outgoing messages.
        let line = "this text with 42 chars is just repeated.\n";
        let long_txt = line.repeat(constants::DC_DESIRED_TEXT_LEN / line.len() + 2);
        let mut msg = Message::new_text(long_txt);
        alice.send_msg(chat_alice.id, &mut msg).await;
        let msg = alice.get_last_msg_in(chat_alice.id).await;
        assert!(msg.has_html());
        let html = msg.id.get_html(alice).await?.unwrap();
        chat::forward_msgs_2ctx(alice, &[msg.get_id()], bob, chat_bob.get_id()).await?;
        let msg = bob.get_last_msg_in(chat_bob.id).await;
        assert!(msg.has_html());
        assert_eq!(msg.id.get_html(bob).await?.unwrap(), html);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_html_save_msg() -> Result<()> {
        // Alice receives a non-delta html-message
        let alice = TestContext::new_alice().await;
        let chat = alice
            .create_chat_with_contact("", "sender@testrun.org")
            .await;
        let raw = include_bytes!("../test-data/message/text_alt_plain_html.eml");
        receive_imf(&alice, raw, false).await?;
        let msg = alice.get_last_msg_in(chat.get_id()).await;

        // Alice saves the message
        let self_chat = alice.get_self_chat().await;
        save_msgs(&alice, &[msg.id]).await?;
        let saved_msg = alice.get_last_msg_in(self_chat.get_id()).await;
        assert_ne!(saved_msg.id, msg.id);
        assert_eq!(
            saved_msg.get_original_msg_id(&alice).await?.unwrap(),
            msg.id
        );
        assert!(!saved_msg.is_forwarded()); // UI should not flag "saved messages" as "forwarded"
        assert_ne!(saved_msg.get_from_id(), ContactId::SELF);
        assert_eq!(saved_msg.get_from_id(), msg.get_from_id());
        assert_eq!(saved_msg.is_dc_message, MessengerMessage::No);
        assert!(saved_msg.get_text().contains("this is plain"));
        assert!(saved_msg.has_html());
        let html = saved_msg.get_id().get_html(&alice).await?.unwrap();
        assert!(html.contains("this is <b>html</b>"));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_html_forwarding_encrypted() {
        let mut tcm = TestContextManager::new();
        // Alice receives a non-delta html-message
        // (`ShowEmails=AcceptedContacts` lets Alice actually receive non-delta messages for known
        // contacts, the contact is marked as known by creating a chat using `chat_with_contact()`)
        let alice = &tcm.alice().await;
        alice
            .set_config(Config::ShowEmails, Some("1"))
            .await
            .unwrap();
        let chat = alice
            .create_chat_with_contact("", "sender@testrun.org")
            .await;
        let raw = include_bytes!("../test-data/message/text_alt_plain_html.eml");
        receive_imf(alice, raw, false).await.unwrap();
        let msg = alice.get_last_msg_in(chat.get_id()).await;

        // forward the message to saved-messages,
        // this will encrypt the message as new_alice() has set up keys
        let chat = alice.get_self_chat().await;
        forward_msgs(alice, &[msg.get_id()], chat.get_id())
            .await
            .unwrap();
        let msg = alice.pop_sent_msg().await;

        // receive the message on another device
        let alice = &tcm.alice().await;
        alice
            .set_config(Config::ShowEmails, Some("0"))
            .await
            .unwrap();
        let msg = alice.recv_msg(&msg).await;
        assert_eq!(msg.chat_id, alice.get_self_chat().await.id);
        assert_eq!(msg.get_from_id(), ContactId::SELF);
        assert_eq!(msg.is_dc_message, MessengerMessage::Yes);
        assert!(msg.get_showpadlock());
        assert!(msg.is_forwarded());
        assert!(msg.get_text().contains("this is plain"));
        assert!(msg.has_html());
        let html = msg.get_id().get_html(alice).await.unwrap().unwrap();
        assert!(html.contains("this is <b>html</b>"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_set_html() {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        // alice sends a message with html-part to bob
        let chat_id = alice.create_chat(bob).await.id;
        let mut msg = Message::new_text("plain text".to_string());
        msg.set_html(Some("<b>html</b> text".to_string()));
        assert!(msg.mime_modified);
        chat::send_msg(alice, chat_id, &mut msg).await.unwrap();

        // check the message is written correctly to alice's db
        let msg = alice.get_last_msg_in(chat_id).await;
        assert_eq!(msg.get_text(), "plain text");
        assert!(!msg.is_forwarded());
        assert!(msg.mime_modified);
        let html = msg.get_id().get_html(alice).await.unwrap().unwrap();
        assert!(html.contains("<b>html</b> text"));

        // let bob receive the message
        let chat_id = bob.create_chat(alice).await.id;
        let msg = bob.recv_msg(&alice.pop_sent_msg().await).await;
        assert_eq!(msg.chat_id, chat_id);
        assert_eq!(msg.get_text(), "plain text");
        assert!(!msg.is_forwarded());
        assert!(msg.mime_modified);
        let html = msg.get_id().get_html(bob).await.unwrap().unwrap();
        assert!(html.contains("<b>html</b> text"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cp1252_html() -> Result<()> {
        let t = TestContext::new_alice().await;
        receive_imf(
            &t,
            include_bytes!("../test-data/message/cp1252-html.eml"),
            false,
        )
        .await?;
        let msg = t.get_last_msg().await;
        assert_eq!(msg.viewtype, Viewtype::Text);
        assert!(msg.text.contains("foo bar ä ö ü ß"));
        assert!(msg.has_html());
        let html = msg.get_id().get_html(&t).await?.unwrap();
        println!("{html}");
        assert!(html.contains("foo bar ä ö ü ß"));
        Ok(())
    }
}
