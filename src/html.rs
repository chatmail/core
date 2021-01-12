///! # Get message as HTML.
///!
///! Use `Message.has_html()` to check if the UI shall render a
///! corresponding button and `MsgId.get_html()` to get the full message.
///!
///! Even when the original mime-message is not HTML,
///! `MsgId.get_html()` will return HTML -
///! this allows nice quoting, handling linebreaks properly etc.
use futures::future::FutureExt;
use std::future::Future;
use std::pin::Pin;

use lettre_email::mime::{self, Mime};

use crate::context::Context;
use crate::error::Result;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::message::{Message, MsgId};
use crate::mimeparser::parse_message_id;
use crate::plaintext::PlainText;
use mailparse::ParsedContentType;

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
async fn get_mime_multipart_type(ctype: &ParsedContentType) -> MimeMultipartType {
    let mimetype = ctype.mimetype.to_lowercase();
    if mimetype.starts_with("multipart") && ctype.params.get("boundary").is_some() {
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
}

impl HtmlMsgParser {
    /// Function takes a raw mime-message string,
    /// searches for the main-text part
    /// and returns that as parser.html
    pub async fn from_bytes(context: &Context, rawmime: &[u8]) -> Result<Self> {
        let mut parser = HtmlMsgParser {
            html: "".to_string(),
            plain: None,
        };

        let parsedmail = mailparse::parse_mail(rawmime)?;

        parser.collect_texts_recursive(context, &parsedmail).await?;

        if parser.html.is_empty() {
            if let Some(plain) = &parser.plain {
                parser.html = plain.to_html().await;
            }
        } else {
            parser.cid_to_data_recursive(context, &parsedmail).await?;
        }

        Ok(parser)
    }

    /// Function iterates over all mime-parts
    /// and searches for text/plain and text/html parts and saves the
    /// last one found
    /// in the corresponding structure fields.
    /// Usually, there is at most one plain-text and one HTML-text part.
    fn collect_texts_recursive<'a>(
        &'a mut self,
        context: &'a Context,
        mail: &'a mailparse::ParsedMail<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a + Send>> {
        // Boxed future to deal with recursion
        async move {
            match get_mime_multipart_type(&mail.ctype).await {
                MimeMultipartType::Multiple => {
                    for cur_data in mail.subparts.iter() {
                        self.collect_texts_recursive(context, cur_data).await?
                    }
                    Ok(())
                }
                MimeMultipartType::Message => {
                    let raw = mail.get_body_raw()?;
                    if raw.is_empty() {
                        return Ok(());
                    }
                    let mail = mailparse::parse_mail(&raw).unwrap();
                    self.collect_texts_recursive(context, &mail).await
                }
                MimeMultipartType::Single => {
                    let mimetype = mail.ctype.mimetype.parse::<Mime>()?;
                    if mimetype == mime::TEXT_HTML {
                        if let Ok(decoded_data) = mail.get_body() {
                            self.html = decoded_data;
                            return Ok(());
                        }
                    } else if mimetype == mime::TEXT_PLAIN {
                        if let Ok(decoded_data) = mail.get_body() {
                            self.plain = Some(PlainText {
                                text: decoded_data,
                                flowed: if let Some(format) = mail.ctype.params.get("format") {
                                    format.as_str().to_ascii_lowercase() == "flowed"
                                } else {
                                    false
                                },
                                delsp: if let Some(delsp) = mail.ctype.params.get("delsp") {
                                    delsp.as_str().to_ascii_lowercase() == "yes"
                                } else {
                                    false
                                },
                            });
                            return Ok(());
                        }
                    }
                    Ok(())
                }
            }
        }
        .boxed()
    }

    /// Replace cid:-protocol by the data:-protocol where appropriate.
    /// This allows the final html-file to be self-contained.
    fn cid_to_data_recursive<'a>(
        &'a mut self,
        context: &'a Context,
        mail: &'a mailparse::ParsedMail<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a + Send>> {
        // Boxed future to deal with recursion
        async move {
            match get_mime_multipart_type(&mail.ctype).await {
                MimeMultipartType::Multiple => {
                    for cur_data in mail.subparts.iter() {
                        self.cid_to_data_recursive(context, cur_data).await?;
                    }
                    Ok(())
                }
                MimeMultipartType::Message => {
                    let raw = mail.get_body_raw()?;
                    if raw.is_empty() {
                        return Ok(());
                    }
                    let mail = mailparse::parse_mail(&raw).unwrap();
                    self.cid_to_data_recursive(context, &mail).await
                }
                MimeMultipartType::Single => {
                    let mimetype = mail.ctype.mimetype.parse::<Mime>()?;
                    if mimetype.type_() == mime::IMAGE {
                        if let Some(cid) = mail.headers.get_header_value(HeaderDef::ContentId) {
                            if let Ok(cid) = parse_message_id(&cid) {
                                if let Ok(replacement) = mimepart_to_data_url(&mail).await {
                                    let re_string = format!(
                                        "(<img[^>]*src[^>]*=[^>]*)(cid:{})([^>]*>)",
                                        regex::escape(&cid)
                                    );
                                    match regex::Regex::new(&re_string) {
                                        Ok(re) => {
                                            self.html = re
                                                .replace_all(
                                                    &*self.html,
                                                    format!("${{1}}{}${{3}}", replacement).as_str(),
                                                )
                                                .as_ref()
                                                .to_string()
                                        }
                                        Err(e) => warn!(
                                            context,
                                            "Cannot create regex for cid: {} throws {}",
                                            re_string,
                                            e
                                        ),
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
        .boxed()
    }
}

/// Convert a mime part to a data: url as defined in [RFC 2397](https://tools.ietf.org/html/rfc2397).
async fn mimepart_to_data_url(mail: &mailparse::ParsedMail<'_>) -> Result<String> {
    let data = mail.get_body_raw()?;
    let data = base64::encode(&data);
    Ok(format!("data:{};base64,{}", mail.ctype.mimetype, data))
}

impl MsgId {
    /// Get HTML from a message-id.
    /// This requires `mime_headers` field to be set for the message;
    /// this is the case at least when `Message.has_html()` returns true
    /// (we do not save raw mime unconditionally in the database to save space).
    /// The corresponding ffi-function is `dc_get_msg_html()`.
    pub async fn get_html(self, context: &Context) -> String {
        let rawmime: Option<String> = context
            .sql
            .query_get_value(
                context,
                "SELECT mime_headers FROM msgs WHERE id=?;",
                paramsv![self],
            )
            .await;

        if let Some(rawmime) = rawmime {
            match HtmlMsgParser::from_bytes(context, rawmime.as_bytes()).await {
                Err(err) => format!("parser error: {}", err),
                Ok(parser) => parser.html,
            }
        } else {
            format!("parser error: no mime for {}", self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContext;

    #[async_std::test]
    async fn test_htmlparse_plain_unspecified() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_plain_unspecified.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html,
            r##"<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /></head><body>
This message does not have Content-Type nor Subject.<br/>
<br/>
</body></html>
"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_plain_iso88591() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_plain_iso88591.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html,
            r##"<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /></head><body>
message with a non-UTF-8 encoding: äöüßÄÖÜ<br/>
<br/>
</body></html>
"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_plain_flowed() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_plain_flowed.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert!(parser.plain.unwrap().flowed);
        assert_eq!(
            parser.html,
            r##"<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /></head><body>
This line ends with a space and will be merged with the next one due to format=flowed.<br/>
<br/>
This line does not end with a space<br/>
and will be wrapped as usual.<br/>
<br/>
</body></html>
"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_alt_plain() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_alt_plain.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html,
            r##"<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /></head><body>
mime-modified should not be set set as there is no html and no special stuff;<br/>
although not being a delta-message.<br/>
test some special html-characters as &lt; &gt; and &amp; but also &quot; and &#x27; :)<br/>
<br/>
<br/>
</body></html>
"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_html() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_html.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();

        // on windows, `\r\n` linends are returned from mimeparser,
        // however, rust multiline-strings use just `\n`;
        // therefore, we just remove `\r` before comparison.
        assert_eq!(
            parser.html.replace("\r", ""),
            r##"
<html>
  <p>mime-modified <b>set</b>; simplify is always regarded as lossy.</p>
</html>"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_alt_html() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_alt_html.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html.replace("\r", ""), // see comment in test_htmlparse_html()
            r##"<html>
  <p>mime-modified <b>set</b>; simplify is always regarded as lossy.</p>
</html>

"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_alt_plain_html() {
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/text_alt_plain_html.eml");
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert_eq!(
            parser.html.replace("\r", ""), // see comment in test_htmlparse_html()
            r##"<html>
  <p>
    this is <b>html</b>
  </p>
</html>

"##
        );
    }

    #[async_std::test]
    async fn test_htmlparse_apple_cid_jpg() {
        // load raw mime html-data with related image-part (cid:)
        // and make sure, Content-Id has angle-brackets that are removed correctly.
        let t = TestContext::new().await;
        let raw = include_bytes!("../test-data/message/apple_cid_jpg.eml");
        let test = String::from_utf8_lossy(raw);
        assert!(test
            .find("Content-Id: <8AE052EF-BC90-486F-BB78-58D3590308EC@fritz.box>")
            .is_some());
        assert!(test
            .find("cid:8AE052EF-BC90-486F-BB78-58D3590308EC@fritz.box")
            .is_some());
        assert!(test.find("data:").is_none());

        // parsing converts cid: to data:
        let parser = HtmlMsgParser::from_bytes(&t.ctx, raw).await.unwrap();
        assert!(parser.html.find("<html>").is_some());
        assert!(parser.html.find("Content-Id:").is_none());
        assert!(parser
            .html
            .find("data:image/jpeg;base64,/9j/4AAQ")
            .is_some());
        assert!(parser.html.find("cid:").is_none());
    }
}
