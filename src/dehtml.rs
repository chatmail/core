//! De-HTML.
//!
//! A module to remove HTML tags from the email text

use std::io::BufRead;
use std::sync::LazyLock;

use quick_xml::{
    Reader,
    errors::Error as QuickXmlError,
    events::{BytesEnd, BytesStart, BytesText},
};

use crate::simplify::{SimplifiedText, simplify_quote};

#[derive(Default)]
struct Dehtml {
    strbuilder: String,
    quote: String,
    add_text: AddText,
    last_href: Option<String>,
    /// GMX wraps a quote in `<div name="quote">`. After a `<div name="quote">`, this count is
    /// increased at each `<div>` and decreased at each `</div>`. This way we know when the quote ends.
    /// If this is > `0`, then we are inside a `<div name="quote">`
    divs_since_quote_div: u32,
    /// Everything between `<div name="quote">` and `<div name="quoted-content">` is usually metadata
    /// If this is > `0`, then we are inside a `<div name="quoted-content">`.
    divs_since_quoted_content_div: u32,
    /// `<div class="header-protection-legacy-display">` elements should be omitted, see
    /// <https://www.rfc-editor.org/rfc/rfc9788.html#section-4.5.3.3>.
    divs_since_hp_legacy_display: u32,
    /// All-Inkl just puts the quote into `<blockquote> </blockquote>`. This count is
    /// increased at each `<blockquote>` and decreased at each `</blockquote>`.
    blockquotes_since_blockquote: u32,
}

impl Dehtml {
    /// Returns true if HTML parser is currently inside the quote.
    fn is_quote(&self) -> bool {
        self.divs_since_quoted_content_div > 0 || self.blockquotes_since_blockquote > 0
    }

    /// Returns the buffer where the text should be written.
    ///
    /// If the parser is inside the quote, returns the quote buffer.
    fn get_buf(&mut self) -> &mut String {
        if self.is_quote() {
            &mut self.quote
        } else {
            &mut self.strbuilder
        }
    }

    fn get_add_text(&self) -> AddText {
        // Everything between `<div name="quoted">` and `<div name="quoted_content">` is
        // metadata which we don't want.
        if self.divs_since_quote_div > 0 && self.divs_since_quoted_content_div == 0
            || self.divs_since_hp_legacy_display > 0
        {
            AddText::No
        } else {
            self.add_text
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
enum AddText {
    /// Inside `<script>`, `<style>` and similar tags
    /// which contents should not be displayed.
    No,

    #[default]
    YesRemoveLineEnds,

    /// Inside `<pre>`.
    YesPreserveLineEnds,
}

pub(crate) fn dehtml(buf: &str) -> Option<SimplifiedText> {
    let (s, quote) = dehtml_quick_xml(buf);
    if !s.trim().is_empty() {
        let text = dehtml_cleanup(s);
        let top_quote = if !quote.trim().is_empty() {
            Some(dehtml_cleanup(simplify_quote(&quote).0))
        } else {
            None
        };
        return Some(SimplifiedText {
            text,
            top_quote,
            ..Default::default()
        });
    }
    let s = dehtml_manually(buf);
    if !s.trim().is_empty() {
        let text = dehtml_cleanup(s);
        return Some(SimplifiedText {
            text,
            ..Default::default()
        });
    }
    None
}

fn dehtml_cleanup(mut text: String) -> String {
    text.retain(|c| c != '\r');
    let lines = text.trim().split('\n');
    let mut text = String::new();
    let mut linebreak = false;
    for line in lines {
        if line.chars().all(char::is_whitespace) {
            linebreak = true;
        } else {
            if !text.is_empty() {
                text += "\n";
                if linebreak {
                    text += "\n";
                }
            }
            text += line.trim_end();
            linebreak = false;
        }
    }
    text
}

fn dehtml_quick_xml(buf: &str) -> (String, String) {
    let buf = buf.trim().trim_start_matches("<!doctype html>");

    let mut dehtml = Dehtml {
        strbuilder: String::with_capacity(buf.len()),
        ..Default::default()
    };

    let mut reader = quick_xml::Reader::from_str(buf);
    reader.config_mut().check_end_names = false;

    let mut buf = Vec::new();
    let mut char_buf = String::with_capacity(4);

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                dehtml_starttag_cb(e, &mut dehtml, &reader)
            }
            Ok(quick_xml::events::Event::End(ref e)) => dehtml_endtag_cb(e, &mut dehtml),
            Ok(quick_xml::events::Event::Text(ref e)) => dehtml_text_cb(e, &mut dehtml),
            Ok(quick_xml::events::Event::CData(e)) => {
                str_cb(&String::from_utf8_lossy(&e as &[_]), &mut dehtml)
            }
            Ok(quick_xml::events::Event::Empty(ref e)) => {
                // Handle empty tags as a start tag immediately followed by end tag.
                // For example, `<p/>` is treated as `<p></p>`.
                dehtml_starttag_cb(e, &mut dehtml, &reader);
                dehtml_endtag_cb(
                    &BytesEnd::new(String::from_utf8_lossy(e.name().as_ref())),
                    &mut dehtml,
                );
            }
            Ok(quick_xml::events::Event::GeneralRef(ref e)) => {
                match e.resolve_char_ref() {
                    Err(err) => eprintln!(
                        "resolve_char_ref() error at position {}: {:?}",
                        reader.buffer_position(),
                        err,
                    ),
                    Ok(Some(ch)) => {
                        char_buf.clear();
                        char_buf.push(ch);
                        str_cb(&char_buf, &mut dehtml);
                    }
                    Ok(None) => {
                        let event_str = String::from_utf8_lossy(e);
                        if let Some(s) = quick_xml::escape::resolve_html5_entity(&event_str) {
                            str_cb(s, &mut dehtml);
                        } else {
                            // Nonstandard entity. Add escaped.
                            str_cb(&format!("&{event_str};"), &mut dehtml);
                        }
                    }
                }
            }
            Err(QuickXmlError::IllFormed(_)) => {
                // This is probably not HTML at all and should be left as is.
                str_cb(&String::from_utf8_lossy(&buf), &mut dehtml);
            }
            Err(e) => {
                eprintln!(
                    "Parse html error: Error at position {}: {:?}",
                    reader.buffer_position(),
                    e
                );
            }
            Ok(quick_xml::events::Event::Eof) => break,
            _ => (),
        }
        buf.clear();
    }

    (dehtml.strbuilder, dehtml.quote)
}

fn dehtml_text_cb(event: &BytesText, dehtml: &mut Dehtml) {
    if dehtml.get_add_text() == AddText::YesPreserveLineEnds
        || dehtml.get_add_text() == AddText::YesRemoveLineEnds
    {
        let event = event as &[_];
        let event_str = std::str::from_utf8(event).unwrap_or_default();
        str_cb(event_str, dehtml);
    }
}

fn str_cb(event_str: &str, dehtml: &mut Dehtml) {
    static LINE_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(\r?\n)+").unwrap());

    let add_text = dehtml.get_add_text();
    if add_text == AddText::YesRemoveLineEnds {
        // Replace all line ends with spaces.
        // E.g. `\r\n\r\n` is replaced with one space.
        let event_str = LINE_RE.replace_all(event_str, " ");

        // Add a space if `event_str` starts with a space
        // and there is no whitespace at the end of the buffer yet.
        // Trim the rest of leading whitespace from `event_str`.
        let buf = dehtml.get_buf();
        if !buf.ends_with(' ') && !buf.ends_with('\n') && event_str.starts_with(' ') {
            *buf += " ";
        }

        *buf += event_str.trim_start();
    } else if add_text == AddText::YesPreserveLineEnds {
        *dehtml.get_buf() += LINE_RE.replace_all(event_str, "\n").as_ref();
    }
}

#[expect(clippy::arithmetic_side_effects)]
fn dehtml_endtag_cb(event: &BytesEnd, dehtml: &mut Dehtml) {
    let tag = String::from_utf8_lossy(event.name().as_ref())
        .trim()
        .to_lowercase();

    match tag.as_str() {
        "style" | "script" | "title" | "pre" => {
            *dehtml.get_buf() += "\n\n";
            dehtml.add_text = AddText::YesRemoveLineEnds;
        }
        "div" => {
            pop_tag(&mut dehtml.divs_since_quote_div);
            pop_tag(&mut dehtml.divs_since_quoted_content_div);
            pop_tag(&mut dehtml.divs_since_hp_legacy_display);

            *dehtml.get_buf() += "\n\n";
            dehtml.add_text = AddText::YesRemoveLineEnds;
        }
        "a" => {
            if let Some(ref last_href) = dehtml.last_href.take() {
                let buf = dehtml.get_buf();
                if buf.ends_with('[') {
                    buf.truncate(buf.len() - 1);
                } else {
                    *buf += "](";
                    *buf += last_href;
                    *buf += ")";
                }
            }
        }
        "b" | "strong" => {
            if dehtml.get_add_text() != AddText::No {
                *dehtml.get_buf() += "*";
            }
        }
        "i" | "em" => {
            if dehtml.get_add_text() != AddText::No {
                *dehtml.get_buf() += "_";
            }
        }
        "blockquote" => pop_tag(&mut dehtml.blockquotes_since_blockquote),
        _ => {}
    }
}

#[expect(clippy::arithmetic_side_effects)]
fn dehtml_starttag_cb<B: std::io::BufRead>(
    event: &BytesStart,
    dehtml: &mut Dehtml,
    reader: &quick_xml::Reader<B>,
) {
    let tag = String::from_utf8_lossy(event.name().as_ref())
        .trim()
        .to_lowercase();

    match tag.as_str() {
        "p" | "table" | "td" => {
            if !dehtml.strbuilder.is_empty() {
                *dehtml.get_buf() += "\n\n";
            }
            dehtml.add_text = AddText::YesRemoveLineEnds;
        }
        #[rustfmt::skip]
        "div" => {
            maybe_push_tag(event, reader, "quote", &mut dehtml.divs_since_quote_div);
            maybe_push_tag(event, reader, "quoted-content", &mut dehtml.divs_since_quoted_content_div);
            maybe_push_tag(event, reader, "header-protection-legacy-display",
                &mut dehtml.divs_since_hp_legacy_display);

            *dehtml.get_buf() += "\n\n";
            dehtml.add_text = AddText::YesRemoveLineEnds;
        }
        "br" => {
            *dehtml.get_buf() += "\n";
            dehtml.add_text = AddText::YesRemoveLineEnds;
        }
        "style" | "script" | "title" => {
            dehtml.add_text = AddText::No;
        }
        "pre" => {
            *dehtml.get_buf() += "\n\n";
            dehtml.add_text = AddText::YesPreserveLineEnds;
        }
        "a" => {
            if let Some(href) = event
                .html_attributes()
                .filter_map(|attr| attr.ok())
                .find(|attr| {
                    String::from_utf8_lossy(attr.key.as_ref())
                        .trim()
                        .to_lowercase()
                        == "href"
                })
            {
                let href = href
                    .decode_and_unescape_value(reader.decoder())
                    .unwrap_or_default()
                    .to_string();

                if !href.is_empty() {
                    dehtml.last_href = Some(href);
                    *dehtml.get_buf() += "[";
                }
            }
        }
        "b" | "strong" => {
            if dehtml.get_add_text() != AddText::No {
                *dehtml.get_buf() += "*";
            }
        }
        "i" | "em" => {
            if dehtml.get_add_text() != AddText::No {
                *dehtml.get_buf() += "_";
            }
        }
        "blockquote" => dehtml.blockquotes_since_blockquote += 1,
        _ => {}
    }
}

/// In order to know when a specific tag is closed, we need to count the opening and closing tags.
/// The `counts`s are stored in the `Dehtml` struct.
#[expect(clippy::arithmetic_side_effects)]
fn pop_tag(count: &mut u32) {
    if *count > 0 {
        *count -= 1;
    }
}

/// In order to know when a specific tag is closed, we need to count the opening and closing tags.
/// The `counts`s are stored in the `Dehtml` struct.
#[expect(clippy::arithmetic_side_effects)]
fn maybe_push_tag(
    event: &BytesStart,
    reader: &Reader<impl BufRead>,
    tag_name: &str,
    count: &mut u32,
) {
    if *count > 0 || tag_contains_attr(event, reader, tag_name) {
        *count += 1;
    }
}

fn tag_contains_attr(event: &BytesStart, reader: &Reader<impl BufRead>, name: &str) -> bool {
    event.attributes().any(|r| {
        r.map(|a| {
            a.decode_and_unescape_value(reader.decoder())
                .map(|v| v == name)
                .unwrap_or(false)
        })
        .unwrap_or(false)
    })
}

pub fn dehtml_manually(buf: &str) -> String {
    // Just strip out everything between "<" and ">"
    let mut strbuilder = String::new();
    let mut show_next_chars = true;
    for c in buf.chars() {
        match c {
            '<' => show_next_chars = false,
            '>' => show_next_chars = true,
            _ => {
                if show_next_chars {
                    strbuilder.push(c)
                }
            }
        }
    }
    strbuilder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dehtml() {
        let cases = vec![
            (
                "<a href='https://example.com'> Foo </a>",
                "[ Foo ](https://example.com)",
            ),
            ("<b> bar </b>", "* bar *"),
            ("<i>foo</i>", "_foo_"),
            ("<b> bar <i> foo", "* bar _ foo"),
            ("&amp; bar", "& bar"),
            // Despite missing ', this should be shown:
            ("<a href='/foo.png>Hi</a> ", "Hi"),
            ("No link: <a href='https://get.delta.chat/'/>", "No link:"),
            (
                "No link: <a href='https://get.delta.chat/'></a>",
                "No link:",
            ),
            ("<!doctype html>\n<b>fat text</b>", "*fat text*"),
            // Invalid html (at least DC should show the text if the html is invalid):
            ("<!some invalid html code>\n<b>some text</b>", "some text"),
        ];
        for (input, output) in cases {
            assert_eq!(dehtml(input).unwrap().text, output);
        }
        let none_cases = vec!["<html> </html>", ""];
        for input in none_cases {
            assert_eq!(dehtml(input), None);
        }
    }

    #[test]
    fn test_dehtml_parse_br() {
        let html = "line1<br>line2";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "line1\nline2");

        let html = "line1<br> line2";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "line1\nline2");

        let html = "line1  <br><br> line2";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "line1\n\nline2");

        let html = "\r\r\nline1<br>\r\n\r\n\r\rline2<br/>line3\n\r";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "line1\nline2\nline3");
    }

    #[test]
    fn test_dehtml_parse_span() {
        assert_eq!(dehtml("<span>Foo</span>bar").unwrap().text, "Foobar");
        assert_eq!(dehtml("<span>Foo</span> bar").unwrap().text, "Foo bar");
        assert_eq!(dehtml("<span>Foo </span>bar").unwrap().text, "Foo bar");
        assert_eq!(dehtml("<span>Foo</span>\nbar").unwrap().text, "Foo bar");
        assert_eq!(dehtml("\n<span>Foo</span> bar").unwrap().text, "Foo bar");
        assert_eq!(dehtml("<span>Foo</span>\n\nbar").unwrap().text, "Foo bar");
        assert_eq!(dehtml("Foo\n<span>bar</span>").unwrap().text, "Foo bar");
        assert_eq!(dehtml("Foo<span>\nbar</span>").unwrap().text, "Foo bar");
    }

    #[test]
    fn test_dehtml_parse_p() {
        let html = "<p>Foo</p><p>Bar</p>";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "Foo\n\nBar");

        let html = "<p>Foo<p>Bar";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "Foo\n\nBar");

        let html = "<p>Foo</p><p>Bar<p>Baz";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "Foo\n\nBar\n\nBaz");
    }

    #[test]
    fn test_dehtml_parse_href() {
        let html = "<a href=url>text</a>";
        let plain = dehtml(html).unwrap().text;

        assert_eq!(plain, "[text](url)");
    }

    #[test]
    fn test_dehtml_case_sensitive_link() {
        let html = "<html><A HrEf=\"https://foo.bar/Data\">case in URLs matter</A></html>";
        let plain = dehtml(html).unwrap().text;
        assert_eq!(plain, "[case in URLs matter](https://foo.bar/Data)");
    }

    #[test]
    fn test_dehtml_bold_text() {
        let html = "<!DOCTYPE name [<!DOCTYPE ...>]><!-- comment -->text <b><?php echo ... ?>bold</b><![CDATA[<>]]>";
        let plain = dehtml(html).unwrap().text;

        assert_eq!(plain, "text *bold*<>");
    }

    #[test]
    fn test_dehtml_html_encoded() {
        let html = "&lt;&gt;&quot;&apos;&amp; &auml;&Auml;&ouml;&Ouml;&uuml;&Uuml;&szlig; foo&AElig;&ccedil;&Ccedil; &diams;&lrm;&rlm;&zwnj;&noent;&zwj;";

        let plain = dehtml(html).unwrap().text;

        assert_eq!(
            plain,
            "<>\"\'& äÄöÖüÜß fooÆçÇ \u{2666}\u{200e}\u{200f}\u{200c}&noent;\u{200d}"
        );
    }

    #[test]
    fn test_unclosed_tags() {
        let input = r##"
        <!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN'
        'http://www.w3.org/TR/html4/loose.dtd'>
        <html>
        <head>
        <title>Hi</title>
        <meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>						
        </head>
        <body>
        lots of text
        </body>
        </html>
        "##;
        let txt = dehtml(input).unwrap();
        assert_eq!(txt.text.trim(), "lots of text");
    }

    #[test]
    fn test_pre_tag() {
        let input = "<html><pre>\ntwo\nlines\n</pre></html>";
        let txt = dehtml(input).unwrap();
        assert_eq!(txt.text.trim(), "two\nlines");
    }

    #[test]
    fn test_hp_legacy_display() {
        let input = r#"
<html><head><title></title></head><body>
<div class="header-protection-legacy-display">
<pre>Subject: Dinner plans</pre>
</div>
<p>
Let's meet at Rama's Roti Shop at 8pm and go to the park
from there.
</p>
</body>
</html>
        "#;
        let txt = dehtml(input).unwrap();
        assert_eq!(
            txt.text.trim(),
            "Let's meet at Rama's Roti Shop at 8pm and go to the park from there."
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quote_div() {
        let input = include_str!("../test-data/message/gmx-quote-body.eml");
        let dehtml = dehtml(input).unwrap();
        let SimplifiedText {
            text,
            is_forwarded,
            is_cut,
            top_quote,
            footer,
        } = dehtml;
        assert_eq!(text, "Test");
        assert_eq!(is_forwarded, false);
        assert_eq!(is_cut, false);
        assert_eq!(top_quote.as_deref(), Some("test"));
        assert_eq!(footer, None);
    }

    #[test]
    fn test_spaces() {
        let input = include_str!("../test-data/spaces.html");
        let txt = dehtml(input).unwrap();
        assert_eq!(
            txt.text,
            "Welcome back to Strolling!\n\nHey there,\n\nWelcome back! Use this link to securely sign in to your Strolling account:\n\nSign in to Strolling\n\nFor your security, the link will expire in 24 hours time.\n\nSee you soon!\n\nYou can also copy & paste this URL into your browser:\n\nhttps://strolling.rosano.ca/members/?token=XXX&action=signin&r=https%3A%2F%2Fstrolling.rosano.ca%2F\n\nIf you did not make this request, you can safely ignore this email.\n\nThis message was sent from [strolling.rosano.ca](https://strolling.rosano.ca/) to [alice@example.org](mailto:alice@example.org)"
        );
    }
}
