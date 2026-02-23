//! # Simplify incoming plaintext.
use crate::tools::IsNoneOrEmpty;

/// Protects lines starting with `--` against being treated as a footer.
/// for that, we insert a ZERO WIDTH SPACE (ZWSP, 0x200B);
/// this should be invisible on most systems and there is no need to unescape it again
/// (which won't be done by non-deltas anyway).
///
/// This escapes a bit more than actually needed by delta (e.g. also lines as "-- footer"),
/// but for non-delta-compatibility, that seems to be better.
/// (to be only compatible with delta, only "[\r\n|\n]-- {0,2}[\r\n|\n]" needs to be replaced)
#[expect(clippy::arithmetic_side_effects)]
pub fn escape_message_footer_marks(text: &str) -> String {
    if let Some(text) = text.strip_prefix("--") {
        "-\u{200B}-".to_string() + &text.replace("\n--", "\n-\u{200B}-")
    } else {
        text.replace("\n--", "\n-\u{200B}-")
    }
}

/// Remove standard (RFC 3676, §4.3) footer if it is found.
/// Returns `(lines, footer_lines)` tuple;
/// `footer_lines` is set to `Some` if the footer was actually removed from `lines`
/// (which is equal to the input array otherwise).
#[expect(clippy::arithmetic_side_effects)]
pub(crate) fn remove_message_footer<'a>(
    lines: &'a [&str],
) -> (&'a [&'a str], Option<&'a [&'a str]>) {
    let mut nearly_standard_footer = None;
    for (ix, &line) in lines.iter().enumerate() {
        match line {
            // some providers encode `-- ` to `-- =20` which results in `--  `
            "-- " | "--  " => return (lines.get(..ix).unwrap_or(lines), lines.get(ix + 1..)),
            // some providers encode `-- ` to `=2D-` which results in only `--`;
            // use that only when no other footer is found
            // and if the line before is empty and the line after is not empty
            "--" => {
                if (ix == 0 || lines.get(ix.saturating_sub(1)).is_none_or_empty())
                    && !lines.get(ix + 1).is_none_or_empty()
                {
                    nearly_standard_footer = Some(ix);
                }
            }
            _ => (),
        }
    }
    if let Some(ix) = nearly_standard_footer {
        return (lines.get(..ix).unwrap_or(lines), lines.get(ix + 1..));
    }
    (lines, None)
}

/// Remove nonstandard footer and a boolean indicating whether such footer was removed.
/// Returns `(lines, is_footer_removed)` tuple;
/// `is_footer_removed` is set to `true` if the footer was actually removed from `lines`
/// (which is equal to the input array otherwise).
fn remove_nonstandard_footer<'a>(lines: &'a [&str]) -> (&'a [&'a str], bool) {
    for (ix, &line) in lines.iter().enumerate() {
        if line == "--"
            || line.starts_with("---")
            || line.starts_with("_____")
            || line.starts_with("=====")
            || line.starts_with("*****")
            || line.starts_with("~~~~~")
        {
            // `get` should always return `Some` here.
            if let Some(lines) = lines.get(..ix) {
                return (lines, true);
            }
        }
    }
    (lines, false)
}

/// Remove footers if any.
/// This also makes all newlines "\n", but why not.
pub(crate) fn remove_footers(msg: &str) -> String {
    let lines = split_lines(msg);
    let lines = remove_message_footer(&lines).0;
    let lines = remove_nonstandard_footer(lines).0;
    lines.join("\n")
}

pub(crate) fn split_lines(buf: &str) -> Vec<&str> {
    buf.split('\n').collect()
}

/// Simplified text and some additional information gained from the input.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SimplifiedText {
    /// The text itself.
    pub text: String,

    /// True if the message is forwarded.
    pub is_forwarded: bool,

    /// True if nonstandard footer was removed
    /// or if the message contains quotes other than `top_quote`.
    pub is_cut: bool,

    /// Top quote, if any.
    pub top_quote: Option<String>,

    /// Footer, if any.
    pub footer: Option<String>,
}

pub(crate) fn simplify_quote(quote: &str) -> (String, bool) {
    let quote_lines = split_lines(quote);
    let (quote_lines, quote_footer_lines) = remove_message_footer(&quote_lines);
    let is_cut = quote_footer_lines.is_some();

    (render_message(quote_lines, false), is_cut)
}

/// Simplify message text for chat display.
/// Remove quotes, signatures, trailing empty lines etc.
pub(crate) fn simplify(mut input: String, is_chat_message: bool) -> SimplifiedText {
    let mut is_cut = false;

    input.retain(|c| c != '\r');
    let lines = split_lines(&input);
    let (lines, is_forwarded) = skip_forward_header(&lines);

    let (lines, mut top_quote) = remove_top_quote(lines, is_chat_message);
    let original_lines = &lines;
    let (lines, footer_lines) = remove_message_footer(lines);
    let footer = footer_lines.map(|footer_lines| render_message(footer_lines, false));

    let text = if is_chat_message {
        render_message(lines, false)
    } else {
        let (lines, has_nonstandard_footer) = remove_nonstandard_footer(lines);
        let (lines, mut bottom_quote) = remove_bottom_quote(lines);

        if top_quote.is_none() && bottom_quote.is_some() {
            std::mem::swap(&mut top_quote, &mut bottom_quote);
        }

        if lines.iter().all(|it| it.trim().is_empty()) {
            render_message(original_lines, false)
        } else {
            is_cut = is_cut || has_nonstandard_footer || bottom_quote.is_some();
            render_message(lines, has_nonstandard_footer || bottom_quote.is_some())
        }
    };

    if !is_chat_message {
        top_quote = top_quote.map(|quote| {
            let (quote, quote_cut) = simplify_quote(&quote);
            is_cut |= quote_cut;
            quote
        });
    }

    SimplifiedText {
        text,
        is_forwarded,
        is_cut,
        top_quote,
        footer,
    }
}

/// Skips "forwarded message" header.
/// Returns message body lines and a boolean indicating whether
/// a message is forwarded or not.
fn skip_forward_header<'a>(lines: &'a [&str]) -> (&'a [&'a str], bool) {
    match lines {
        [
            "---------- Forwarded message ----------",
            first_line,
            "",
            rest @ ..,
        ] if first_line.starts_with("From: ") => (rest, true),
        _ => (lines, false),
    }
}

#[expect(clippy::arithmetic_side_effects)]
fn remove_bottom_quote<'a>(lines: &'a [&str]) -> (&'a [&'a str], Option<String>) {
    let mut first_quoted_line = lines.len();
    let mut last_quoted_line = None;
    for (l, line) in lines.iter().enumerate().rev() {
        if is_plain_quote(line) {
            if last_quoted_line.is_none() {
                first_quoted_line = l + 1;
            }
            last_quoted_line = Some(l)
        } else if !is_empty_line(line) {
            break;
        }
    }
    if let Some(mut l_last) = last_quoted_line {
        let quoted_text = lines
            .iter()
            .take(first_quoted_line)
            .skip(l_last)
            .map(|s| {
                s.strip_prefix('>')
                    .map_or(*s, |u| u.strip_prefix(' ').unwrap_or(u))
            })
            .collect::<Vec<&str>>()
            .join("\n");
        if l_last > 1
            && let Some(line) = lines.get(l_last - 1)
            && is_empty_line(line)
        {
            l_last -= 1
        }
        if l_last > 1
            && let Some(line) = lines.get(l_last - 1)
            && is_quoted_headline(line)
        {
            l_last -= 1
        }
        (lines.get(..l_last).unwrap_or(lines), Some(quoted_text))
    } else {
        (lines, None)
    }
}

#[expect(clippy::arithmetic_side_effects)]
fn remove_top_quote<'a>(
    lines: &'a [&str],
    is_chat_message: bool,
) -> (&'a [&'a str], Option<String>) {
    let mut first_quoted_line = 0;
    let mut last_quoted_line = None;
    let mut has_quoted_headline = false;
    for (l, line) in lines.iter().enumerate() {
        if is_plain_quote(line) {
            if last_quoted_line.is_none() {
                first_quoted_line = l;
            }
            last_quoted_line = Some(l)
        } else if !is_chat_message
            && is_quoted_headline(line)
            && !has_quoted_headline
            && last_quoted_line.is_none()
        {
            has_quoted_headline = true
        } else {
            /* non-quoting line found */
            break;
        }
    }
    if let Some(last_quoted_line) = last_quoted_line {
        (
            lines.get(last_quoted_line + 1..).unwrap_or(lines),
            Some(
                lines
                    .iter()
                    .take(last_quoted_line + 1)
                    .skip(first_quoted_line)
                    .map(|s| {
                        s.strip_prefix('>')
                            .map_or(*s, |u| u.strip_prefix(' ').unwrap_or(u))
                    })
                    .collect::<Vec<&str>>()
                    .join("\n"),
            ),
        )
    } else {
        (lines, None)
    }
}

#[expect(clippy::arithmetic_side_effects)]
fn render_message(lines: &[&str], is_cut_at_end: bool) -> String {
    let mut ret = String::new();
    /* we write empty lines only in case and non-empty line follows */
    let mut pending_linebreaks = 0;
    for line in lines {
        if is_empty_line(line) {
            pending_linebreaks += 1
        } else {
            if !ret.is_empty() {
                if pending_linebreaks > 2 {
                    pending_linebreaks = 2
                }
                while 0 != pending_linebreaks {
                    ret += "\n";
                    pending_linebreaks -= 1
                }
            }
            // the incoming message might contain invalid UTF8
            ret += line;
            pending_linebreaks = 1
        }
    }
    if is_cut_at_end && !ret.is_empty() {
        ret += " [...]";
    }
    // redo escaping done by escape_message_footer_marks()
    ret.replace('\u{200B}', "")
}

/// Returns true if the line contains only whitespace.
fn is_empty_line(buf: &str) -> bool {
    buf.chars().all(char::is_whitespace)
    // for some time, this checked for `char <= ' '`,
    // see discussion at: <https://github.com/deltachat/deltachat-core-rust/pull/402#discussion_r317062392>
    // and <https://github.com/deltachat/deltachat-core-rust/pull/2104/files#r538973613>
}

fn is_quoted_headline(buf: &str) -> bool {
    /* This function may be called for the line _directly_ before a quote.
    The function checks if the line contains sth. like "On 01.02.2016, xy@z wrote:" in various languages.
    - Currently, we simply check if the last character is a ':'.
    - Checking for the existence of an email address may fail (headlines may show the user's name instead of the address) */

    buf.len() <= 120 && buf.ends_with(':')
}

fn is_plain_quote(buf: &str) -> bool {
    buf.starts_with('>')
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        // proptest does not support [[:graphical:][:space:]] regex.
        fn test_simplify_plain_text_fuzzy(input in "[!-~\t \n]+") {
            let SimplifiedText {
                text,
                ..
            } = simplify(input, true);
            assert!(text.split('\n').all(|s| s != "-- "));
        }
    }

    #[test]
    fn test_dont_remove_whole_message() {
        let input = "\n------\nFailed\n------\n\nUh-oh, this workflow did not succeed!\n\nlots of other text".to_string();
        let SimplifiedText {
            text,
            is_forwarded,
            is_cut,
            ..
        } = simplify(input, false);
        assert_eq!(
            text,
            "------\nFailed\n------\n\nUh-oh, this workflow did not succeed!\n\nlots of other text"
        );
        assert!(!is_forwarded);
        assert!(!is_cut);
    }

    #[test]
    fn test_chat_message() {
        let input = "Hi! How are you?\n\n---\n\nI am good.\n-- \nSent with my Delta Chat Messenger: https://delta.chat".to_string();
        let SimplifiedText {
            text,
            is_forwarded,
            is_cut,
            footer,
            ..
        } = simplify(input, true);
        assert_eq!(text, "Hi! How are you?\n\n---\n\nI am good.");
        assert!(!is_forwarded);
        assert!(!is_cut);
        assert_eq!(
            footer.unwrap(),
            "Sent with my Delta Chat Messenger: https://delta.chat"
        );
    }

    #[test]
    fn test_simplify_trim() {
        let input = "line1\n\r\r\rline2".to_string();
        let SimplifiedText {
            text,
            is_forwarded,
            is_cut,
            ..
        } = simplify(input, false);

        assert_eq!(text, "line1\nline2");
        assert!(!is_forwarded);
        assert!(!is_cut);
    }

    #[test]
    fn test_simplify_forwarded_message() {
        let input = "---------- Forwarded message ----------\r\nFrom: test@example.com\r\n\r\nForwarded message\r\n-- \r\nSignature goes here".to_string();
        let SimplifiedText {
            text,
            is_forwarded,
            is_cut,
            footer,
            ..
        } = simplify(input, false);

        assert_eq!(text, "Forwarded message");
        assert!(is_forwarded);
        assert!(!is_cut);
        assert_eq!(footer.unwrap(), "Signature goes here");
    }

    #[test]
    fn test_simplify_utilities() {
        assert!(is_empty_line(" \t"));
        assert!(is_empty_line(""));
        assert!(is_empty_line(" \r"));
        assert!(!is_empty_line(" x"));
        assert!(is_plain_quote("> hello world"));
        assert!(is_plain_quote(">>"));
        assert!(!is_plain_quote("Life is pain"));
        assert!(!is_plain_quote(""));
    }

    #[test]
    fn test_is_quoted_headline() {
        assert!(is_quoted_headline("On 2024-08-28, Bob wrote:"));
        assert!(is_quoted_headline("Am 11. November 2024 schrieb Alice:"));
        assert!(is_quoted_headline("Anonymous Longer Name a écrit:"));
        assert!(is_quoted_headline("There is not really a pattern wrote:"));
        assert!(is_quoted_headline(
            "On Mon, 3 Jan, 2022 at 8:34 PM \"Anonymous Longer Name\" <anonymous-longer-name@example.com> wrote:"
        ));
        assert!(!is_quoted_headline(
            "How are you? I just want to say that this line does not belong to the quote!"
        ));
        assert!(!is_quoted_headline(
            "No quote headline as not ending with a colon"
        ));
        assert!(!is_quoted_headline(
            "Even though this ends with a colon, \
            this is no quote-headline as just too long for most cases of date+name+address. \
            it's all heuristics only, it is expected to go wrong sometimes. there is always the 'Show full message' button:"
        ));
    }

    #[test]
    fn test_remove_top_quote() {
        let (lines, top_quote) = remove_top_quote(&["> first", "> second"], true);
        assert!(lines.is_empty());
        assert_eq!(top_quote.unwrap(), "first\nsecond");

        let (lines, top_quote) = remove_top_quote(&["> first", "> second", "not a quote"], true);
        assert_eq!(lines, &["not a quote"]);
        assert_eq!(top_quote.unwrap(), "first\nsecond");

        let (lines, top_quote) = remove_top_quote(&["not a quote", "> first", "> second"], true);
        assert_eq!(lines, &["not a quote", "> first", "> second"]);
        assert!(top_quote.is_none());

        let (lines, top_quote) = remove_top_quote(
            &["On 2024-08-28, Bob wrote:", "> quote", "not a quote"],
            false,
        );
        assert_eq!(lines, &["not a quote"]);
        assert_eq!(top_quote.unwrap(), "quote");

        let (lines, top_quote) = remove_top_quote(
            &["On 2024-08-28, Bob wrote:", "> quote", "not a quote"],
            true,
        );
        assert_eq!(
            lines,
            &["On 2024-08-28, Bob wrote:", "> quote", "not a quote"]
        );
        assert!(top_quote.is_none());
    }

    #[test]
    fn test_escape_message_footer_marks() {
        let esc = escape_message_footer_marks("--\n--text --in line");
        assert_eq!(esc, "-\u{200B}-\n-\u{200B}-text --in line");

        let esc = escape_message_footer_marks("--\r\n--text");
        assert_eq!(esc, "-\u{200B}-\r\n-\u{200B}-text");
    }

    #[test]
    fn test_remove_message_footer() {
        let input = "text\n--\nno footer".to_string();
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input, true);
        assert_eq!(text, "text\n--\nno footer");
        assert_eq!(footer, None);
        assert!(!is_cut);

        let input = "text\n\n--\n\nno footer".to_string();
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input, true);
        assert_eq!(text, "text\n\n--\n\nno footer");
        assert_eq!(footer, None);
        assert!(!is_cut);

        let input = "text\n\n-- no footer\n\n".to_string();
        let SimplifiedText { text, footer, .. } = simplify(input, true);
        assert_eq!(text, "text\n\n-- no footer");
        assert_eq!(footer, None);

        let input = "text\n\n--\nno footer\n-- \nfooter".to_string();
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input, true);
        assert_eq!(text, "text\n\n--\nno footer");
        assert!(!is_cut);
        assert_eq!(footer.unwrap(), "footer");

        let input = "text\n\n--\ntreated as footer when unescaped".to_string();
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input.clone(), true);
        assert_eq!(text, "text"); // see remove_message_footer() for some explanations
        assert!(!is_cut);
        assert_eq!(footer.unwrap(), "treated as footer when unescaped");
        let escaped = escape_message_footer_marks(&input);
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(escaped, true);
        assert_eq!(text, "text\n\n--\ntreated as footer when unescaped");
        assert!(!is_cut);
        assert_eq!(footer, None);

        // Nonstandard footer sent by <https://siju.es/>
        let input = "Message text here\n---Desde mi teléfono con SIJÚ\n\nQuote here".to_string();
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input.clone(), false);
        assert_eq!(text, "Message text here [...]");
        assert!(is_cut);
        assert_eq!(footer, None);
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input.clone(), true);
        assert_eq!(text, input);
        assert!(!is_cut);
        assert_eq!(footer, None);

        let input = "--\ntreated as footer when unescaped".to_string();
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(input.clone(), true);
        assert_eq!(text, ""); // see remove_message_footer() for some explanations
        assert!(!is_cut);
        assert_eq!(footer.unwrap(), "treated as footer when unescaped");

        let escaped = escape_message_footer_marks(&input);
        let SimplifiedText {
            text,
            is_cut,
            footer,
            ..
        } = simplify(escaped, true);
        assert_eq!(text, "--\ntreated as footer when unescaped");
        assert!(!is_cut);
        assert_eq!(footer, None);
    }
}
