use crate::dehtml::*;

/// Return index of footer line in vector of message lines, or vector length if
/// no footer is found.
///
/// Also return whether not-standard (rfc3676, §4.3) footer is found.
fn find_message_footer(lines: &[&str]) -> (usize, bool) {
    for (ix, &line) in lines.iter().enumerate() {
        // quoted-printable may encode `-- ` to `-- =20` which is converted
        // back to `--  `
        match line {
            "-- " | "--  " => return (ix, false),
            "--" | "---" | "----" => return (ix, true),
            _ => (),
        }
    }
    (lines.len(), false)
}

fn split_lines(buf: &str) -> Vec<&str> {
    buf.split('\n').collect()
}

/// Simplify and normalise text: Remove quotes, signatures, unnecessary
/// lineends etc.
/// The data returned from simplify() must be free()'d when no longer used.
pub fn simplify(input: &str, is_html: bool, is_msgrmsg: bool) -> (String, bool) {
    let mut out = if is_html {
        dehtml(input)
    } else {
        input.to_string()
    };

    out.retain(|c| c != '\r');
    let lines = split_lines(&out);
    let (mut out, is_forwarded) = simplify_plain_text(&lines, is_msgrmsg);
    out.retain(|c| c != '\r');

    (out, is_forwarded)
}

/// Skips "forwarded message" header.
/// Returns `None` if message is not a forwarded message,
/// otherwise returns lines of the forwarded message without the header.
fn skip_forward_header<'a>(lines: &'a [&str]) -> Option<&'a [&'a str]> {
    if lines.len() >= 3
        && lines[0] == "---------- Forwarded message ----------"
        && lines[1].starts_with("From: ")
        && lines[2].is_empty()
    {
        Some(&lines[3..])
    } else {
        None
    }
}
/**
 * Simplify Plain Text
 */
#[allow(non_snake_case, clippy::mut_range_bound, clippy::needless_range_loop)]
fn simplify_plain_text(lines: &[&str], is_msgrmsg: bool) -> (String, bool) {
    /* This function ...
    ... removes all text after the line `-- ` (footer mark)
    ... removes full quotes at the beginning and at the end of the text -
        these are all lines starting with the character `>`
    ... remove a non-empty line before the removed quote (contains sth. like "On 2.9.2016, Bjoern wrote:" in different formats and lanugages) */
    /* split the given buffer into lines */
    let (lines, is_forwarded) = if let Some(lines) = skip_forward_header(lines) {
        (lines, true)
    } else {
        (lines, false)
    };

    let mut l_first: usize = 0;
    let (mut l_last, mut is_cut_at_end) = find_message_footer(&lines);

    for l in l_first..l_last {
        let line = lines[l];
        if line == "-----"
            || line == "_____"
            || line == "====="
            || line == "*****"
            || line == "~~~~~"
        {
            l_last = l;
            is_cut_at_end = true;
            /* done */
            break;
        }
    }
    if !is_msgrmsg {
        let mut l_lastQuotedLine = None;
        for l in (l_first..l_last).rev() {
            let line = lines[l];
            if is_plain_quote(line) {
                l_lastQuotedLine = Some(l)
            } else if !is_empty_line(line) {
                break;
            }
        }
        if let Some(last_quoted_line) = l_lastQuotedLine {
            l_last = last_quoted_line;
            is_cut_at_end = true;
            if l_last > 1 && is_empty_line(lines[l_last - 1]) {
                l_last -= 1
            }
            if l_last > 1 {
                let line = lines[l_last - 1];
                if is_quoted_headline(line) {
                    l_last -= 1
                }
            }
        }
    }

    let mut is_cut_at_begin = false;
    if !is_msgrmsg {
        let mut l_lastQuotedLine_0 = None;
        let mut hasQuotedHeadline = 0;
        for l in l_first..l_last {
            let line = lines[l];
            if is_plain_quote(line) {
                l_lastQuotedLine_0 = Some(l)
            } else if !is_empty_line(line) {
                if is_quoted_headline(line)
                    && 0 == hasQuotedHeadline
                    && l_lastQuotedLine_0.is_none()
                {
                    hasQuotedHeadline = 1i32
                } else {
                    /* non-quoting line found */
                    break;
                }
            }
        }
        if let Some(last_quoted_line) = l_lastQuotedLine_0 {
            l_first = last_quoted_line + 1;
            is_cut_at_begin = true
        }
    }
    /* re-create buffer from the remaining lines */
    let mut ret = String::new();
    if is_cut_at_begin {
        ret += "[...]";
    }
    /* we write empty lines only in case and non-empty line follows */
    let mut pending_linebreaks = 0;
    let mut content_lines_added = 0;
    for l in l_first..l_last {
        let line = lines[l];
        if is_empty_line(line) {
            pending_linebreaks += 1
        } else {
            if 0 != content_lines_added {
                if pending_linebreaks > 2i32 {
                    pending_linebreaks = 2i32
                }
                while 0 != pending_linebreaks {
                    ret += "\n";
                    pending_linebreaks -= 1
                }
            }
            // the incoming message might contain invalid UTF8
            ret += line;
            content_lines_added += 1;
            pending_linebreaks = 1i32
        }
    }
    if is_cut_at_end && (!is_cut_at_begin || 0 != content_lines_added) {
        ret += " [...]";
    }

    (ret, is_forwarded)
}

/**
 * Tools
 */
fn is_empty_line(buf: &str) -> bool {
    // XXX: can it be simplified to buf.chars().all(|c| c.is_whitespace())?
    //
    // Strictly speaking, it is not equivalent (^A is not whitespace, but less than ' '),
    // but having control sequences in email body?!
    //
    // See discussion at: https://github.com/deltachat/deltachat-core-rust/pull/402#discussion_r317062392
    for c in buf.chars() {
        if c > ' ' {
            return false;
        }
    }

    true
}

fn is_quoted_headline(buf: &str) -> bool {
    /* This function may be called for the line _directly_ before a quote.
    The function checks if the line contains sth. like "On 01.02.2016, xy@z wrote:" in various languages.
    - Currently, we simply check if the last character is a ':'.
    - Checking for the existence of an email address may fail (headlines may show the user's name instead of the address) */

    buf.len() <= 80 && buf.ends_with(':')
}

fn is_plain_quote(buf: &str) -> bool {
    buf.starts_with('>')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        // proptest does not support [[:graphical:][:space:]] regex.
        fn test_simplify_plain_text_fuzzy(input in "[!-~\t \n]+") {
            let output = Simplify::new().simplify_plain_text(&input, true);
            assert!(output.split('\n').all(|s| s != "-- "));
        }
    }

    #[test]
    fn test_simplify_trim() {
        let mut simplify = Simplify::new();
        let html = "\r\r\nline1<br>\r\n\r\n\r\rline2\n\r";
        let plain = simplify.simplify(html, true, false);

        assert_eq!(plain, "line1\nline2");
    }

    #[test]
    fn test_simplify_parse_href() {
        let mut simplify = Simplify::new();
        let html = "<a href=url>text</a";
        let plain = simplify.simplify(html, true, false);

        assert_eq!(plain, "[text](url)");
    }

    #[test]
    fn test_simplify_bold_text() {
        let mut simplify = Simplify::new();
        let html = "<!DOCTYPE name [<!DOCTYPE ...>]><!-- comment -->text <b><?php echo ... ?>bold</b><![CDATA[<>]]>";
        let plain = simplify.simplify(html, true, false);

        assert_eq!(plain, "text *bold*<>");
    }

    #[test]
    fn test_simplify_html_encoded() {
        let mut simplify = Simplify::new();
        let html =
                "&lt;&gt;&quot;&apos;&amp; &auml;&Auml;&ouml;&Ouml;&uuml;&Uuml;&szlig; foo&AElig;&ccedil;&Ccedil; &diams;&lrm;&rlm;&zwnj;&noent;&zwj;";

        let plain = simplify.simplify(html, true, false);

        assert_eq!(
            plain,
            "<>\"\'& äÄöÖüÜß fooÆçÇ \u{2666}\u{200e}\u{200f}\u{200c}&noent;\u{200d}"
        );
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
}
