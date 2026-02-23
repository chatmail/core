//! Handle plain text together with some attributes.

use std::sync::LazyLock;

use crate::simplify::remove_message_footer;

/// Plaintext message body together with format=flowed attributes.
#[derive(Debug)]
pub struct PlainText {
    /// The text itself.
    pub text: String,

    /// Text may "flowed" as defined in [RFC 2646](https://tools.ietf.org/html/rfc2646).
    /// At a glance, that means, if a line ends with a space, it is merged with the next one
    /// and the first leading spaces is ignored
    /// (to allow lines starting with `>` that normally indicates a quote)
    pub flowed: bool,

    /// If set together with "flowed",
    /// The space indicating merging two lines is removed.
    pub delsp: bool,
}

impl PlainText {
    /// Convert plain text to HTML.
    /// The function handles quotes, links, fixed and floating text paragraphs.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn to_html(&self) -> String {
        static LINKIFY_MAIL_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"\b([\w.\-+]+@[\w.\-]+)\b").unwrap());

        static LINKIFY_URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"\b((http|https|ftp|ftps):[\w.,:;$/@!?&%\-~=#+]+)").unwrap()
        });

        let lines: Vec<&str> = self.text.lines().collect();
        let (lines, _footer) = remove_message_footer(&lines);

        let mut ret = r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
"#
        .to_string();

        for line in lines {
            let is_quote = line.starts_with('>');

            // we need to do html-entity-encoding after linkify, as otherwise encapsulated links
            // as <http://example.org> cannot be handled correctly
            // (they would become &lt;http://example.org&gt; where the trailing &gt; would become a valid url part).
            // to avoid double encoding, we escape our html-entities by \r that must not be used in the string elsewhere.
            let line = line.to_string().replace('\r', "");

            let mut line = LINKIFY_MAIL_RE
                .replace_all(&line, "\rLTa href=\rQUOTmailto:$1\rQUOT\rGT$1\rLT/a\rGT")
                .as_ref()
                .to_string();

            line = LINKIFY_URL_RE
                .replace_all(&line, "\rLTa href=\rQUOT$1\rQUOT\rGT$1\rLT/a\rGT")
                .as_ref()
                .to_string();

            // encode html-entities after linkify the raw string
            line = escaper::encode_minimal(&line);

            // make our escaped html-entities real after encoding all others
            line = line.replace("\rLT", "<");
            line = line.replace("\rGT", ">");
            line = line.replace("\rQUOT", "\"");

            if self.flowed {
                // flowed text as of RFC 3676 -
                // a leading space shall be removed
                // and is only there to allow > at the beginning of a line that is no quote.
                line = line.strip_prefix(' ').unwrap_or(&line).to_string();
                if is_quote {
                    line = "<em>".to_owned() + &line + "</em>";
                }

                // a trailing space indicates that the line can be merged with the next one;
                // for sake of simplicity, we skip merging for quotes (quotes may be combined with
                // delsp, so `> >` is different from `>>` etc. see RFC 3676 for details)
                if line.ends_with(' ') && !is_quote {
                    if self.delsp {
                        line.pop();
                    }
                } else {
                    line += "<br/>\n";
                }
            } else {
                // normal, fixed text
                if is_quote {
                    line = "<em>".to_owned() + &line + "</em>";
                }
                line += "<br/>\n";
            }

            let len_with_indentation = line.len();
            let line = line.trim_start_matches(' ');
            for _ in line.len()..len_with_indentation {
                ret += "&nbsp;";
            }
            ret += line;
        }
        ret += "</body></html>\n";
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_to_html() {
        let html = PlainText {
            text: r##"line 1
line 2
line with https://link-mid-of-line.org and http://link-end-of-line.com/file?foo=bar%20
http://link-at-start-of-line.org
"##
            .to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
line 1<br/>
line 2<br/>
line with <a href="https://link-mid-of-line.org">https://link-mid-of-line.org</a> and <a href="http://link-end-of-line.com/file?foo=bar%20">http://link-end-of-line.com/file?foo=bar%20</a><br/>
<a href="http://link-at-start-of-line.org">http://link-at-start-of-line.org</a><br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_remove_signature() {
        let html = PlainText {
            text: "Foo\nbar\n-- \nSignature here".to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
Foo<br/>
bar<br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_encapsulated() {
        let html = PlainText {
            text: r#"line with <http://encapsulated.link/?foo=_bar> here!"#.to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
line with &lt;<a href="http://encapsulated.link/?foo=_bar">http://encapsulated.link/?foo=_bar</a>&gt; here!<br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_nolink() {
        let html = PlainText {
            text: r#"line with nohttp://no.link here"#.to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
line with nohttp://no.link here<br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_mailto() {
        let html = PlainText {
            text: r#"just an address: foo@bar.org another@one.de"#.to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
just an address: <a href="mailto:foo@bar.org">foo@bar.org</a> <a href="mailto:another@one.de">another@one.de</a><br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_flowed() {
        let html = PlainText {
            text: "line \nstill line\n>quote \n>still quote\n >no quote".to_string(),
            flowed: true,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
line still line<br/>
<em>&gt;quote </em><br/>
<em>&gt;still quote</em><br/>
&gt;no quote<br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_flowed_delsp() {
        let html = PlainText {
            text: "line \nstill line\n>quote \n>still quote\n >no quote".to_string(),
            flowed: true,
            delsp: true,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
linestill line<br/>
<em>&gt;quote </em><br/>
<em>&gt;still quote</em><br/>
&gt;no quote<br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_fixed() {
        let html = PlainText {
            text: "line \nstill line\n>quote \n>still quote\n >no quote".to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
line <br/>
still line<br/>
<em>&gt;quote </em><br/>
<em>&gt;still quote</em><br/>
&nbsp;&gt;no quote<br/>
</body></html>
"#
        );
    }

    #[test]
    fn test_plain_to_html_indentation() {
        let html = PlainText {
            text: "def foo():\n    pass\n\ndef bar(x):\n    return x + 5".to_string(),
            flowed: false,
            delsp: false,
        }
        .to_html();
        assert_eq!(
            html,
            r#"<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="color-scheme" content="light dark" />
</head><body>
def foo():<br/>
&nbsp;&nbsp;&nbsp;&nbsp;pass<br/>
<br/>
def bar(x):<br/>
&nbsp;&nbsp;&nbsp;&nbsp;return x + 5<br/>
</body></html>
"#
        );
    }
}
