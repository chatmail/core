//! Contact-related tools, like parsing vcards and sanitizing name and address

#![forbid(unsafe_code)]
#![warn(
    unused,
    clippy::correctness,
    missing_debug_implementations,
    missing_docs,
    clippy::all,
    clippy::wildcard_imports,
    clippy::needless_borrow,
    clippy::cast_lossless,
    clippy::unused_async,
    clippy::explicit_iter_loop,
    clippy::explicit_into_iter_loop,
    clippy::cloned_instead_of_copied
)]
#![cfg_attr(not(test), forbid(clippy::indexing_slicing))]
#![cfg_attr(not(test), forbid(clippy::string_slice))]
#![allow(
    clippy::match_bool,
    clippy::mixed_read_write_in_expression,
    clippy::bool_assert_comparison,
    clippy::manual_split_once,
    clippy::format_push_string,
    clippy::bool_to_int_with_if,
    clippy::manual_range_contains
)]

use std::fmt;
use std::ops::Deref;
use std::sync::LazyLock;

use anyhow::bail;
use anyhow::Result;
use regex::Regex;

mod vcard;
pub use vcard::{make_vcard, parse_vcard, VcardContact};

/// Valid contact address.
#[derive(Debug, Clone)]
pub struct ContactAddress(String);

impl Deref for ContactAddress {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for ContactAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContactAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ContactAddress {
    /// Constructs a new contact address from string,
    /// normalizing and validating it.
    pub fn new(s: &str) -> Result<Self> {
        let addr = addr_normalize(s);
        if !may_be_valid_addr(&addr) {
            bail!("invalid address {:?}", s);
        }
        Ok(Self(addr.to_string()))
    }
}

/// Allow converting [`ContactAddress`] to an SQLite type.
impl rusqlite::types::ToSql for ContactAddress {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let val = rusqlite::types::Value::Text(self.0.to_string());
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

/// Takes a name and an address and sanitizes them:
/// - Extracts a name from the addr if the addr is in form "Alice <alice@example.org>"
/// - Removes special characters from the name, see [`sanitize_name()`]
/// - Removes the name if it is equal to the address by setting it to ""
pub fn sanitize_name_and_addr(name: &str, addr: &str) -> (String, String) {
    static ADDR_WITH_NAME_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("(.*)<(.*)>").unwrap());
    let (name, addr) = if let Some(captures) = ADDR_WITH_NAME_REGEX.captures(addr.as_ref()) {
        (
            if name.is_empty() {
                captures.get(1).map_or("", |m| m.as_str())
            } else {
                name
            },
            captures
                .get(2)
                .map_or("".to_string(), |m| m.as_str().to_string()),
        )
    } else {
        (name, addr.to_string())
    };
    let mut name = sanitize_name(name);

    // If the 'display name' is just the address, remove it:
    // Otherwise, the contact would sometimes be shown as "alice@example.com (alice@example.com)" (see `get_name_n_addr()`).
    // If the display name is empty, DC will just show the address when it needs a display name.
    if name == addr {
        name = "".to_string();
    }

    (name, addr)
}

/// Sanitizes a name.
///
/// - Removes newlines and trims the string
/// - Removes quotes (come from some bad MUA implementations)
/// - Removes potentially-malicious bidi characters
pub fn sanitize_name(name: &str) -> String {
    let name = sanitize_single_line(name);

    match name.as_bytes() {
        [b'\'', .., b'\''] | [b'\"', .., b'\"'] | [b'<', .., b'>'] => name
            .get(1..name.len() - 1)
            .map_or("".to_string(), |s| s.trim().to_string()),
        _ => name.to_string(),
    }
}

/// Sanitizes user input
///
/// - Removes newlines and trims the string
/// - Removes potentially-malicious bidi characters
pub fn sanitize_single_line(input: &str) -> String {
    sanitize_bidi_characters(input.replace(['\n', '\r'], " ").trim())
}

const RTLO_CHARACTERS: [char; 5] = ['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}'];
const ISOLATE_CHARACTERS: [char; 3] = ['\u{2066}', '\u{2067}', '\u{2068}'];
const POP_ISOLATE_CHARACTER: char = '\u{2069}';
/// Some control unicode characters can influence whether adjacent text is shown from
/// left to right or from right to left.
///
/// Since user input is not supposed to influence how adjacent text looks,
/// this function removes some of these characters.
///
/// Also see https://github.com/deltachat/deltachat-core-rust/issues/3479.
pub fn sanitize_bidi_characters(input_str: &str) -> String {
    // RTLO_CHARACTERS are apparently rarely used in practice.
    // They can impact all following text, so, better remove them all:
    let input_str = input_str.replace(|char| RTLO_CHARACTERS.contains(&char), "");

    // If the ISOLATE characters are not ended with a POP DIRECTIONAL ISOLATE character,
    // we regard the input as potentially malicious and simply remove all ISOLATE characters.
    // See https://en.wikipedia.org/wiki/Bidirectional_text#Unicode_bidi_support
    // and https://www.w3.org/International/questions/qa-bidi-unicode-controls.en
    // for an explanation about ISOLATE characters.
    fn isolate_characters_are_valid(input_str: &str) -> bool {
        let mut isolate_character_nesting: i32 = 0;
        for char in input_str.chars() {
            if ISOLATE_CHARACTERS.contains(&char) {
                isolate_character_nesting += 1;
            } else if char == POP_ISOLATE_CHARACTER {
                isolate_character_nesting -= 1;
            }

            // According to Wikipedia, 125 levels are allowed:
            // https://en.wikipedia.org/wiki/Unicode_control_characters
            // (although, in practice, we could also significantly lower this number)
            if isolate_character_nesting < 0 || isolate_character_nesting > 125 {
                return false;
            }
        }
        isolate_character_nesting == 0
    }

    if isolate_characters_are_valid(&input_str) {
        input_str
    } else {
        input_str.replace(
            |char| ISOLATE_CHARACTERS.contains(&char) || POP_ISOLATE_CHARACTER == char,
            "",
        )
    }
}

/// Returns false if addr is an invalid address, otherwise true.
pub fn may_be_valid_addr(addr: &str) -> bool {
    let res = EmailAddress::new(addr);
    res.is_ok()
}

/// Returns address lowercased,
/// with whitespace trimmed and `mailto:` prefix removed.
pub fn addr_normalize(addr: &str) -> String {
    let norm = addr.trim().to_lowercase();

    if norm.starts_with("mailto:") {
        norm.get(7..).unwrap_or(&norm).to_string()
    } else {
        norm
    }
}

/// Compares two email addresses, normalizing them beforehand.
pub fn addr_cmp(addr1: &str, addr2: &str) -> bool {
    let norm1 = addr_normalize(addr1);
    let norm2 = addr_normalize(addr2);

    norm1 == norm2
}

///
/// Represents an email address, right now just the `name@domain` portion.
///
/// # Example
///
/// ```
/// use deltachat_contact_tools::EmailAddress;
/// let email = match EmailAddress::new("someone@example.com") {
///     Ok(addr) => addr,
///     Err(e) => panic!("Error parsing address, error was {}", e),
/// };
/// assert_eq!(&email.local, "someone");
/// assert_eq!(&email.domain, "example.com");
/// assert_eq!(email.to_string(), "someone@example.com");
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EmailAddress {
    /// Local part of the email address.
    pub local: String,

    /// Email address domain.
    pub domain: String,
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl EmailAddress {
    /// Performs a dead-simple parse of an email address.
    pub fn new(input: &str) -> Result<EmailAddress> {
        if input.is_empty() {
            bail!("empty string is not valid");
        }
        let parts: Vec<&str> = input.rsplitn(2, '@').collect();

        if input
            .chars()
            .any(|c| c.is_whitespace() || c == '<' || c == '>')
        {
            bail!("Email {:?} must not contain whitespaces, '>' or '<'", input);
        }

        match &parts[..] {
            [domain, local] => {
                if local.is_empty() {
                    bail!("empty string is not valid for local part in {:?}", input);
                }
                if domain.is_empty() {
                    bail!("missing domain after '@' in {:?}", input);
                }
                if domain.ends_with('.') {
                    bail!("Domain {domain:?} should not contain the dot in the end");
                }
                Ok(EmailAddress {
                    local: (*local).to_string(),
                    domain: (*domain).to_string(),
                })
            }
            _ => bail!("Email {:?} must contain '@' character", input),
        }
    }
}

impl rusqlite::types::ToSql for EmailAddress {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let val = rusqlite::types::Value::Text(self.to_string());
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_address() -> Result<()> {
        let alice_addr = "alice@example.org";
        let contact_address = ContactAddress::new(alice_addr)?;
        assert_eq!(contact_address.as_ref(), alice_addr);

        let invalid_addr = "<> foobar";
        assert!(ContactAddress::new(invalid_addr).is_err());

        Ok(())
    }

    #[test]
    fn test_emailaddress_parse() {
        assert_eq!(EmailAddress::new("").is_ok(), false);
        assert_eq!(
            EmailAddress::new("user@domain.tld").unwrap(),
            EmailAddress {
                local: "user".into(),
                domain: "domain.tld".into(),
            }
        );
        assert_eq!(
            EmailAddress::new("user@localhost").unwrap(),
            EmailAddress {
                local: "user".into(),
                domain: "localhost".into()
            }
        );
        assert_eq!(EmailAddress::new("uuu").is_ok(), false);
        assert_eq!(EmailAddress::new("dd.tt").is_ok(), false);
        assert!(EmailAddress::new("tt.dd@uu").is_ok());
        assert!(EmailAddress::new("u@d").is_ok());
        assert!(EmailAddress::new("u@d.").is_err());
        assert!(EmailAddress::new("u@d.t").is_ok());
        assert_eq!(
            EmailAddress::new("u@d.tt").unwrap(),
            EmailAddress {
                local: "u".into(),
                domain: "d.tt".into(),
            }
        );
        assert!(EmailAddress::new("u@tt").is_ok());
        assert_eq!(EmailAddress::new("@d.tt").is_ok(), false);
    }

    #[test]
    fn test_sanitize_name() {
        assert_eq!(&sanitize_name(" hello world   "), "hello world");
        assert_eq!(&sanitize_name("<"), "<");
        assert_eq!(&sanitize_name(">"), ">");
        assert_eq!(&sanitize_name("'"), "'");
        assert_eq!(&sanitize_name("\""), "\"");
    }

    #[test]
    fn test_sanitize_single_line() {
        assert_eq!(sanitize_single_line("Hi\naiae "), "Hi aiae");
        assert_eq!(sanitize_single_line("\r\nahte\n\r"), "ahte");
    }

    #[test]
    fn test_sanitize_bidi_characters() {
        // Legit inputs:
        assert_eq!(
            &sanitize_bidi_characters("Tes\u{2067}ting Delta Chat\u{2069}"),
            "Tes\u{2067}ting Delta Chat\u{2069}"
        );

        assert_eq!(
            &sanitize_bidi_characters("Tes\u{2067}ting \u{2068} Delta Chat\u{2069}\u{2069}"),
            "Tes\u{2067}ting \u{2068} Delta Chat\u{2069}\u{2069}"
        );

        assert_eq!(
            &sanitize_bidi_characters("Tes\u{2067}ting\u{2069} Delta Chat\u{2067}\u{2069}"),
            "Tes\u{2067}ting\u{2069} Delta Chat\u{2067}\u{2069}"
        );

        // Potentially-malicious inputs:
        assert_eq!(
            &sanitize_bidi_characters("Tes\u{202C}ting Delta Chat"),
            "Testing Delta Chat"
        );

        assert_eq!(
            &sanitize_bidi_characters("Testing Delta Chat\u{2069}"),
            "Testing Delta Chat"
        );

        assert_eq!(
            &sanitize_bidi_characters("Tes\u{2067}ting Delta Chat"),
            "Testing Delta Chat"
        );

        assert_eq!(
            &sanitize_bidi_characters("Tes\u{2069}ting Delta Chat\u{2067}"),
            "Testing Delta Chat"
        );

        assert_eq!(
            &sanitize_bidi_characters("Tes\u{2068}ting Delta Chat"),
            "Testing Delta Chat"
        );
    }
}
