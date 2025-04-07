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
use anyhow::Context as _;
use anyhow::Result;
use chrono::{DateTime, NaiveDateTime};
use regex::Regex;

#[derive(Debug)]
/// A Contact, as represented in a VCard.
pub struct VcardContact {
    /// The email address, vcard property `email`
    pub addr: String,
    /// This must be the name authorized by the contact itself, not a locally given name. Vcard
    /// property `fn`. Can be empty, one should use `display_name()` to obtain the display name.
    pub authname: String,
    /// The contact's public PGP key in Base64, vcard property `key`
    pub key: Option<String>,
    /// The contact's profile image (=avatar) in Base64, vcard property `photo`
    pub profile_image: Option<String>,
    /// The timestamp when the vcard was created / last updated, vcard property `rev`
    pub timestamp: Result<i64>,
}

impl VcardContact {
    /// Returns the contact's display name.
    pub fn display_name(&self) -> &str {
        match self.authname.is_empty() {
            false => &self.authname,
            true => &self.addr,
        }
    }
}

/// Returns a vCard containing given contacts.
///
/// Calling [`parse_vcard()`] on the returned result is a reverse operation.
pub fn make_vcard(contacts: &[VcardContact]) -> String {
    fn format_timestamp(c: &VcardContact) -> Option<String> {
        let timestamp = *c.timestamp.as_ref().ok()?;
        let datetime = DateTime::from_timestamp(timestamp, 0)?;
        Some(datetime.format("%Y%m%dT%H%M%SZ").to_string())
    }

    let mut res = "".to_string();
    for c in contacts {
        let addr = &c.addr;
        let display_name = c.display_name();
        res += &format!(
            "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:{addr}\r\n\
             FN:{display_name}\r\n"
        );
        if let Some(key) = &c.key {
            res += &format!("KEY:data:application/pgp-keys;base64,{key}\r\n");
        }
        if let Some(profile_image) = &c.profile_image {
            res += &format!("PHOTO:data:image/jpeg;base64,{profile_image}\r\n");
        }
        if let Some(timestamp) = format_timestamp(c) {
            res += &format!("REV:{timestamp}\r\n");
        }
        res += "END:VCARD\r\n";
    }
    res
}

/// Parses `VcardContact`s from a given `&str`.
pub fn parse_vcard(vcard: &str) -> Vec<VcardContact> {
    fn remove_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        let start_of_s = s.get(..prefix.len())?;

        if start_of_s.eq_ignore_ascii_case(prefix) {
            s.get(prefix.len()..)
        } else {
            None
        }
    }
    /// Returns (parameters, value) tuple.
    fn vcard_property<'a>(line: &'a str, property: &str) -> Option<(&'a str, &'a str)> {
        let remainder = remove_prefix(line, property)?;
        // If `s` is `EMAIL;TYPE=work:alice@example.com` and `property` is `EMAIL`,
        // then `remainder` is now `;TYPE=work:alice@example.com`

        // Note: This doesn't handle the case where there are quotes around a colon,
        // like `NAME;Foo="Some quoted text: that contains a colon":value`.
        // This could be improved in the future, but for now, the parsing is good enough.
        let (mut params, value) = remainder.split_once(':')?;
        // In the example from above, `params` is now `;TYPE=work`
        // and `value` is now `alice@example.com`

        if params
            .chars()
            .next()
            .filter(|c| !c.is_ascii_punctuation() || *c == '_')
            .is_some()
        {
            // `s` started with `property`, but the next character after it was not punctuation,
            // so this line's property is actually something else
            return None;
        }
        if let Some(p) = remove_prefix(params, ";") {
            params = p;
        }
        if let Some(p) = remove_prefix(params, "PREF=1") {
            params = p;
        }
        Some((params, value))
    }
    fn base64_key(line: &str) -> Option<&str> {
        let (params, value) = vcard_property(line, "key")?;
        if params.eq_ignore_ascii_case("PGP;ENCODING=BASE64")
            || params.eq_ignore_ascii_case("TYPE=PGP;ENCODING=b")
        {
            return Some(value);
        }
        if let Some(value) = remove_prefix(value, "data:application/pgp-keys;base64,")
            .or_else(|| remove_prefix(value, r"data:application/pgp-keys;base64\,"))
        {
            return Some(value);
        }

        None
    }
    fn base64_photo(line: &str) -> Option<&str> {
        let (params, value) = vcard_property(line, "photo")?;
        if params.eq_ignore_ascii_case("JPEG;ENCODING=BASE64")
            || params.eq_ignore_ascii_case("ENCODING=BASE64;JPEG")
            || params.eq_ignore_ascii_case("TYPE=JPEG;ENCODING=b")
            || params.eq_ignore_ascii_case("ENCODING=b;TYPE=JPEG")
            || params.eq_ignore_ascii_case("ENCODING=BASE64;TYPE=JPEG")
            || params.eq_ignore_ascii_case("TYPE=JPEG;ENCODING=BASE64")
        {
            return Some(value);
        }
        if let Some(value) = remove_prefix(value, "data:image/jpeg;base64,")
            .or_else(|| remove_prefix(value, r"data:image/jpeg;base64\,"))
        {
            return Some(value);
        }

        None
    }
    fn parse_datetime(datetime: &str) -> Result<i64> {
        // According to https://www.rfc-editor.org/rfc/rfc6350#section-4.3.5, the timestamp
        // is in ISO.8601.2004 format. DateTime::parse_from_rfc3339() apparently parses
        // ISO.8601, but fails to parse any of the examples given.
        // So, instead just parse using a format string.

        // Parses 19961022T140000Z, 19961022T140000-05, or 19961022T140000-0500.
        let timestamp = match DateTime::parse_from_str(datetime, "%Y%m%dT%H%M%S%#z") {
            Ok(datetime) => datetime.timestamp(),
            // Parses 19961022T140000.
            Err(e) => match NaiveDateTime::parse_from_str(datetime, "%Y%m%dT%H%M%S") {
                Ok(datetime) => datetime
                    .and_local_timezone(chrono::offset::Local)
                    .single()
                    .context("Could not apply local timezone to parsed date and time")?
                    .timestamp(),
                Err(_) => return Err(e.into()),
            },
        };
        Ok(timestamp)
    }

    // Remove line folding, see https://datatracker.ietf.org/doc/html/rfc6350#section-3.2
    static NEWLINE_AND_SPACE_OR_TAB: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("\r?\n[\t ]").unwrap());
    let unfolded_lines = NEWLINE_AND_SPACE_OR_TAB.replace_all(vcard, "");

    let mut lines = unfolded_lines.lines().peekable();
    let mut contacts = Vec::new();

    while lines.peek().is_some() {
        // Skip to the start of the vcard:
        for line in lines.by_ref() {
            if line.eq_ignore_ascii_case("BEGIN:VCARD") {
                break;
            }
        }

        let mut display_name = None;
        let mut addr = None;
        let mut key = None;
        let mut photo = None;
        let mut datetime = None;

        for mut line in lines.by_ref() {
            if let Some(remainder) = remove_prefix(line, "item1.") {
                // Remove the group name, if the group is called "item1".
                // If necessary, we can improve this to also remove groups that are called something different that "item1".
                //
                // Search "group name" at https://datatracker.ietf.org/doc/html/rfc6350 for more infos.
                line = remainder;
            }

            if let Some((_params, email)) = vcard_property(line, "email") {
                addr.get_or_insert(email);
            } else if let Some((_params, name)) = vcard_property(line, "fn") {
                display_name.get_or_insert(name);
            } else if let Some(k) = base64_key(line) {
                key.get_or_insert(k);
            } else if let Some(p) = base64_photo(line) {
                photo.get_or_insert(p);
            } else if let Some((_params, rev)) = vcard_property(line, "rev") {
                datetime.get_or_insert(rev);
            } else if line.eq_ignore_ascii_case("END:VCARD") {
                let (authname, addr) =
                    sanitize_name_and_addr(display_name.unwrap_or(""), addr.unwrap_or(""));

                contacts.push(VcardContact {
                    authname,
                    addr,
                    key: key.map(|s| s.to_string()),
                    profile_image: photo.map(|s| s.to_string()),
                    timestamp: datetime
                        .context("No timestamp in vcard")
                        .and_then(parse_datetime),
                });
                break;
            }
        }
    }

    contacts
}

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
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
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
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
        let val = rusqlite::types::Value::Text(self.to_string());
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn test_vcard_thunderbird() {
        let contacts = parse_vcard(
            "BEGIN:VCARD
VERSION:4.0
FN:'Alice Mueller'
EMAIL;PREF=1:alice.mueller@posteo.de
UID:a8083264-ca47-4be7-98a8-8ec3db1447ca
END:VCARD
BEGIN:VCARD
VERSION:4.0
FN:'bobzzz@freenet.de'
EMAIL;PREF=1:bobzzz@freenet.de
UID:cac4fef4-6351-4854-bbe4-9b6df857eaed
END:VCARD
",
        );

        assert_eq!(contacts[0].addr, "alice.mueller@posteo.de".to_string());
        assert_eq!(contacts[0].authname, "Alice Mueller".to_string());
        assert_eq!(contacts[0].key, None);
        assert_eq!(contacts[0].profile_image, None);
        assert!(contacts[0].timestamp.is_err());

        assert_eq!(contacts[1].addr, "bobzzz@freenet.de".to_string());
        assert_eq!(contacts[1].authname, "".to_string());
        assert_eq!(contacts[1].key, None);
        assert_eq!(contacts[1].profile_image, None);
        assert!(contacts[1].timestamp.is_err());

        assert_eq!(contacts.len(), 2);
    }

    #[test]
    fn test_vcard_simple_example() {
        let contacts = parse_vcard(
            "BEGIN:VCARD
VERSION:4.0
FN:Alice Wonderland
N:Wonderland;Alice;;;Ms.
GENDER:W
EMAIL;TYPE=work:alice@example.com
KEY;TYPE=PGP;ENCODING=b:[base64-data]
REV:20240418T184242Z

END:VCARD",
        );

        assert_eq!(contacts[0].addr, "alice@example.com".to_string());
        assert_eq!(contacts[0].authname, "Alice Wonderland".to_string());
        assert_eq!(contacts[0].key, Some("[base64-data]".to_string()));
        assert_eq!(contacts[0].profile_image, None);
        assert_eq!(*contacts[0].timestamp.as_ref().unwrap(), 1713465762);

        assert_eq!(contacts.len(), 1);
    }

    #[test]
    fn test_vcard_with_trailing_newline() {
        let contacts = parse_vcard(
            "BEGIN:VCARD\r
VERSION:4.0\r
FN:Alice Wonderland\r
N:Wonderland;Alice;;;Ms.\r
GENDER:W\r
EMAIL;TYPE=work:alice@example.com\r
KEY;TYPE=PGP;ENCODING=b:[base64-data]\r
REV:20240418T184242Z\r
END:VCARD\r
\r",
        );

        assert_eq!(contacts[0].addr, "alice@example.com".to_string());
        assert_eq!(contacts[0].authname, "Alice Wonderland".to_string());
        assert_eq!(contacts[0].key, Some("[base64-data]".to_string()));
        assert_eq!(contacts[0].profile_image, None);
        assert_eq!(*contacts[0].timestamp.as_ref().unwrap(), 1713465762);

        assert_eq!(contacts.len(), 1);
    }

    #[test]
    fn test_make_and_parse_vcard() {
        let contacts = [
            VcardContact {
                addr: "alice@example.org".to_string(),
                authname: "Alice Wonderland".to_string(),
                key: Some("[base64-data]".to_string()),
                profile_image: Some("image in Base64".to_string()),
                timestamp: Ok(1713465762),
            },
            VcardContact {
                addr: "bob@example.com".to_string(),
                authname: "".to_string(),
                key: None,
                profile_image: None,
                timestamp: Ok(0),
            },
        ];
        let items = [
            "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:alice@example.org\r\n\
             FN:Alice Wonderland\r\n\
             KEY:data:application/pgp-keys;base64,[base64-data]\r\n\
             PHOTO:data:image/jpeg;base64,image in Base64\r\n\
             REV:20240418T184242Z\r\n\
             END:VCARD\r\n",
            "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:bob@example.com\r\n\
             FN:bob@example.com\r\n\
             REV:19700101T000000Z\r\n\
             END:VCARD\r\n",
        ];
        let mut expected = "".to_string();
        for len in 0..=contacts.len() {
            let contacts = &contacts[0..len];
            let vcard = make_vcard(contacts);
            if len > 0 {
                expected += items[len - 1];
            }
            assert_eq!(vcard, expected);
            let parsed = parse_vcard(&vcard);
            assert_eq!(parsed.len(), contacts.len());
            for i in 0..parsed.len() {
                assert_eq!(parsed[i].addr, contacts[i].addr);
                assert_eq!(parsed[i].authname, contacts[i].authname);
                assert_eq!(parsed[i].key, contacts[i].key);
                assert_eq!(parsed[i].profile_image, contacts[i].profile_image);
                assert_eq!(
                    parsed[i].timestamp.as_ref().unwrap(),
                    contacts[i].timestamp.as_ref().unwrap()
                );
            }
        }
    }

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
    fn test_vcard_android() {
        let contacts = parse_vcard(
            "BEGIN:VCARD
VERSION:2.1
N:;Bob;;;
FN:Bob
TEL;CELL:+1-234-567-890
EMAIL;HOME:bob@example.org
END:VCARD
BEGIN:VCARD
VERSION:2.1
N:;Alice;;;
FN:Alice
EMAIL;HOME:alice@example.org
END:VCARD
",
        );

        assert_eq!(contacts[0].addr, "bob@example.org".to_string());
        assert_eq!(contacts[0].authname, "Bob".to_string());
        assert_eq!(contacts[0].key, None);
        assert_eq!(contacts[0].profile_image, None);

        assert_eq!(contacts[1].addr, "alice@example.org".to_string());
        assert_eq!(contacts[1].authname, "Alice".to_string());
        assert_eq!(contacts[1].key, None);
        assert_eq!(contacts[1].profile_image, None);

        assert_eq!(contacts.len(), 2);
    }

    #[test]
    fn test_vcard_local_datetime() {
        let contacts = parse_vcard(
            "BEGIN:VCARD\n\
             VERSION:4.0\n\
             FN:Alice Wonderland\n\
             EMAIL;TYPE=work:alice@example.org\n\
             REV:20240418T184242\n\
             END:VCARD",
        );
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].addr, "alice@example.org".to_string());
        assert_eq!(contacts[0].authname, "Alice Wonderland".to_string());
        assert_eq!(
            *contacts[0].timestamp.as_ref().unwrap(),
            chrono::offset::Local
                .with_ymd_and_hms(2024, 4, 18, 18, 42, 42)
                .unwrap()
                .timestamp()
        );
    }

    #[test]
    fn test_vcard_with_base64_avatar() {
        // This is not an actual base64-encoded avatar, it's just to test the parsing.
        // This one is Android-like.
        let vcard0 = "BEGIN:VCARD
VERSION:2.1
N:;Bob;;;
FN:Bob
EMAIL;HOME:bob@example.org
PHOTO;ENCODING=BASE64;JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/4gIoSUNDX1BST0ZJTEU
 AAQEAAAIYAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAA
 L8bRuAJYoZUYrI4ZY3VWwxw4Ay28AAGBISScmf/2Q==

END:VCARD
";
        // This one is DOS-like.
        let vcard1 = vcard0.replace('\n', "\r\n");
        for vcard in [vcard0, vcard1.as_str()] {
            let contacts = parse_vcard(vcard);
            assert_eq!(contacts.len(), 1);
            assert_eq!(contacts[0].addr, "bob@example.org".to_string());
            assert_eq!(contacts[0].authname, "Bob".to_string());
            assert_eq!(contacts[0].key, None);
            assert_eq!(contacts[0].profile_image.as_deref().unwrap(), "/9j/4AAQSkZJRgABAQAAAQABAAD/4gIoSUNDX1BST0ZJTEUAAQEAAAIYAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAL8bRuAJYoZUYrI4ZY3VWwxw4Ay28AAGBISScmf/2Q==");
        }
    }

    #[test]
    fn test_protonmail_vcard() {
        let contacts = parse_vcard(
            "BEGIN:VCARD
VERSION:4.0
FN;PREF=1:Alice Wonderland
UID:proton-web-03747582-328d-38dc-5ddd-000000000000
ITEM1.EMAIL;PREF=1:alice@example.org
ITEM1.KEY;PREF=1:data:application/pgp-keys;base64,aaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ITEM1.KEY;PREF=2:data:application/pgp-keys;base64,bbbbbbbbbbbbbbbbbbbbbbbbb
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ITEM1.X-PM-ENCRYPT:true
ITEM1.X-PM-SIGN:true
END:VCARD",
        );

        assert_eq!(contacts.len(), 1);
        assert_eq!(&contacts[0].addr, "alice@example.org");
        assert_eq!(&contacts[0].authname, "Alice Wonderland");
        assert_eq!(contacts[0].key.as_ref().unwrap(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(contacts[0].timestamp.is_err());
        assert_eq!(contacts[0].profile_image, None);
    }

    /// Proton at some point slightly changed the format of their vcards
    #[test]
    fn test_protonmail_vcard2() {
        let contacts = parse_vcard(
            r"BEGIN:VCARD
VERSION:4.0
FN;PREF=1:Alice
PHOTO;PREF=1:data:image/jpeg;base64\,/9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Z
REV:Invalid Date
ITEM1.EMAIL;PREF=1:alice@example.org
KEY;PREF=1:data:application/pgp-keys;base64,xsaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==
UID:proton-web-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
END:VCARD",
        );

        assert_eq!(contacts.len(), 1);
        assert_eq!(&contacts[0].addr, "alice@example.org");
        assert_eq!(&contacts[0].authname, "Alice");
        assert_eq!(contacts[0].key.as_ref().unwrap(), "xsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==");
        assert!(contacts[0].timestamp.is_err());
        assert_eq!(contacts[0].profile_image.as_ref().unwrap(), "/9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Z");
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
