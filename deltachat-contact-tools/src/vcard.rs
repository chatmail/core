use std::sync::LazyLock;

use anyhow::Context as _;
use anyhow::Result;
use chrono::DateTime;
use chrono::NaiveDateTime;
use regex::Regex;

use crate::sanitize_name_and_addr;

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
    /// The biography, stored in the vcard property `note`
    pub biography: Option<String>,
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

    fn escape(s: &str) -> String {
        s.replace(',', "\\,")
    }

    let mut res = "".to_string();
    for c in contacts {
        // Mustn't contain ',', but it's easier to escape than to error out.
        let addr = escape(&c.addr);
        let display_name = escape(c.display_name());
        res += &format!(
            "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:{addr}\r\n\
             FN:{display_name}\r\n"
        );
        if let Some(key) = &c.key {
            res += &format!("KEY:data:application/pgp-keys;base64\\,{key}\r\n");
        }
        if let Some(profile_image) = &c.profile_image {
            res += &format!("PHOTO:data:image/jpeg;base64\\,{profile_image}\r\n");
        }
        if let Some(biography) = &c.biography {
            res += &format!("NOTE:{}\r\n", escape(biography));
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
    /// Returns (parameters, raw value) tuple.
    fn vcard_property_raw<'a>(line: &'a str, property: &str) -> Option<(&'a str, &'a str)> {
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
    /// Returns (parameters, unescaped value) tuple.
    fn vcard_property<'a>(line: &'a str, property: &str) -> Option<(&'a str, String)> {
        let (params, value) = vcard_property_raw(line, property)?;
        // Some fields can't contain commas, but unescape them everywhere for safety.
        Some((params, value.replace("\\,", ",")))
    }
    fn base64_key(line: &str) -> Option<&str> {
        let (params, value) = vcard_property_raw(line, "key")?;
        if params.eq_ignore_ascii_case("PGP;ENCODING=BASE64")
            || params.eq_ignore_ascii_case("TYPE=PGP;ENCODING=b")
        {
            return Some(value);
        }
        remove_prefix(value, "data:application/pgp-keys;base64\\,")
            // Old Delta Chat format.
            .or_else(|| remove_prefix(value, "data:application/pgp-keys;base64,"))
    }
    fn base64_photo(line: &str) -> Option<&str> {
        let (params, value) = vcard_property_raw(line, "photo")?;
        if params.eq_ignore_ascii_case("JPEG;ENCODING=BASE64")
            || params.eq_ignore_ascii_case("ENCODING=BASE64;JPEG")
            || params.eq_ignore_ascii_case("TYPE=JPEG;ENCODING=b")
            || params.eq_ignore_ascii_case("ENCODING=b;TYPE=JPEG")
            || params.eq_ignore_ascii_case("ENCODING=BASE64;TYPE=JPEG")
            || params.eq_ignore_ascii_case("TYPE=JPEG;ENCODING=BASE64")
        {
            return Some(value);
        }
        remove_prefix(value, "data:image/jpeg;base64\\,")
            // Old Delta Chat format.
            .or_else(|| remove_prefix(value, "data:image/jpeg;base64,"))
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
        let mut biography = None;
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
            } else if let Some((_params, bio)) = vcard_property(line, "note") {
                biography.get_or_insert(bio);
            } else if let Some((_params, rev)) = vcard_property(line, "rev") {
                datetime.get_or_insert(rev);
            } else if line.eq_ignore_ascii_case("END:VCARD") {
                let (authname, addr) = sanitize_name_and_addr(
                    &display_name.unwrap_or_default(),
                    &addr.unwrap_or_default(),
                );

                contacts.push(VcardContact {
                    authname,
                    addr,
                    key: key.map(|s| s.to_string()),
                    profile_image: photo.map(|s| s.to_string()),
                    biography,
                    timestamp: datetime
                        .as_deref()
                        .context("No timestamp in vcard")
                        .and_then(parse_datetime),
                });
                break;
            }
        }
    }

    contacts
}

#[cfg(test)]
mod vcard_tests;
