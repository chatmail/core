//! Some tools and enhancements to the used libraries, there should be
//! no references to Context and other "larger" entities here.

use core::cmp::{max, min};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;
use std::{fmt, fs};

use chrono::{Local, TimeZone};
use rand::{thread_rng, Rng};

use crate::context::Context;
use crate::error::Error;
use crate::events::Event;

pub(crate) fn dc_exactly_one_bit_set(v: i32) -> bool {
    0 != v && 0 == v & (v - 1)
}

/// Shortens a string to a specified length and adds "..." or "[...]" to the end of
/// the shortened string.
pub(crate) fn dc_truncate(buf: &str, approx_chars: usize, do_unwrap: bool) -> Cow<str> {
    let ellipse = if do_unwrap { "..." } else { "[...]" };

    let count = buf.chars().count();
    if approx_chars > 0 && count > approx_chars + ellipse.len() {
        let end_pos = buf
            .char_indices()
            .nth(approx_chars)
            .map(|(n, _)| n)
            .unwrap_or_default();

        if let Some(index) = buf[..end_pos].rfind(|c| c == ' ' || c == '\n') {
            Cow::Owned(format!("{}{}", &buf[..=index], ellipse))
        } else {
            Cow::Owned(format!("{}{}", &buf[..end_pos], ellipse))
        }
    } else {
        Cow::Borrowed(buf)
    }
}

/// the colors must fulfill some criterions as:
/// - contrast to black and to white
/// - work as a text-color
/// - being noticeable on a typical map
/// - harmonize together while being different enough
/// (therefore, we cannot just use random rgb colors :)
const COLORS: [u32; 16] = [
    0xe56555, 0xf28c48, 0x8e85ee, 0x76c84d, 0x5bb6cc, 0x549cdd, 0xd25c99, 0xb37800, 0xf23030,
    0x39b249, 0xbb243b, 0x964078, 0x66874f, 0x308ab9, 0x127ed0, 0xbe450c,
];

pub(crate) fn dc_str_to_color(s: impl AsRef<str>) -> u32 {
    let str_lower = s.as_ref().to_lowercase();
    let mut checksum = 0;
    let bytes = str_lower.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        checksum += (i + 1) * *byte as usize;
        checksum %= 0xffffff;
    }
    let color_index = checksum % COLORS.len();

    COLORS[color_index]
}

/* ******************************************************************************
 * date/time tools
 ******************************************************************************/

pub fn dc_timestamp_to_str(wanted: i64) -> String {
    let ts = Local.timestamp(wanted, 0);
    ts.format("%Y.%m.%d %H:%M:%S").to_string()
}

pub(crate) fn dc_gm2local_offset() -> i64 {
    /* returns the offset that must be _added_ to an UTC/GMT-time to create the localtime.
    the function may return negative values. */
    let lt = Local::now();
    lt.offset().local_minus_utc() as i64
}

// timesmearing
// - as e-mails typically only use a second-based-resolution for timestamps,
//   the order of two mails sent withing one second is unclear.
//   this is bad eg. when forwarding some messages from a chat -
//   these messages will appear at the recipient easily out of order.
// - we work around this issue by not sending out two mails with the same timestamp.
// - for this purpose, in short, we track the last timestamp used in `last_smeared_timestamp`
//   when another timestamp is needed in the same second, we use `last_smeared_timestamp+1`
// - after some moments without messages sent out,
//   `last_smeared_timestamp` is again in sync with the normal time.
// - however, we do not do all this for the far future,
//   but at max `MAX_SECONDS_TO_LEND_FROM_FUTURE`
const MAX_SECONDS_TO_LEND_FROM_FUTURE: i64 = 5;

// returns the currently smeared timestamp,
// may be used to check if call to dc_create_smeared_timestamp() is needed or not.
// the returned timestamp MUST NOT be used to be sent out or saved in the database!
pub(crate) fn dc_smeared_time(context: &Context) -> i64 {
    let mut now = time();
    let ts = *context.last_smeared_timestamp.read().unwrap();
    if ts >= now {
        now = ts + 1;
    }

    now
}

// returns a timestamp that is guaranteed to be unique.
pub(crate) fn dc_create_smeared_timestamp(context: &Context) -> i64 {
    let now = time();
    let mut ret = now;

    let mut last_smeared_timestamp = context.last_smeared_timestamp.write().unwrap();
    if ret <= *last_smeared_timestamp {
        ret = *last_smeared_timestamp + 1;
        if ret - now > MAX_SECONDS_TO_LEND_FROM_FUTURE {
            ret = now + MAX_SECONDS_TO_LEND_FROM_FUTURE
        }
    }

    *last_smeared_timestamp = ret;
    ret
}

// creates `count` timestamps that are guaranteed to be unique.
// the frist created timestamps is returned directly,
// get the other timestamps just by adding 1..count-1
pub(crate) fn dc_create_smeared_timestamps(context: &Context, count: usize) -> i64 {
    let now = time();
    let count = count as i64;
    let mut start = now + min(count, MAX_SECONDS_TO_LEND_FROM_FUTURE) - count;

    let mut last_smeared_timestamp = context.last_smeared_timestamp.write().unwrap();
    start = max(*last_smeared_timestamp + 1, start);

    *last_smeared_timestamp = start + count - 1;
    start
}

/* Message-ID tools */
pub(crate) fn dc_create_id() -> String {
    /* generate an id. the generated ID should be as short and as unique as possible:
    - short, because it may also used as part of Message-ID headers or in QR codes
    - unique as two IDs generated on two devices should not be the same. However, collisions are not world-wide but only by the few contacts.
    IDs generated by this function are 66 bit wide and are returned as 11 base64 characters.
    If possible, RNG of OpenSSL is used.

    Additional information when used as a message-id or group-id:
    - for OUTGOING messages this ID is written to the header as `Chat-Group-ID:` and is added to the message ID as Gr.<grpid>.<random>@<random>
    - for INCOMING messages, the ID is taken from the Chat-Group-ID-header or from the Message-ID in the In-Reply-To: or References:-Header
    - the group-id should be a string with the characters [a-zA-Z0-9\-_] */

    let mut rng = thread_rng();
    let buf: [u32; 3] = [rng.gen(), rng.gen(), rng.gen()];

    encode_66bits_as_base64(buf[0usize], buf[1usize], buf[2usize])
}

/// Encode 66 bits as a base64 string.
/// This is useful for ID generating with short strings as we save 5 character
/// in each id compared to 64 bit hex encoding. For a typical group ID, these
/// are 10 characters (grpid+msgid):
///    hex:    64 bit, 4 bits/character, length = 64/4 = 16 characters
///    base64: 64 bit, 6 bits/character, length = 64/6 = 11 characters (plus 2 additional bits)
/// Only the lower 2 bits of `fill` are used.
fn encode_66bits_as_base64(v1: u32, v2: u32, fill: u32) -> String {
    use byteorder::{BigEndian, WriteBytesExt};

    let mut wrapped_writer = Vec::new();
    {
        let mut enc = base64::write::EncoderWriter::new(&mut wrapped_writer, base64::URL_SAFE);
        enc.write_u32::<BigEndian>(v1).unwrap();
        enc.write_u32::<BigEndian>(v2).unwrap();
        enc.write_u8(((fill & 0x3) as u8) << 6).unwrap();
        enc.finish().unwrap();
    }
    assert_eq!(wrapped_writer.pop(), Some(b'A')); // Remove last "A"
    String::from_utf8(wrapped_writer).unwrap()
}

pub(crate) fn dc_create_incoming_rfc724_mid(
    message_timestamp: i64,
    contact_id_from: u32,
    contact_ids_to: &[u32],
) -> Option<String> {
    /* create a deterministic rfc724_mid from input such that
    repeatedly calling it with the same input results in the same Message-id */

    let largest_id_to = contact_ids_to.iter().max().copied().unwrap_or_default();
    let result = format!(
        "{}-{}-{}@stub",
        message_timestamp, contact_id_from, largest_id_to
    );
    Some(result)
}

/// Function generates a Message-ID that can be used for a new outgoing message.
/// - this function is called for all outgoing messages.
/// - the message ID should be globally unique
/// - do not add a counter or any private data as this leaks information unncessarily
pub(crate) fn dc_create_outgoing_rfc724_mid(grpid: Option<&str>, from_addr: &str) -> String {
    let hostname = from_addr
        .find('@')
        .map(|k| &from_addr[k..])
        .unwrap_or("@nohost");
    match grpid {
        Some(grpid) => format!("Gr.{}.{}{}", grpid, dc_create_id(), hostname),
        None => format!("Mr.{}.{}{}", dc_create_id(), dc_create_id(), hostname),
    }
}

/// Extract the group id (grpid) from a message id (mid)
///
/// # Arguments
///
/// * `mid` - A string that holds the message id
pub(crate) fn dc_extract_grpid_from_rfc724_mid(mid: &str) -> Option<&str> {
    if mid.len() < 9 || !mid.starts_with("Gr.") {
        return None;
    }

    if let Some(mid_without_offset) = mid.get(3..) {
        if let Some(grpid_len) = mid_without_offset.find('.') {
            /* strict length comparison, the 'Gr.' magic is weak enough */
            if grpid_len == 11 || grpid_len == 16 {
                return Some(mid_without_offset.get(0..grpid_len).unwrap());
            }
        }
    }

    None
}

pub(crate) fn dc_ensure_no_slash_safe(path: &str) -> &str {
    if path.ends_with('/') || path.ends_with('\\') {
        return &path[..path.len() - 1];
    }
    path
}

// Function returns a sanitized basename that does not contain
// win/linux path separators and also not any non-ascii chars
fn get_safe_basename(filename: &str) -> String {
    // return the (potentially mangled) basename of the input filename
    // this might be a path that comes in from another operating system
    let mut index: usize = 0;

    if let Some(unix_index) = filename.rfind('/') {
        index = unix_index + 1;
    }
    if let Some(win_index) = filename.rfind('\\') {
        index = max(index, win_index + 1);
    }
    if index >= filename.len() {
        "nobasename".to_string()
    } else {
        // we don't allow any non-ascii to be super-safe
        filename[index..].replace(|c: char| !c.is_ascii() || c == ':', "-")
    }
}

pub fn dc_derive_safe_stem_ext(filename: &str) -> (String, String) {
    let basename = get_safe_basename(&filename);
    let (mut stem, mut ext) = if let Some(index) = basename.rfind('.') {
        (
            basename[0..index].to_string(),
            basename[index..].to_string(),
        )
    } else {
        (basename, "".to_string())
    };
    // limit length of stem and ext
    stem.truncate(32);
    ext.truncate(32);
    (stem, ext)
}

// the returned suffix is lower-case
#[allow(non_snake_case)]
pub fn dc_get_filesuffix_lc(path_filename: impl AsRef<str>) -> Option<String> {
    if let Some(p) = Path::new(path_filename.as_ref()).extension() {
        Some(p.to_string_lossy().to_lowercase())
    } else {
        None
    }
}

/// Returns the `(width, height)` of the given image buffer.
pub fn dc_get_filemeta(buf: &[u8]) -> Result<(u32, u32), Error> {
    let meta = image_meta::load_from_buf(buf)?;

    Ok((meta.dimensions.width, meta.dimensions.height))
}

/// Expand paths relative to $BLOBDIR into absolute paths.
///
/// If `path` starts with "$BLOBDIR", replaces it with the blobdir path.
/// Otherwise, returns path as is.
pub(crate) fn dc_get_abs_path<P: AsRef<std::path::Path>>(
    context: &Context,
    path: P,
) -> std::path::PathBuf {
    let p: &std::path::Path = path.as_ref();
    if let Ok(p) = p.strip_prefix("$BLOBDIR") {
        context.get_blobdir().join(p)
    } else {
        p.into()
    }
}

pub(crate) fn dc_get_filebytes(context: &Context, path: impl AsRef<std::path::Path>) -> u64 {
    let path_abs = dc_get_abs_path(context, &path);
    match fs::metadata(&path_abs) {
        Ok(meta) => meta.len() as u64,
        Err(_err) => 0,
    }
}

pub(crate) fn dc_delete_file(context: &Context, path: impl AsRef<std::path::Path>) -> bool {
    let path_abs = dc_get_abs_path(context, &path);
    if !path_abs.exists() {
        return false;
    }
    if !path_abs.is_file() {
        warn!(
            context,
            "refusing to delete non-file \"{}\".",
            path.as_ref().display()
        );
        return false;
    }

    let dpath = format!("{}", path.as_ref().to_string_lossy());
    match fs::remove_file(path_abs) {
        Ok(_) => {
            context.call_cb(Event::DeletedBlobFile(dpath));
            true
        }
        Err(err) => {
            warn!(context, "Cannot delete \"{}\": {}", dpath, err);
            false
        }
    }
}

pub(crate) fn dc_copy_file(
    context: &Context,
    src_path: impl AsRef<std::path::Path>,
    dest_path: impl AsRef<std::path::Path>,
) -> bool {
    let src_abs = dc_get_abs_path(context, &src_path);
    let mut src_file = match fs::File::open(&src_abs) {
        Ok(file) => file,
        Err(err) => {
            warn!(
                context,
                "failed to open for read '{}': {}",
                src_abs.display(),
                err
            );
            return false;
        }
    };

    let dest_abs = dc_get_abs_path(context, &dest_path);
    let mut dest_file = match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&dest_abs)
    {
        Ok(file) => file,
        Err(err) => {
            warn!(
                context,
                "failed to open for write '{}': {}",
                dest_abs.display(),
                err
            );
            return false;
        }
    };

    match std::io::copy(&mut src_file, &mut dest_file) {
        Ok(_) => true,
        Err(err) => {
            error!(
                context,
                "Cannot copy \"{}\" to \"{}\": {}",
                src_abs.display(),
                dest_abs.display(),
                err
            );
            {
                // Attempt to remove the failed file, swallow errors resulting from that.
                fs::remove_file(dest_abs).ok();
            }
            false
        }
    }
}

pub(crate) fn dc_create_folder(context: &Context, path: impl AsRef<std::path::Path>) -> bool {
    let path_abs = dc_get_abs_path(context, &path);
    if !path_abs.exists() {
        match fs::create_dir_all(path_abs) {
            Ok(_) => true,
            Err(err) => {
                warn!(
                    context,
                    "Cannot create directory \"{}\": {}",
                    path.as_ref().display(),
                    err
                );
                false
            }
        }
    } else {
        true
    }
}

/// Write a the given content to provied file path.
pub(crate) fn dc_write_file(
    context: &Context,
    path: impl AsRef<Path>,
    buf: &[u8],
) -> Result<(), std::io::Error> {
    let path_abs = dc_get_abs_path(context, &path);
    fs::write(&path_abs, buf).map_err(|err| {
        warn!(
            context,
            "Cannot write {} bytes to \"{}\": {}",
            buf.len(),
            path.as_ref().display(),
            err
        );
        err
    })
}

pub fn dc_read_file<P: AsRef<std::path::Path>>(
    context: &Context,
    path: P,
) -> Result<Vec<u8>, Error> {
    let path_abs = dc_get_abs_path(context, &path);

    match fs::read(&path_abs) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            warn!(
                context,
                "Cannot read \"{}\" or file is empty: {}",
                path.as_ref().display(),
                err
            );
            Err(err.into())
        }
    }
}

pub fn dc_open_file<P: AsRef<std::path::Path>>(
    context: &Context,
    path: P,
) -> Result<std::fs::File, Error> {
    let path_abs = dc_get_abs_path(context, &path);

    match fs::File::open(&path_abs) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            warn!(
                context,
                "Cannot read \"{}\" or file is empty: {}",
                path.as_ref().display(),
                err
            );
            Err(err.into())
        }
    }
}

pub(crate) fn dc_get_next_backup_path(
    folder: impl AsRef<Path>,
    backup_time: i64,
) -> Result<PathBuf, Error> {
    let folder = PathBuf::from(folder.as_ref());
    let stem = chrono::NaiveDateTime::from_timestamp(backup_time, 0)
        .format("delta-chat-%Y-%m-%d")
        .to_string();

    // 64 backup files per day should be enough for everyone
    for i in 0..64 {
        let mut path = folder.clone();
        path.push(format!("{}-{}.bak", stem, i));
        if !path.exists() {
            return Ok(path);
        }
    }
    bail!("could not create backup file, disk full?");
}

pub(crate) fn time() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Very simple email address wrapper.
///
/// Represents an email address, right now just the `name@domain` portion.
///
/// # Example
///
/// ```
/// use deltachat::dc_tools::EmailAddress;
/// let email = match EmailAddress::new("someone@example.com") {
///     Ok(addr) => addr,
///     Err(e) => panic!("Error parsing address, error was {}", e),
/// };
/// assert_eq!(&email.local, "someone");
/// assert_eq!(&email.domain, "example.com");
/// assert_eq!(email.to_string(), "someone@example.com");
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct EmailAddress {
    pub local: String,
    pub domain: String,
}

impl EmailAddress {
    pub fn new(input: &str) -> Result<Self, Error> {
        input.parse::<EmailAddress>()
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl FromStr for EmailAddress {
    type Err = Error;

    /// Performs a dead-simple parse of an email address.
    fn from_str(input: &str) -> Result<EmailAddress, Error> {
        ensure!(!input.is_empty(), "empty string is not valid");
        let parts: Vec<&str> = input.rsplitn(2, '@').collect();

        ensure!(parts.len() > 1, "missing '@' character");
        let local = parts[1];
        let domain = parts[0];

        ensure!(
            !local.is_empty(),
            "empty string is not valid for local part"
        );
        ensure!(domain.len() > 3, "domain is too short");

        let dot = domain.find('.');
        ensure!(dot.is_some(), "invalid domain");
        ensure!(dot.unwrap() < domain.len() - 2, "invalid domain");

        Ok(EmailAddress {
            local: local.to_string(),
            domain: domain.to_string(),
        })
    }
}

/// Utility to check if a in the binary represantion of listflags
/// the bit at position bitindex is 1.
pub(crate) fn listflags_has(listflags: u32, bitindex: usize) -> bool {
    let listflags = listflags as usize;
    (listflags & bitindex) == bitindex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    use crate::constants::*;
    use crate::test_utils::*;

    #[test]
    fn test_rust_ftoa() {
        assert_eq!("1.22", format!("{}", 1.22));
    }

    #[test]
    fn test_dc_truncate_1() {
        let s = "this is a little test string";
        assert_eq!(dc_truncate(s, 16, false), "this is a [...]");
        assert_eq!(dc_truncate(s, 16, true), "this is a ...");
    }

    #[test]
    fn test_dc_truncate_2() {
        assert_eq!(dc_truncate("1234", 2, false), "1234");
        assert_eq!(dc_truncate("1234", 2, true), "1234");
    }

    #[test]
    fn test_dc_truncate_3() {
        assert_eq!(dc_truncate("1234567", 1, false), "1[...]");
        assert_eq!(dc_truncate("1234567", 1, true), "1...");
    }

    #[test]
    fn test_dc_truncate_4() {
        assert_eq!(dc_truncate("123456", 4, false), "123456");
        assert_eq!(dc_truncate("123456", 4, true), "123456");
    }

    #[test]
    fn test_dc_truncate_edge() {
        assert_eq!(dc_truncate("", 4, false), "");
        assert_eq!(dc_truncate("", 4, true), "");

        assert_eq!(dc_truncate("\n  hello \n world", 4, false), "\n  [...]");
        assert_eq!(dc_truncate("\n  hello \n world", 4, true), "\n  ...");

        assert_eq!(
            dc_truncate("𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ", 1, false),
            "𐠈[...]"
        );
        assert_eq!(
            dc_truncate("𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ", 0, false),
            "𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ"
        );

        // 9 characters, so no truncation
        assert_eq!(
            dc_truncate("𑒀ὐ￠🜀\u{1e01b}A a🟠", 6, false),
            "𑒀ὐ￠🜀\u{1e01b}A a🟠",
        );

        // 12 characters, truncation
        assert_eq!(
            dc_truncate("𑒀ὐ￠🜀\u{1e01b}A a🟠bcd", 6, false),
            "𑒀ὐ￠🜀\u{1e01b}A[...]",
        );
    }

    #[test]
    fn test_dc_create_id() {
        let buf = dc_create_id();
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn test_encode_66bits_as_base64() {
        assert_eq!(
            encode_66bits_as_base64(0x01234567, 0x89abcdef, 0),
            "ASNFZ4mrze8"
        );
        assert_eq!(
            encode_66bits_as_base64(0x01234567, 0x89abcdef, 1),
            "ASNFZ4mrze9"
        );
        assert_eq!(
            encode_66bits_as_base64(0x01234567, 0x89abcdef, 2),
            "ASNFZ4mrze-"
        );
        assert_eq!(
            encode_66bits_as_base64(0x01234567, 0x89abcdef, 3),
            "ASNFZ4mrze_"
        );
    }

    #[test]
    #[test]
    fn test_dc_extract_grpid_from_rfc724_mid() {
        // Should return None if we pass invalid mid
        let mid = "foobar";
        let grpid = dc_extract_grpid_from_rfc724_mid(mid);
        assert_eq!(grpid, None);

        // Should return None if grpid has a length which is not 11 or 16
        let mid = "Gr.12345678.morerandom@domain.de";
        let grpid = dc_extract_grpid_from_rfc724_mid(mid);
        assert_eq!(grpid, None);

        // Should return extracted grpid for grpid with length of 11
        let mid = "Gr.12345678901.morerandom@domain.de";
        let grpid = dc_extract_grpid_from_rfc724_mid(mid);
        assert_eq!(grpid, Some("12345678901"));

        // Should return extracted grpid for grpid with length of 11
        let mid = "Gr.1234567890123456.morerandom@domain.de";
        let grpid = dc_extract_grpid_from_rfc724_mid(mid);
        assert_eq!(grpid, Some("1234567890123456"));
    }

    #[test]
    fn test_dc_create_outgoing_rfc724_mid() {
        // create a normal message-id
        let mid = dc_create_outgoing_rfc724_mid(None, "foo@bar.de");
        assert!(mid.starts_with("Mr."));
        assert!(mid.ends_with("bar.de"));
        assert!(dc_extract_grpid_from_rfc724_mid(mid.as_str()).is_none());

        // create a message-id containing a group-id
        let grpid = dc_create_id();
        let mid = dc_create_outgoing_rfc724_mid(Some(&grpid), "foo@bar.de");
        assert!(mid.starts_with("Gr."));
        assert!(mid.ends_with("bar.de"));
        assert_eq!(
            dc_extract_grpid_from_rfc724_mid(mid.as_str()),
            Some(grpid.as_str())
        );
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
        assert_eq!(EmailAddress::new("uuu").is_ok(), false);
        assert_eq!(EmailAddress::new("dd.tt").is_ok(), false);
        assert_eq!(EmailAddress::new("tt.dd@uu").is_ok(), false);
        assert_eq!(EmailAddress::new("u@d").is_ok(), false);
        assert_eq!(EmailAddress::new("u@d.").is_ok(), false);
        assert_eq!(EmailAddress::new("u@d.t").is_ok(), false);
        assert_eq!(
            EmailAddress::new("u@d.tt").unwrap(),
            EmailAddress {
                local: "u".into(),
                domain: "d.tt".into(),
            }
        );
        assert_eq!(EmailAddress::new("u@.tt").is_ok(), false);
        assert_eq!(EmailAddress::new("@d.tt").is_ok(), false);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_dc_truncate(
            buf: String,
            approx_chars in 0..10000usize,
            do_unwrap: bool,
        ) {
            let res = dc_truncate(&buf, approx_chars, do_unwrap);
            let el_len = if do_unwrap { 3 } else { 5 };
            let l = res.chars().count();
            if approx_chars > 0 {
                assert!(
                    l <= approx_chars + el_len,
                    "buf: '{}' - res: '{}' - len {}, approx {}",
                    &buf, &res, res.len(), approx_chars
                );
            } else {
                assert_eq!(&res, &buf);
            }

            if approx_chars > 0 && buf.chars().count() > approx_chars + el_len {
                let l = res.len();
                if do_unwrap {
                    assert_eq!(&res[l-3..l], "...", "missing ellipsis in {}", &res);
                } else {
                    assert_eq!(&res[l-5..l], "[...]", "missing ellipsis in {}", &res);
                }
            }
        }
    }

    #[test]
    fn test_dc_create_incoming_rfc724_mid() {
        let res = dc_create_incoming_rfc724_mid(123, 45, &[6, 7]);
        assert_eq!(res, Some("123-45-7@stub".into()));
        let res = dc_create_incoming_rfc724_mid(123, 45, &[]);
        assert_eq!(res, Some("123-45-0@stub".into()));
    }

    #[test]
    fn test_file_get_safe_basename() {
        assert_eq!(get_safe_basename("12312/hello"), "hello");
        assert_eq!(get_safe_basename("12312\\hello"), "hello");
        assert_eq!(get_safe_basename("//12312\\hello"), "hello");
        assert_eq!(get_safe_basename("//123:12\\hello"), "hello");
        assert_eq!(get_safe_basename("//123:12/\\\\hello"), "hello");
        assert_eq!(get_safe_basename("//123:12//hello"), "hello");
        assert_eq!(get_safe_basename("//123:12//"), "nobasename");
        assert_eq!(get_safe_basename("//123:12/"), "nobasename");
        assert!(get_safe_basename("123\x012.hello").ends_with(".hello"));
    }

    #[test]
    fn test_file_handling() {
        let t = dummy_context();
        let context = &t.ctx;
        let dc_file_exist = |ctx: &Context, fname: &str| {
            ctx.get_blobdir()
                .join(Path::new(fname).file_name().unwrap())
                .exists()
        };

        assert!(!dc_delete_file(context, "$BLOBDIR/lkqwjelqkwlje"));
        if dc_file_exist(context, "$BLOBDIR/foobar")
            || dc_file_exist(context, "$BLOBDIR/dada")
            || dc_file_exist(context, "$BLOBDIR/foobar.dadada")
            || dc_file_exist(context, "$BLOBDIR/foobar-folder")
        {
            dc_delete_file(context, "$BLOBDIR/foobar");
            dc_delete_file(context, "$BLOBDIR/dada");
            dc_delete_file(context, "$BLOBDIR/foobar.dadada");
            dc_delete_file(context, "$BLOBDIR/foobar-folder");
        }
        assert!(dc_write_file(context, "$BLOBDIR/foobar", b"content").is_ok());
        assert!(dc_file_exist(context, "$BLOBDIR/foobar",));
        assert!(!dc_file_exist(context, "$BLOBDIR/foobarx"));
        assert_eq!(dc_get_filebytes(context, "$BLOBDIR/foobar"), 7);

        let abs_path = context
            .get_blobdir()
            .join("foobar")
            .to_string_lossy()
            .to_string();

        assert!(dc_file_exist(context, &abs_path));

        assert!(dc_copy_file(context, "$BLOBDIR/foobar", "$BLOBDIR/dada",));

        // attempting to copy a second time should fail
        assert!(!dc_copy_file(context, "$BLOBDIR/foobar", "$BLOBDIR/dada",));

        assert_eq!(dc_get_filebytes(context, "$BLOBDIR/dada",), 7);

        let buf = dc_read_file(context, "$BLOBDIR/dada").unwrap();

        assert_eq!(buf.len(), 7);
        assert_eq!(&buf, b"content");

        assert!(dc_delete_file(context, "$BLOBDIR/foobar"));
        assert!(dc_delete_file(context, "$BLOBDIR/dada"));
        assert!(dc_create_folder(context, "$BLOBDIR/foobar-folder"));
        assert!(dc_file_exist(context, "$BLOBDIR/foobar-folder",));
        assert!(!dc_delete_file(context, "$BLOBDIR/foobar-folder"));

        let fn0 = "$BLOBDIR/data.data";
        assert!(dc_write_file(context, &fn0, b"content").is_ok());

        assert!(dc_delete_file(context, &fn0));
        assert!(!dc_file_exist(context, &fn0));
    }

    #[test]
    fn test_listflags_has() {
        let listflags: u32 = 0x1101;
        assert!(listflags_has(listflags, 0x1));
        assert!(!listflags_has(listflags, 0x10));
        assert!(listflags_has(listflags, 0x100));
        assert!(listflags_has(listflags, 0x1000));
        let listflags: u32 = (DC_GCL_ADD_SELF | DC_GCL_VERIFIED_ONLY).try_into().unwrap();
        assert!(listflags_has(listflags, DC_GCL_VERIFIED_ONLY));
        assert!(listflags_has(listflags, DC_GCL_ADD_SELF));
        let listflags: u32 = DC_GCL_VERIFIED_ONLY.try_into().unwrap();
        assert!(!listflags_has(listflags, DC_GCL_ADD_SELF));
    }

    #[test]
    fn test_create_smeared_timestamp() {
        let t = dummy_context();
        assert_ne!(
            dc_create_smeared_timestamp(&t.ctx),
            dc_create_smeared_timestamp(&t.ctx)
        );
        assert!(
            dc_create_smeared_timestamp(&t.ctx)
                >= SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
        );
    }

    #[test]
    fn test_create_smeared_timestamps() {
        let t = dummy_context();
        let count = MAX_SECONDS_TO_LEND_FROM_FUTURE - 1;
        let start = dc_create_smeared_timestamps(&t.ctx, count as usize);
        let next = dc_smeared_time(&t.ctx);
        assert!((start + count - 1) < next);

        let count = MAX_SECONDS_TO_LEND_FROM_FUTURE + 30;
        let start = dc_create_smeared_timestamps(&t.ctx, count as usize);
        let next = dc_smeared_time(&t.ctx);
        assert!((start + count - 1) < next);
    }
}
