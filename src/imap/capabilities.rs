//! # IMAP capabilities
//!
//! IMAP server capabilities are determined with a `CAPABILITY` command.
use std::collections::HashMap;

#[derive(Debug)]
pub(crate) struct Capabilities {
    /// True if the server has IDLE capability as defined in
    /// <https://tools.ietf.org/html/rfc2177>
    pub can_idle: bool,

    /// True if the server has QUOTA capability as defined in
    /// <https://tools.ietf.org/html/rfc2087>
    pub can_check_quota: bool,

    /// True if the server has METADATA capability as defined in
    /// <https://tools.ietf.org/html/rfc5464>
    pub can_metadata: bool,

    /// True if the server has COMPRESS=DEFLATE capability as defined in
    /// <https://tools.ietf.org/html/rfc4978>
    pub can_compress: bool,

    /// Server ID if the server supports ID capability.
    pub server_id: Option<HashMap<String, String>>,
}
