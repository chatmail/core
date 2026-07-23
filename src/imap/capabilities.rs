//! # IMAP capabilities
//!
//! IMAP server capabilities are determined with a `CAPABILITY` command.
use std::collections::HashMap;

#[derive(Debug)]
pub(crate) struct Capabilities {
    /// True if the server has IDLE capability as defined in
    /// <https://tools.ietf.org/html/rfc2177>
    pub can_idle: bool,

    /// True if the server has MOVE capability as defined in
    /// <https://tools.ietf.org/html/rfc6851>
    pub can_move: bool,

    /// True if the server has QUOTA capability as defined in
    /// <https://tools.ietf.org/html/rfc2087>
    pub can_check_quota: bool,

    /// True if the server has METADATA capability as defined in
    /// <https://tools.ietf.org/html/rfc5464>
    pub can_metadata: bool,

    /// True if the server has COMPRESS=DEFLATE capability as defined in
    /// <https://tools.ietf.org/html/rfc4978>
    pub can_compress: bool,

    /// True if the server has an XCHATMAIL capability
    /// indicating that it is a <https://github.com/deltachat/chatmail> server.
    ///
    /// This can be used to hide some advanced settings in the UI
    /// that are only interesting for normal email accounts,
    /// e.g. the ability to move messages to Delta Chat folder.
    pub is_chatmail: bool,

    /// Server ID if the server supports ID capability.
    pub server_id: Option<HashMap<String, String>>,
}
