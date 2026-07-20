//! Provider types.

use serde::{Deserialize, Serialize};

/// Server protocol.
#[derive(Debug, Display, PartialEq, Eq, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Protocol {
    /// SMTP protocol.
    Smtp = 1,

    /// IMAP protocol.
    Imap = 2,
}

/// Socket security.
#[derive(
    Debug,
    Default,
    Display,
    PartialEq,
    Eq,
    Copy,
    Clone,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum Socket {
    /// Unspecified socket security, select automatically.
    #[default]
    Automatic = 0,

    /// TLS connection.
    Ssl = 1,

    /// STARTTLS connection.
    Starttls = 2,

    /// No TLS, plaintext connection.
    Plain = 3,
}

/// Pattern used to construct login usernames from email addresses.
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum UsernamePattern {
    /// Whole email is used as username.
    Email = 1,

    /// Part of address before `@` is used as username.
    Emaillocalpart = 2,
}
