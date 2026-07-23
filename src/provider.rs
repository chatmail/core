//! Provider types.

use anyhow::Result;
use deltachat_contact_tools::EmailAddress;
use serde::{Deserialize, Serialize};

use crate::configure::server_params::ServerParams;

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

/// Non-default settings that used to be looked up in provider.db for a few domains.
#[derive(Debug, Default)]
pub(crate) struct LegacyProviderSettings {
    /// Servers to use instead of autoconfig, if any.
    pub autoconfig_servers: Option<Vec<ServerParams>>,

    /// Maximum number of recipients allowed in a single SMTP send, if limited.
    pub max_smtp_rcpt_to: Option<u32>,

    /// Whether to disable strict TLS certificate checks by default.
    pub disable_strict_tls: bool,

    /// Whether to default to worse media quality (for slow/expensive connections).
    pub worse_media_quality: bool,
}

/// Returns hard-coded legacy settings for the domain of `addr`.
pub(crate) fn legacy_settings_for_addr(addr: &str) -> Result<LegacyProviderSettings> {
    if !EmailAddress::new(addr)?
        .domain
        .eq_ignore_ascii_case("nauta.cu")
    {
        return Ok(LegacyProviderSettings::default());
    }
    Ok(LegacyProviderSettings {
        autoconfig_servers: Some(vec![
            ServerParams {
                protocol: Protocol::Imap,
                socket: Socket::Starttls,
                hostname: "imap.nauta.cu".to_string(),
                port: 143,
                username: String::new(),
            },
            ServerParams {
                protocol: Protocol::Smtp,
                socket: Socket::Starttls,
                hostname: "smtp.nauta.cu".to_string(),
                port: 25,
                username: String::new(),
            },
        ]),
        max_smtp_rcpt_to: Some(20),
        disable_strict_tls: true,
        worse_media_quality: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_domain_overrides() -> Result<()> {
        let nauta = legacy_settings_for_addr("alice@nauta.cu")?;
        assert_eq!(nauta.max_smtp_rcpt_to, Some(20));
        assert!(nauta.disable_strict_tls);
        assert!(nauta.worse_media_quality);
        let servers = nauta.autoconfig_servers.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].hostname, "imap.nauta.cu");
        assert_eq!(servers[1].hostname, "smtp.nauta.cu");

        let unknown = legacy_settings_for_addr("alice@example.org")?;
        assert_eq!(unknown.autoconfig_servers, None);
        assert_eq!(unknown.max_smtp_rcpt_to, None);
        assert!(!unknown.disable_strict_tls);
        assert!(!unknown.worse_media_quality);

        assert!(legacy_settings_for_addr("not-an-email").is_err());
        Ok(())
    }
}
