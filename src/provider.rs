//! [Provider database](https://providers.delta.chat/) module.

pub(crate) mod data;

use anyhow::Result;
use deltachat_contact_tools::EmailAddress;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::provider::data::{PROVIDER_DATA, PROVIDER_IDS};

/// Provider status according to manual testing.
#[derive(Debug, Display, Copy, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Status {
    /// Provider is known to be working with Delta Chat.
    Ok = 1,

    /// Provider works with Delta Chat, but requires some preparation,
    /// such as changing the settings in the web interface.
    Preparation = 2,

    /// Provider is known not to work with Delta Chat.
    Broken = 3,
}

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

/// Type of OAuth 2 authorization.
#[derive(Debug, PartialEq, Eq)]
pub enum Oauth2Authorizer {
    /// Yandex.
    Yandex,
}

/// Email server endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Server protocol, e.g. SMTP or IMAP.
    pub protocol: Protocol,

    /// Port security, e.g. TLS or STARTTLS.
    pub socket: Socket,

    /// Server host.
    pub hostname: &'static str,

    /// Server port.
    pub port: u16,

    /// Pattern used to construct login usernames from email addresses.
    pub username_pattern: UsernamePattern,
}

/// Pair of key and value for default configuration.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigDefault {
    /// Configuration variable name.
    pub key: Config,

    /// Configuration variable value.
    pub value: &'static str,
}

/// Provider database entry.
#[derive(Debug, PartialEq, Eq)]
pub struct Provider {
    /// Unique ID, corresponding to provider database filename.
    pub id: &'static str,

    /// Provider status according to manual testing.
    pub status: Status,

    /// Hint to be shown to the user on the login screen.
    pub before_login_hint: &'static str,

    /// Hint to be added to the device chat after provider configuration.
    pub after_login_hint: &'static str,

    /// URL of the page with provider overview.
    pub overview_page: &'static str,

    /// List of provider servers.
    pub server: &'static [Server],

    /// Default configuration values to set when provider is configured.
    pub config_defaults: Option<&'static [ConfigDefault]>,

    /// Type of OAuth 2 authorization if provider supports it.
    pub oauth2_authorizer: Option<Oauth2Authorizer>,

    /// Options with good defaults.
    pub opt: ProviderOptions,
}

/// Provider options with good defaults.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderOptions {
    /// True if provider is known to use use proper,
    /// not self-signed certificates.
    pub strict_tls: bool,

    /// Maximum number of recipients the provider allows to send a single email to.
    pub max_smtp_rcpt_to: Option<u16>,

    /// Move messages to the Trash folder instead of marking them "\Deleted".
    pub delete_to_trash: bool,
}

impl ProviderOptions {
    const fn new() -> Self {
        Self {
            strict_tls: true,
            max_smtp_rcpt_to: None,
            delete_to_trash: false,
        }
    }
}

/// Returns provider for the given an e-mail address.
///
/// Returns an error if provided address is not valid.
pub fn get_provider_info_by_addr(addr: &str) -> Result<Option<&'static Provider>> {
    let addr = EmailAddress::new(addr)?;

    Ok(get_provider_info(&addr.domain))
}

/// Finds a provider in offline database based on domain.
pub fn get_provider_info(domain: &str) -> Option<&'static Provider> {
    let domain = domain.to_lowercase();
    for (pattern, provider) in PROVIDER_DATA {
        if let Some(suffix) = pattern.strip_prefix('*') {
            // Wildcard domain pattern.
            //
            // For example, `suffix` is ".hermes.radio" for "*.hermes.radio" pattern.
            if domain.ends_with(suffix) {
                return Some(provider);
            }
        } else if pattern == domain {
            return Some(provider);
        }
    }

    None
}

/// Returns a provider with the given ID from the database.
pub fn get_provider_by_id(id: &str) -> Option<&'static Provider> {
    if let Some(provider) = PROVIDER_IDS.get(id) {
        Some(provider)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_provider_by_domain_unexistant() {
        let provider = get_provider_info("unexistant.org");
        assert!(provider.is_none());
    }

    #[test]
    fn test_get_provider_by_domain_mixed_case() {
        let provider = get_provider_info("nAUta.Cu").unwrap();
        assert!(provider.status == Status::Ok);
    }

    #[test]
    fn test_get_provider_info() {
        let addr = "nauta.cu";
        let provider = get_provider_info(addr).unwrap();
        assert!(provider.status == Status::Ok);
        let server = &provider.server[0];
        assert_eq!(server.protocol, Protocol::Imap);
        assert_eq!(server.socket, Socket::Starttls);
        assert_eq!(server.hostname, "imap.nauta.cu");
        assert_eq!(server.port, 143);
        assert_eq!(server.username_pattern, UsernamePattern::Email);
        let server = &provider.server[1];
        assert_eq!(server.protocol, Protocol::Smtp);
        assert_eq!(server.socket, Socket::Starttls);
        assert_eq!(server.hostname, "smtp.nauta.cu");
        assert_eq!(server.port, 25);
        assert_eq!(server.username_pattern, UsernamePattern::Email);

        let provider = get_provider_info("gmail.com").unwrap();
        assert!(provider.status == Status::Preparation);
        assert!(!provider.before_login_hint.is_empty());
        assert!(!provider.overview_page.is_empty());

        let provider = get_provider_info("googlemail.com").unwrap();
        assert!(provider.status == Status::Preparation);

        assert!(get_provider_info("").is_none());
        assert!(get_provider_info("google.com").unwrap().id == "gmail");
        assert!(get_provider_info("example@google.com").is_none());
    }

    #[test]
    fn test_get_provider_by_id() {
        let provider = get_provider_by_id("gmail").unwrap();
        assert!(provider.id == "gmail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_provider_info_by_addr() -> Result<()> {
        assert!(get_provider_info_by_addr("google.com").is_err());
        assert!(get_provider_info_by_addr("example@google.com")?.unwrap().id == "gmail");
        Ok(())
    }
}
