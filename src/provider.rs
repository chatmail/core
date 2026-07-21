//! Provider types.

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

/// Pattern used to construct login usernames from email addresses.
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum UsernamePattern {
    /// Whole email is used as username.
    Email = 1,

    /// Part of address before `@` is used as username.
    Emaillocalpart = 2,
}

/// Returns true if `domain` is `suffix` itself or a subdomain of it.
fn is_exact_or_subdomain(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

/// Non-default settings that used to be looked up in provider.db for a few domains.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct LegacyProviderSettings {
    /// Servers to use instead of autoconfig, if any.
    pub autoconfig_servers: Option<Vec<ServerParams>>,

    /// Maximum number of recipients allowed in a single SMTP send, if limited.
    pub max_smtp_rcpt_to: Option<usize>,

    /// Whether to disable strict TLS certificate checks by default.
    pub disable_strict_tls: bool,

    /// Whether to disable local network contact discovery (mDNS) by default.
    pub disable_mdns: bool,

    /// Whether to default to worse media quality (for slow/expensive connections).
    pub worse_media_quality: bool,
}

/// Returns hard-coded legacy settings for the domain of `addr`.
///
/// Provider.db lookup was removed, but a handful of domains still need these overrides,
/// so they are hard-coded here instead.
pub(crate) fn legacy_settings_for_addr(addr: &str) -> LegacyProviderSettings {
    let Ok(email) = EmailAddress::new(addr) else {
        return LegacyProviderSettings::default();
    };
    let domain = email.domain.to_ascii_lowercase();

    match domain.as_str() {
        "nauta.cu" => LegacyProviderSettings {
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
            ..Default::default()
        },
        _ if is_exact_or_subdomain(&domain, "hermes.radio")
            || domain.ends_with(".aco-connexion.org") =>
        {
            LegacyProviderSettings {
                disable_strict_tls: true,
                disable_mdns: true,
                ..Default::default()
            }
        }
        _ => LegacyProviderSettings {
            autoconfig_servers: None,
            max_smtp_rcpt_to: None,
            disable_strict_tls: false,
            disable_mdns: false,
            worse_media_quality: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_domain_overrides() {
        let nauta = legacy_settings_for_addr("alice@nauta.cu");
        assert_eq!(nauta.max_smtp_rcpt_to, Some(20));
        assert!(nauta.disable_strict_tls);
        assert!(nauta.worse_media_quality);
        let servers = nauta.autoconfig_servers.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].hostname, "imap.nauta.cu");
        assert_eq!(servers[1].hostname, "smtp.nauta.cu");

        let hermes = legacy_settings_for_addr("alice@foo.hermes.radio");
        assert!(hermes.disable_strict_tls);
        assert!(hermes.disable_mdns);
        // hermes.radio itself (not just its subdomains) is also a valid provider domain.
        assert!(legacy_settings_for_addr("alice@hermes.radio").disable_strict_tls);

        let aco = legacy_settings_for_addr("alice@foo.aco-connexion.org");
        assert!(aco.disable_strict_tls);
        assert!(aco.disable_mdns);
        // Unlike hermes.radio, aco-connexion.org itself is not a valid provider domain,
        // only its subdomains are (matching the original provider.db entries).
        let not_aco = legacy_settings_for_addr("alice@aco-connexion.org");
        assert_eq!(not_aco.autoconfig_servers, None);
        assert_eq!(not_aco.max_smtp_rcpt_to, None);
        assert!(!not_aco.disable_strict_tls);
        assert!(!not_aco.disable_mdns);
        assert!(!not_aco.worse_media_quality);

        let unknown = legacy_settings_for_addr("alice@example.org");
        assert_eq!(unknown.autoconfig_servers, None);
        assert_eq!(unknown.max_smtp_rcpt_to, None);
        assert!(!unknown.disable_strict_tls);
        assert!(!unknown.disable_mdns);
        assert!(!unknown.worse_media_quality);
    }
}
