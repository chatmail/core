//! [Provider database](https://providers.delta.chat/) module.

pub(crate) mod data;

use anyhow::Result;
use deltachat_contact_tools::EmailAddress;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{Resolver, TokioResolver, config};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::context::Context;
use crate::log::warn;
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
#[repr(u8)]
pub enum Oauth2Authorizer {
    /// Yandex.
    Yandex = 1,

    /// Gmail.
    Gmail = 2,
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

/// Get resolver to query MX records.
///
/// We first try to read the system's resolver from `/etc/resolv.conf`.
/// This does not work at least on some Androids, therefore we fallback
/// to the default `ResolverConfig` which uses eg. to google's `8.8.8.8` or `8.8.4.4`.
fn get_resolver() -> Result<TokioResolver> {
    if let Ok(resolver) = TokioResolver::builder_tokio() {
        return Ok(resolver.build());
    }
    let resolver = Resolver::builder_with_config(
        config::ResolverConfig::default(),
        TokioConnectionProvider::default(),
    );
    Ok(resolver.build())
}

/// Returns provider for the given an e-mail address.
///
/// Returns an error if provided address is not valid.
pub async fn get_provider_info_by_addr(
    context: &Context,
    addr: &str,
    skip_mx: bool,
) -> Result<Option<&'static Provider>> {
    let addr = EmailAddress::new(addr)?;

    let provider = get_provider_info(context, &addr.domain, skip_mx).await;
    Ok(provider)
}

/// Returns provider for the given domain.
///
/// This function looks up domain in offline database first. If not
/// found, it queries MX record for the domain and looks up offline
/// database for MX domains.
pub async fn get_provider_info(
    context: &Context,
    domain: &str,
    skip_mx: bool,
) -> Option<&'static Provider> {
    if let Some(provider) = get_provider_by_domain(domain) {
        return Some(provider);
    }

    if !skip_mx {
        if let Some(provider) = get_provider_by_mx(context, domain).await {
            return Some(provider);
        }
    }

    None
}

/// Finds a provider in offline database based on domain.
pub fn get_provider_by_domain(domain: &str) -> Option<&'static Provider> {
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

/// Finds a provider based on MX record for the given domain.
///
/// For security reasons, only Gmail can be configured this way.
pub async fn get_provider_by_mx(context: &Context, domain: &str) -> Option<&'static Provider> {
    let Ok(resolver) = get_resolver() else {
        warn!(context, "Cannot get a resolver to check MX records.");
        return None;
    };

    let mut fqdn: String = domain.to_string();
    if !fqdn.ends_with('.') {
        fqdn.push('.');
    }

    let Ok(mx_domains) = resolver.mx_lookup(fqdn).await else {
        warn!(context, "Cannot resolve MX records for {domain:?}.");
        return None;
    };

    for (provider_domain_pattern, provider) in PROVIDER_DATA {
        if provider.id != "gmail" {
            // MX lookup is limited to Gmail for security reasons
            continue;
        }

        if provider_domain_pattern.starts_with('*') {
            // Skip wildcard patterns.
            continue;
        }

        let provider_fqdn = provider_domain_pattern.to_string() + ".";
        let provider_fqdn_dot = ".".to_string() + &provider_fqdn;

        for mx_domain in mx_domains.iter() {
            let mx_domain = mx_domain.exchange().to_lowercase().to_utf8();

            if mx_domain == provider_fqdn || mx_domain.ends_with(&provider_fqdn_dot) {
                return Some(provider);
            }
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
    use crate::test_utils::TestContext;

    #[test]
    fn test_get_provider_by_domain_unexistant() {
        let provider = get_provider_by_domain("unexistant.org");
        assert!(provider.is_none());
    }

    #[test]
    fn test_get_provider_by_domain_mixed_case() {
        let provider = get_provider_by_domain("nAUta.Cu").unwrap();
        assert!(provider.status == Status::Ok);
    }

    #[test]
    fn test_get_provider_by_domain() {
        let addr = "nauta.cu";
        let provider = get_provider_by_domain(addr).unwrap();
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

        let provider = get_provider_by_domain("gmail.com").unwrap();
        assert!(provider.status == Status::Preparation);
        assert!(!provider.before_login_hint.is_empty());
        assert!(!provider.overview_page.is_empty());

        let provider = get_provider_by_domain("googlemail.com").unwrap();
        assert!(provider.status == Status::Preparation);
    }

    #[test]
    fn test_get_provider_by_id() {
        let provider = get_provider_by_id("gmail").unwrap();
        assert!(provider.id == "gmail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_provider_info() {
        let t = TestContext::new().await;
        assert!(get_provider_info(&t, "", false).await.is_none());
        assert!(get_provider_info(&t, "google.com", false).await.unwrap().id == "gmail");
        assert!(
            get_provider_info(&t, "example@google.com", false)
                .await
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_provider_info_by_addr() -> Result<()> {
        let t = TestContext::new().await;
        assert!(
            get_provider_info_by_addr(&t, "google.com", false)
                .await
                .is_err()
        );
        assert!(
            get_provider_info_by_addr(&t, "example@google.com", false)
                .await?
                .unwrap()
                .id
                == "gmail"
        );
        Ok(())
    }

    #[test]
    fn test_get_resolver() -> Result<()> {
        assert!(get_resolver().is_ok());
        Ok(())
    }
}
