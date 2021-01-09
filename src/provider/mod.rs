//! [Provider database](https://providers.delta.chat/) module

mod data;

use crate::config::Config;
use crate::provider::data::{PROVIDER_DATA, PROVIDER_IDS, PROVIDER_UPDATED};
use async_std_resolver::{config, resolver};
use chrono::{NaiveDateTime, NaiveTime};

#[derive(Debug, Display, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Status {
    OK = 1,
    PREPARATION = 2,
    BROKEN = 3,
}

#[derive(Debug, Display, PartialEq, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Protocol {
    SMTP = 1,
    IMAP = 2,
}

#[derive(Debug, Display, PartialEq, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum Socket {
    Automatic = 0,
    SSL = 1,
    STARTTLS = 2,
    Plain = 3,
}

impl Default for Socket {
    fn default() -> Self {
        Socket::Automatic
    }
}

#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum UsernamePattern {
    EMAIL = 1,
    EMAILLOCALPART = 2,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum Oauth2Authorizer {
    Yandex = 1,
    Gmail = 2,
}

#[derive(Debug, Clone)]
pub struct Server {
    pub protocol: Protocol,
    pub socket: Socket,
    pub hostname: &'static str,
    pub port: u16,
    pub username_pattern: UsernamePattern,
}

#[derive(Debug)]
pub struct ConfigDefault {
    pub key: Config,
    pub value: &'static str,
}

#[derive(Debug)]
pub struct Provider {
    /// Unique ID, corresponding to provider database filename.
    pub id: &'static str,
    pub status: Status,
    pub before_login_hint: &'static str,
    pub after_login_hint: &'static str,
    pub overview_page: &'static str,
    pub server: Vec<Server>,
    pub config_defaults: Option<Vec<ConfigDefault>>,
    pub strict_tls: bool,
    pub max_smtp_rcpt_to: Option<u16>,
    pub oauth2_authorizer: Option<Oauth2Authorizer>,
}

/// Returns provider for the given domain.
///
/// This function looks up domain in offline database first. If not
/// found, it queries MX record for the domain and looks up offline
/// database for MX domains.
///
/// For compatibility, email address can be passed to this function
/// instead of the domain.
pub async fn get_provider_info(domain: &str) -> Option<&'static Provider> {
    let domain = domain.rsplitn(2, '@').next()?;

    if let Some(provider) = get_provider_by_domain(domain) {
        return Some(provider);
    }

    if let Some(provider) = get_provider_by_mx(domain).await {
        return Some(provider);
    }

    None
}

/// Finds a provider in offline database based on domain.
pub fn get_provider_by_domain(domain: &str) -> Option<&'static Provider> {
    if let Some(provider) = PROVIDER_DATA.get(domain.to_lowercase().as_str()) {
        return Some(*provider);
    }

    None
}

/// Finds a provider based on MX record for the given domain.
///
/// For security reasons, only Gmail can be configured this way.
pub async fn get_provider_by_mx(domain: impl AsRef<str>) -> Option<&'static Provider> {
    if let Ok(resolver) = resolver(
        config::ResolverConfig::default(),
        config::ResolverOpts::default(),
    )
    .await
    {
        let mut fqdn: String = String::from(domain.as_ref());
        if !fqdn.ends_with('.') {
            fqdn.push('.');
        }

        if let Ok(mx_domains) = resolver.mx_lookup(fqdn).await {
            for (provider_domain, provider) in PROVIDER_DATA.iter() {
                if provider.id != "gmail" {
                    // MX lookup is limited to Gmail for security reasons
                    continue;
                }

                let provider_fqdn = provider_domain.to_string() + ".";
                let provider_fqdn_dot = ".".to_string() + &provider_fqdn;

                for mx_domain in mx_domains.iter() {
                    let mx_domain = mx_domain.exchange().to_lowercase().to_utf8();

                    if mx_domain == provider_fqdn || mx_domain.ends_with(&provider_fqdn_dot) {
                        return Some(provider);
                    }
                }
            }
        }
    }

    None
}

pub fn get_provider_by_id(id: &str) -> Option<&'static Provider> {
    if let Some(provider) = PROVIDER_IDS.get(id) {
        Some(&provider)
    } else {
        None
    }
}

// returns update timestamp in seconds, UTC, compatible for comparison with time() and database times
pub fn get_provider_update_timestamp() -> i64 {
    NaiveDateTime::new(*PROVIDER_UPDATED, NaiveTime::from_hms(0, 0, 0)).timestamp_millis() / 1_000
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::dc_tools::time;
    use chrono::NaiveDate;

    #[test]
    fn test_get_provider_by_domain_unexistant() {
        let provider = get_provider_by_domain("unexistant.org");
        assert!(provider.is_none());
    }

    #[test]
    fn test_get_provider_by_domain_mixed_case() {
        let provider = get_provider_by_domain("nAUta.Cu").unwrap();
        assert!(provider.status == Status::OK);
    }

    #[test]
    fn test_get_provider_by_domain() {
        let addr = "nauta.cu";
        let provider = get_provider_by_domain(addr).unwrap();
        assert!(provider.status == Status::OK);
        let server = &provider.server[0];
        assert_eq!(server.protocol, Protocol::IMAP);
        assert_eq!(server.socket, Socket::STARTTLS);
        assert_eq!(server.hostname, "imap.nauta.cu");
        assert_eq!(server.port, 143);
        assert_eq!(server.username_pattern, UsernamePattern::EMAIL);
        let server = &provider.server[1];
        assert_eq!(server.protocol, Protocol::SMTP);
        assert_eq!(server.socket, Socket::STARTTLS);
        assert_eq!(server.hostname, "smtp.nauta.cu");
        assert_eq!(server.port, 25);
        assert_eq!(server.username_pattern, UsernamePattern::EMAIL);

        let provider = get_provider_by_domain("gmail.com").unwrap();
        assert!(provider.status == Status::PREPARATION);
        assert!(!provider.before_login_hint.is_empty());
        assert!(!provider.overview_page.is_empty());

        let provider = get_provider_by_domain("googlemail.com").unwrap();
        assert!(provider.status == Status::PREPARATION);
    }

    #[test]
    fn test_get_provider_by_id() {
        let provider = get_provider_by_id("gmail").unwrap();
        assert!(provider.id == "gmail");
    }

    #[async_std::test]
    async fn test_get_provider_info() {
        assert!(get_provider_info("").await.is_none());
        assert!(get_provider_info("google.com").await.unwrap().id == "gmail");

        // get_provider_info() accepts email addresses for backwards compatibility
        assert!(get_provider_info("example@google.com").await.unwrap().id == "gmail");
    }

    #[test]
    fn test_get_provider_update_timestamp() {
        let timestamp_past = NaiveDateTime::new(
            NaiveDate::from_ymd(2020, 9, 9),
            NaiveTime::from_hms(0, 0, 0),
        )
        .timestamp_millis()
            / 1_000;
        assert!(get_provider_update_timestamp() <= time());
        assert!(get_provider_update_timestamp() > timestamp_past);
    }
}
