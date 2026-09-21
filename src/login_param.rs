//! # Login parameters.
//!
//! Login parameters are entered by the user
//! to configure a new transport.
//! Login parameters may also be entered
//! implicitly by scanning a QR code
//! of `dcaccount:` or `dclogin:` scheme.

use std::fmt;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::context::Context;
pub use crate::net::proxy::ProxyConfig;
pub use crate::provider::Socket;

/// User-entered setting for certificate checks.
///
/// Should be saved into `imap_certificate_checks` before running configuration.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Display,
    FromPrimitive,
    ToPrimitive,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum EnteredCertificateChecks {
    /// `Automatic` means strict certificate checks,
    /// unless a legacy-domain override disables them.
    #[default]
    Automatic = 0,

    /// Ensure that TLS certificate is valid for the server hostname.
    Strict = 1,

    /// Accept certificates that are expired, self-signed
    /// or otherwise not valid for the server hostname.
    AcceptInvalidCertificates = 2,

    /// Alias for `AcceptInvalidCertificates`
    /// for API compatibility.
    AcceptInvalidCertificates2 = 3,
}

impl EnteredCertificateChecks {
    pub(crate) fn accept_invalid_certificates(self) -> bool {
        matches!(
            self,
            Self::AcceptInvalidCertificates | Self::AcceptInvalidCertificates2
        )
    }
}

/// Login parameters for a single IMAP server.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnteredImapLoginParam {
    /// Server hostname or IP address.
    pub server: String,

    /// Server port.
    ///
    /// 0 if not specified.
    pub port: u16,

    /// Folder to watch.
    ///
    /// If empty, user has not entered anything and it shuold expand to "INBOX" later.
    #[serde(default)]
    pub folder: String,

    /// Socket security.
    pub security: Socket,

    /// Username.
    ///
    /// Empty string if not specified.
    pub user: String,

    /// Password.
    pub password: String,
}

/// Login parameters for a single SMTP server.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnteredSmtpLoginParam {
    /// Server hostname or IP address.
    pub server: String,

    /// Server port.
    ///
    /// 0 if not specified.
    pub port: u16,

    /// Socket security.
    pub security: Socket,

    /// Username.
    ///
    /// Empty string if not specified.
    pub user: String,

    /// Password.
    pub password: String,
}

/// Login parameters entered by the user.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnteredLoginParam {
    /// Email address.
    pub addr: String,

    /// IMAP settings.
    pub imap: EnteredImapLoginParam,

    /// SMTP settings.
    pub smtp: EnteredSmtpLoginParam,

    /// TLS options: whether to allow invalid certificates and/or
    /// invalid hostnames
    pub certificate_checks: EnteredCertificateChecks,

    /// Deprecated 2026-07, always false
    #[serde(default)]
    pub oauth2: bool,
}

impl EnteredLoginParam {
    /// Loads entered account settings
    /// that were set by the deprecated `configured_*` configs.
    ///
    /// This is only needed by tests and clients using the old CFFI API.
    pub(crate) async fn load_legacy(context: &Context) -> Result<Self> {
        let addr = context
            .get_config(Config::Addr)
            .await?
            .unwrap_or_default()
            .trim()
            .to_string();

        let mail_server = context
            .get_config(Config::MailServer)
            .await?
            .unwrap_or_default();
        let mail_port = context
            .get_config_parsed::<u16>(Config::MailPort)
            .await?
            .unwrap_or_default();

        // There is no way to set custom folder with this legacy API.
        let mail_folder = String::new();

        let mail_security = context
            .get_config_parsed::<i32>(Config::MailSecurity)
            .await?
            .and_then(num_traits::FromPrimitive::from_i32)
            .unwrap_or_default();
        let mail_user = context
            .get_config(Config::MailUser)
            .await?
            .unwrap_or_default();
        let mail_pw = context
            .get_config(Config::MailPw)
            .await?
            .unwrap_or_default();

        // The setting is named `imap_certificate_checks`
        // for backwards compatibility,
        // but now it is a global setting applied to all protocols,
        // while `smtp_certificate_checks` has been removed.
        let certificate_checks = if let Some(certificate_checks) = context
            .get_config_parsed::<i32>(Config::ImapCertificateChecks)
            .await?
        {
            num_traits::FromPrimitive::from_i32(certificate_checks)
                .context("Unknown imap_certificate_checks value")?
        } else {
            Default::default()
        };

        let send_server = context
            .get_config(Config::SendServer)
            .await?
            .unwrap_or_default();
        let send_port = context
            .get_config_parsed::<u16>(Config::SendPort)
            .await?
            .unwrap_or_default();
        let send_security = context
            .get_config_parsed::<i32>(Config::SendSecurity)
            .await?
            .and_then(num_traits::FromPrimitive::from_i32)
            .unwrap_or_default();
        let send_user = context
            .get_config(Config::SendUser)
            .await?
            .unwrap_or_default();
        let send_pw = context
            .get_config(Config::SendPw)
            .await?
            .unwrap_or_default();

        Ok(EnteredLoginParam {
            addr,
            imap: EnteredImapLoginParam {
                server: mail_server,
                port: mail_port,
                folder: mail_folder,
                security: mail_security,
                user: mail_user,
                password: mail_pw,
            },
            smtp: EnteredSmtpLoginParam {
                server: send_server,
                port: send_port,
                security: send_security,
                user: send_user,
                password: send_pw,
            },
            certificate_checks,
            oauth2: false,
        })
    }
}

impl fmt::Display for EnteredLoginParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unset = "0";
        let pw = "***";

        write!(
            f,
            "{} imap:{}:{}:{}:{}:{} smtp:{}:{}:{}:{}:{} cert_{}",
            unset_empty(&self.addr),
            unset_empty(&self.imap.user),
            if !self.imap.password.is_empty() {
                pw
            } else {
                unset
            },
            unset_empty(&self.imap.server),
            self.imap.port,
            self.imap.security,
            unset_empty(&self.smtp.user),
            if !self.smtp.password.is_empty() {
                pw
            } else {
                unset
            },
            unset_empty(&self.smtp.server),
            self.smtp.port,
            self.smtp.security,
            self.certificate_checks
        )
    }
}

fn unset_empty(s: &str) -> &str {
    if s.is_empty() { "unset" } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestContext;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_entered_certificate_checks_display() {
        use std::string::ToString;

        assert_eq!(
            "accept_invalid_certificates".to_string(),
            EnteredCertificateChecks::AcceptInvalidCertificates.to_string()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_entered_login_param() -> Result<()> {
        let t = &TestContext::new().await;

        t.set_config(Config::Addr, Some("alice@example.org"))
            .await?;
        t.set_config(Config::MailPw, Some("foobarbaz")).await?;

        let param = EnteredLoginParam::load_legacy(t).await?;
        assert_eq!(param.addr, "alice@example.org");
        assert_eq!(
            param.certificate_checks,
            EnteredCertificateChecks::Automatic
        );

        t.set_config(Config::ImapCertificateChecks, Some("1"))
            .await?;
        let param = EnteredLoginParam::load_legacy(t).await?;
        assert_eq!(param.certificate_checks, EnteredCertificateChecks::Strict);

        // Fail to load invalid settings, but do not panic.
        t.set_config(Config::ImapCertificateChecks, Some("999"))
            .await?;
        assert!(EnteredLoginParam::load_legacy(t).await.is_err());

        Ok(())
    }
}
