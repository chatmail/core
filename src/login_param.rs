//! # Login parameters.
//!
//! Login parameters are entered by the user
//! to configure a new transport.
//! Login parameters may also be entered
//! implicitly by scanning a QR code
//! of `dcaccount:` or `dclogin:` scheme.

use std::fmt;

use anyhow::{Context as _, Result};
use num_traits::ToPrimitive as _;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::constants::{DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2};
use crate::context::Context;
pub use crate::net::proxy::ProxyConfig;
pub use crate::provider::Socket;
use crate::tools::ToOption;

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
    /// `Automatic` means that provider database setting should be taken.
    /// If there is no provider database setting for certificate checks,
    /// check certificates strictly.
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

/// Login parameters for a single server, either IMAP or SMTP
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnteredServerLoginParam {
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
    pub imap: EnteredServerLoginParam,

    /// SMTP settings.
    pub smtp: EnteredServerLoginParam,

    /// TLS options: whether to allow invalid certificates and/or
    /// invalid hostnames
    pub certificate_checks: EnteredCertificateChecks,

    /// If true, login via OAUTH2 (not recommended anymore)
    pub oauth2: bool,
}

impl EnteredLoginParam {
    /// Loads entered account settings.
    pub(crate) async fn load(context: &Context) -> Result<Self> {
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
        // while `smtp_certificate_checks` is ignored.
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

        let server_flags = context
            .get_config_parsed::<i32>(Config::ServerFlags)
            .await?
            .unwrap_or_default();
        let oauth2 = matches!(server_flags & DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2);

        Ok(EnteredLoginParam {
            addr,
            imap: EnteredServerLoginParam {
                server: mail_server,
                port: mail_port,
                security: mail_security,
                user: mail_user,
                password: mail_pw,
            },
            smtp: EnteredServerLoginParam {
                server: send_server,
                port: send_port,
                security: send_security,
                user: send_user,
                password: send_pw,
            },
            certificate_checks,
            oauth2,
        })
    }

    /// Saves entered account settings,
    /// so that they can be prefilled if the user wants to configure the server again.
    pub(crate) async fn save(&self, context: &Context) -> Result<()> {
        context.set_config(Config::Addr, Some(&self.addr)).await?;

        context
            .set_config(Config::MailServer, self.imap.server.to_option())
            .await?;
        context
            .set_config(Config::MailPort, self.imap.port.to_option().as_deref())
            .await?;
        context
            .set_config(
                Config::MailSecurity,
                self.imap.security.to_i32().to_option().as_deref(),
            )
            .await?;
        context
            .set_config(Config::MailUser, self.imap.user.to_option())
            .await?;
        context
            .set_config(Config::MailPw, self.imap.password.to_option())
            .await?;

        context
            .set_config(Config::SendServer, self.smtp.server.to_option())
            .await?;
        context
            .set_config(Config::SendPort, self.smtp.port.to_option().as_deref())
            .await?;
        context
            .set_config(
                Config::SendSecurity,
                self.smtp.security.to_i32().to_option().as_deref(),
            )
            .await?;
        context
            .set_config(Config::SendUser, self.smtp.user.to_option())
            .await?;
        context
            .set_config(Config::SendPw, self.smtp.password.to_option())
            .await?;

        context
            .set_config(
                Config::ImapCertificateChecks,
                self.certificate_checks.to_i32().to_option().as_deref(),
            )
            .await?;

        let server_flags = if self.oauth2 {
            Some(DC_LP_AUTH_OAUTH2.to_string())
        } else {
            None
        };
        context
            .set_config(Config::ServerFlags, server_flags.as_deref())
            .await?;

        Ok(())
    }
}

impl fmt::Display for EnteredLoginParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unset = "0";
        let pw = "***";

        write!(
            f,
            "{} imap:{}:{}:{}:{}:{}:{} smtp:{}:{}:{}:{}:{}:{} cert_{}",
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
            if self.oauth2 { "OAUTH2" } else { "AUTH_NORMAL" },
            unset_empty(&self.smtp.user),
            if !self.smtp.password.is_empty() {
                pw
            } else {
                unset
            },
            unset_empty(&self.smtp.server),
            self.smtp.port,
            self.smtp.security,
            if self.oauth2 { "OAUTH2" } else { "AUTH_NORMAL" },
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

        let param = EnteredLoginParam::load(t).await?;
        assert_eq!(param.addr, "alice@example.org");
        assert_eq!(
            param.certificate_checks,
            EnteredCertificateChecks::Automatic
        );

        t.set_config(Config::ImapCertificateChecks, Some("1"))
            .await?;
        let param = EnteredLoginParam::load(t).await?;
        assert_eq!(param.certificate_checks, EnteredCertificateChecks::Strict);

        // Fail to load invalid settings, but do not panic.
        t.set_config(Config::ImapCertificateChecks, Some("999"))
            .await?;
        assert!(EnteredLoginParam::load(t).await.is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_save_entered_login_param() -> Result<()> {
        let t = TestContext::new().await;
        let param = EnteredLoginParam {
            addr: "alice@example.org".to_string(),
            imap: EnteredServerLoginParam {
                server: "".to_string(),
                port: 0,
                security: Socket::Starttls,
                user: "".to_string(),
                password: "foobar".to_string(),
            },
            smtp: EnteredServerLoginParam {
                server: "".to_string(),
                port: 2947,
                security: Socket::default(),
                user: "".to_string(),
                password: "".to_string(),
            },
            certificate_checks: Default::default(),
            oauth2: false,
        };
        param.save(&t).await?;
        assert_eq!(
            t.get_config(Config::Addr).await?.unwrap(),
            "alice@example.org"
        );
        assert_eq!(t.get_config(Config::MailPw).await?.unwrap(), "foobar");
        assert_eq!(t.get_config(Config::SendPw).await?, None);
        assert_eq!(t.get_config_int(Config::SendPort).await?, 2947);

        assert_eq!(EnteredLoginParam::load(&t).await?, param);

        Ok(())
    }
}
