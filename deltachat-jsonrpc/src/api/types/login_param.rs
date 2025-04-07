use anyhow::Result;
use deltachat::login_param as dc;
use serde::Deserialize;
use serde::Serialize;
use yerpc::TypeDef;

/// Login parameters entered by the user.
///
/// Usually it will be enough to only set `addr` and `password`,
/// and all the other settings will be autoconfigured.
#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnteredLoginParam {
    /// Email address.
    pub addr: String,

    /// Password.
    pub password: String,

    /// Imap server hostname or IP address.
    pub imap_server: Option<String>,

    /// Imap server port.
    pub imap_port: Option<u16>,

    /// Imap socket security.
    pub imap_security: Option<Socket>,

    /// Imap username.
    pub imap_user: Option<String>,

    /// SMTP server hostname or IP address.
    pub smtp_server: Option<String>,

    /// SMTP server port.
    pub smtp_port: Option<u16>,

    /// SMTP socket security.
    pub smtp_security: Option<Socket>,

    /// SMTP username.
    pub smtp_user: Option<String>,

    /// SMTP Password.
    ///
    /// Only needs to be specified if different than IMAP password.
    pub smtp_password: Option<String>,

    /// TLS options: whether to allow invalid certificates and/or
    /// invalid hostnames.
    /// Default: Automatic
    pub certificate_checks: Option<EnteredCertificateChecks>,

    /// If true, login via OAUTH2 (not recommended anymore).
    /// Default: false
    pub oauth2: Option<bool>,
}

impl From<dc::EnteredLoginParam> for EnteredLoginParam {
    fn from(param: dc::EnteredLoginParam) -> Self {
        let imap_security: Socket = param.imap.security.into();
        let smtp_security: Socket = param.smtp.security.into();
        let certificate_checks: EnteredCertificateChecks = param.certificate_checks.into();
        Self {
            addr: param.addr,
            password: param.imap.password,
            imap_server: param.imap.server.into_option(),
            imap_port: param.imap.port.into_option(),
            imap_security: imap_security.into_option(),
            imap_user: param.imap.user.into_option(),
            smtp_server: param.smtp.server.into_option(),
            smtp_port: param.smtp.port.into_option(),
            smtp_security: smtp_security.into_option(),
            smtp_user: param.smtp.user.into_option(),
            smtp_password: param.smtp.password.into_option(),
            certificate_checks: certificate_checks.into_option(),
            oauth2: param.oauth2.into_option(),
        }
    }
}

impl TryFrom<EnteredLoginParam> for dc::EnteredLoginParam {
    type Error = anyhow::Error;

    fn try_from(param: EnteredLoginParam) -> Result<Self> {
        Ok(Self {
            addr: param.addr,
            imap: dc::EnteredServerLoginParam {
                server: param.imap_server.unwrap_or_default(),
                port: param.imap_port.unwrap_or_default(),
                security: param.imap_security.unwrap_or_default().into(),
                user: param.imap_user.unwrap_or_default(),
                password: param.password,
            },
            smtp: dc::EnteredServerLoginParam {
                server: param.smtp_server.unwrap_or_default(),
                port: param.smtp_port.unwrap_or_default(),
                security: param.smtp_security.unwrap_or_default().into(),
                user: param.smtp_user.unwrap_or_default(),
                password: param.smtp_password.unwrap_or_default(),
            },
            certificate_checks: param.certificate_checks.unwrap_or_default().into(),
            oauth2: param.oauth2.unwrap_or_default(),
        })
    }
}

#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Socket {
    /// Unspecified socket security, select automatically.
    #[default]
    Automatic,

    /// TLS connection.
    Ssl,

    /// STARTTLS connection.
    Starttls,

    /// No TLS, plaintext connection.
    Plain,
}

impl From<dc::Socket> for Socket {
    fn from(value: dc::Socket) -> Self {
        match value {
            dc::Socket::Automatic => Self::Automatic,
            dc::Socket::Ssl => Self::Ssl,
            dc::Socket::Starttls => Self::Starttls,
            dc::Socket::Plain => Self::Plain,
        }
    }
}

impl From<Socket> for dc::Socket {
    fn from(value: Socket) -> Self {
        match value {
            Socket::Automatic => Self::Automatic,
            Socket::Ssl => Self::Ssl,
            Socket::Starttls => Self::Starttls,
            Socket::Plain => Self::Plain,
        }
    }
}

#[derive(Serialize, Deserialize, TypeDef, schemars::JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EnteredCertificateChecks {
    /// `Automatic` means that provider database setting should be taken.
    /// If there is no provider database setting for certificate checks,
    /// check certificates strictly.
    #[default]
    Automatic,

    /// Ensure that TLS certificate is valid for the server hostname.
    Strict,

    /// Accept certificates that are expired, self-signed
    /// or otherwise not valid for the server hostname.
    AcceptInvalidCertificates,
}

impl From<dc::EnteredCertificateChecks> for EnteredCertificateChecks {
    fn from(value: dc::EnteredCertificateChecks) -> Self {
        match value {
            dc::EnteredCertificateChecks::Automatic => Self::Automatic,
            dc::EnteredCertificateChecks::Strict => Self::Strict,
            dc::EnteredCertificateChecks::AcceptInvalidCertificates => {
                Self::AcceptInvalidCertificates
            }
            dc::EnteredCertificateChecks::AcceptInvalidCertificates2 => {
                Self::AcceptInvalidCertificates
            }
        }
    }
}

impl From<EnteredCertificateChecks> for dc::EnteredCertificateChecks {
    fn from(value: EnteredCertificateChecks) -> Self {
        match value {
            EnteredCertificateChecks::Automatic => Self::Automatic,
            EnteredCertificateChecks::Strict => Self::Strict,
            EnteredCertificateChecks::AcceptInvalidCertificates => Self::AcceptInvalidCertificates,
        }
    }
}

trait IntoOption<T> {
    fn into_option(self) -> Option<T>;
}
impl<T> IntoOption<T> for T
where
    T: Default + std::cmp::PartialEq,
{
    fn into_option(self) -> Option<T> {
        if self == T::default() {
            None
        } else {
            Some(self)
        }
    }
}
