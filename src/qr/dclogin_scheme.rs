use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};

use deltachat_contact_tools::may_be_valid_addr;

use super::{DCLOGIN_SCHEME, Qr};
use crate::login_param::{EnteredCertificateChecks, EnteredLoginParam, EnteredServerLoginParam};
use crate::provider::Socket;

/// Options for `dclogin:` scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOptions {
    /// Unsupported version.
    UnsuportedVersion(u32),

    /// Version 1.
    V1 {
        /// IMAP server password.
        ///
        /// Used for SMTP if separate SMTP password is not provided.
        mail_pw: String,

        /// IMAP host.
        imap_host: Option<String>,

        /// IMAP port.
        imap_port: Option<u16>,

        /// IMAP username.
        imap_username: Option<String>,

        /// IMAP password.
        imap_password: Option<String>,

        /// IMAP socket security.
        imap_security: Option<Socket>,

        /// SMTP host.
        smtp_host: Option<String>,

        /// SMTP port.
        smtp_port: Option<u16>,

        /// SMTP username.
        smtp_username: Option<String>,

        /// SMTP password.
        smtp_password: Option<String>,

        /// SMTP socket security.
        smtp_security: Option<Socket>,

        /// Certificate checks.
        certificate_checks: Option<EnteredCertificateChecks>,
    },
}

/// scheme: `dclogin://user@host/?p=password&v=1[&options]`
/// read more about the scheme at <https://github.com/deltachat/interface/blob/master/uri-schemes.md#DCLOGIN>
pub(super) fn decode_login(qr: &str) -> Result<Qr> {
    let qr = qr.replacen("://", ":", 1);

    let url = url::Url::parse(&qr).with_context(|| format!("Malformed url: {qr:?}"))?;
    let payload = qr
        .get(DCLOGIN_SCHEME.len()..)
        .context("invalid DCLOGIN payload E1")?;

    let addr = payload
        .split(['?', '/'])
        .next()
        .context("invalid DCLOGIN payload E3")?;

    if url.scheme().eq_ignore_ascii_case("dclogin") {
        let options = url.query_pairs();
        if options.count() == 0 {
            bail!("invalid DCLOGIN payload E4")
        }
        // load options into hashmap
        let parameter_map: HashMap<String, String> = options
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();

        // check if username is there
        if !may_be_valid_addr(addr) {
            bail!("invalid DCLOGIN payload: invalid username E5");
        }

        // apply to result struct
        let options: LoginOptions = match parameter_map.get("v").map(|i| i.parse::<u32>()) {
            Some(Ok(1)) => LoginOptions::V1 {
                mail_pw: parameter_map
                    .get("p")
                    .map(|s| s.to_owned())
                    .context("password missing")?,
                imap_host: parameter_map.get("ih").map(|s| s.to_owned()),
                imap_port: parse_port(parameter_map.get("ip"))
                    .context("could not parse imap port")?,
                imap_username: parameter_map.get("iu").map(|s| s.to_owned()),
                imap_password: parameter_map.get("ipw").map(|s| s.to_owned()),
                imap_security: parse_socket_security(parameter_map.get("is"))?,
                smtp_host: parameter_map.get("sh").map(|s| s.to_owned()),
                smtp_port: parse_port(parameter_map.get("sp"))
                    .context("could not parse smtp port")?,
                smtp_username: parameter_map.get("su").map(|s| s.to_owned()),
                smtp_password: parameter_map.get("spw").map(|s| s.to_owned()),
                smtp_security: parse_socket_security(parameter_map.get("ss"))?,
                certificate_checks: parse_certificate_checks(parameter_map.get("ic"))?,
            },
            Some(Ok(v)) => LoginOptions::UnsuportedVersion(v),
            Some(Err(_)) => bail!("version could not be parsed as number E6"),
            None => bail!("invalid DCLOGIN payload: version missing E7"),
        };

        Ok(Qr::Login {
            address: addr.to_owned(),
            options,
        })
    } else {
        bail!("Bad scheme for account URL: {payload:?}.");
    }
}

fn parse_port(port: Option<&String>) -> core::result::Result<Option<u16>, std::num::ParseIntError> {
    match port {
        Some(p) => Ok(Some(p.parse::<u16>()?)),
        None => Ok(None),
    }
}

fn parse_socket_security(security: Option<&String>) -> Result<Option<Socket>> {
    Ok(match security.map(|s| s.as_str()) {
        Some("ssl") => Some(Socket::Ssl),
        Some("starttls") => Some(Socket::Starttls),
        Some("default") => Some(Socket::Automatic),
        Some("plain") => Some(Socket::Plain),
        Some(other) => bail!("Unknown security level: {other}"),
        None => None,
    })
}

fn parse_certificate_checks(
    certificate_checks: Option<&String>,
) -> Result<Option<EnteredCertificateChecks>> {
    Ok(match certificate_checks.map(|s| s.as_str()) {
        Some("0") => Some(EnteredCertificateChecks::Automatic),
        Some("1") => Some(EnteredCertificateChecks::Strict),
        Some("2") => Some(EnteredCertificateChecks::AcceptInvalidCertificates),
        Some("3") => Some(EnteredCertificateChecks::AcceptInvalidCertificates2),
        Some(other) => bail!("Unknown certificatecheck level: {other}"),
        None => None,
    })
}

pub(crate) fn login_param_from_login_qr(
    addr: &str,
    options: LoginOptions,
) -> Result<EnteredLoginParam> {
    match options {
        LoginOptions::V1 {
            mail_pw,
            imap_host,
            imap_port,
            imap_username,
            imap_password,
            imap_security,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_security,
            certificate_checks,
        } => {
            let param = EnteredLoginParam {
                addr: addr.to_string(),
                imap: EnteredServerLoginParam {
                    server: imap_host.unwrap_or_default(),
                    port: imap_port.unwrap_or_default(),
                    security: imap_security.unwrap_or_default(),
                    user: imap_username.unwrap_or_default(),
                    password: imap_password.unwrap_or(mail_pw),
                },
                smtp: EnteredServerLoginParam {
                    server: smtp_host.unwrap_or_default(),
                    port: smtp_port.unwrap_or_default(),
                    security: smtp_security.unwrap_or_default(),
                    user: smtp_username.unwrap_or_default(),
                    password: smtp_password.unwrap_or_default(),
                },
                certificate_checks: certificate_checks.unwrap_or_default(),
                oauth2: false,
            };
            Ok(param)
        }
        _ => bail!(
            "DeltaChat does not understand this QR Code yet, please update the app and try again."
        ),
    }
}

#[cfg(test)]
mod test {
    use anyhow::bail;

    use super::{LoginOptions, decode_login};
    use crate::{login_param::EnteredCertificateChecks, provider::Socket, qr::Qr};

    macro_rules! login_options_just_pw {
        ($pw: expr) => {
            LoginOptions::V1 {
                mail_pw: $pw,
                imap_host: None,
                imap_port: None,
                imap_username: None,
                imap_password: None,
                imap_security: None,
                smtp_host: None,
                smtp_port: None,
                smtp_username: None,
                smtp_password: None,
                smtp_security: None,
                certificate_checks: None,
            }
        };
    }

    #[test]
    fn minimal_no_options() -> anyhow::Result<()> {
        let result = decode_login("dclogin://email@host.tld?p=123&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(options, login_options_just_pw!("123".to_owned()));
        } else {
            bail!("wrong type")
        }
        let result = decode_login("dclogin://email@host.tld/?p=123456&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(options, login_options_just_pw!("123456".to_owned()));
        } else {
            bail!("wrong type")
        }
        let result = decode_login("dclogin://email@host.tld/ignored/path?p=123456&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(options, login_options_just_pw!("123456".to_owned()));
        } else {
            bail!("wrong type")
        }
        Ok(())
    }
    #[test]
    fn minimal_no_options_no_double_slash() -> anyhow::Result<()> {
        let result = decode_login("dclogin:email@host.tld?p=123&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(options, login_options_just_pw!("123".to_owned()));
        } else {
            bail!("wrong type")
        }
        let result = decode_login("dclogin:email@host.tld/?p=123456&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(options, login_options_just_pw!("123456".to_owned()));
        } else {
            bail!("wrong type")
        }
        let result = decode_login("dclogin:email@host.tld/ignored/path?p=123456&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(options, login_options_just_pw!("123456".to_owned()));
        } else {
            bail!("wrong type")
        }
        Ok(())
    }

    #[test]
    fn no_version_set() {
        assert!(decode_login("dclogin:email@host.tld?p=123").is_err());
    }

    #[test]
    fn invalid_version_set() {
        assert!(decode_login("dclogin:email@host.tld?p=123&v=").is_err());
        assert!(decode_login("dclogin:email@host.tld?p=123&v=%40").is_err());
        assert!(decode_login("dclogin:email@host.tld?p=123&v=-20").is_err());
        assert!(decode_login("dclogin:email@host.tld?p=123&v=hi").is_err());
    }

    #[test]
    fn version_too_new() -> anyhow::Result<()> {
        let result = decode_login("dclogin:email@host.tld/?p=123456&v=2")?;
        if let Qr::Login { options, .. } = result {
            assert_eq!(options, LoginOptions::UnsuportedVersion(2));
        } else {
            bail!("wrong type");
        }
        let result = decode_login("dclogin:email@host.tld/?p=123456&v=5")?;
        if let Qr::Login { options, .. } = result {
            assert_eq!(options, LoginOptions::UnsuportedVersion(5));
        } else {
            bail!("wrong type");
        }
        Ok(())
    }

    #[test]
    fn all_advanced_options() -> anyhow::Result<()> {
        let result = decode_login(
            "dclogin:email@host.tld?p=secret&v=1&ih=imap.host.tld&ip=4000&iu=max&ipw=87654&is=ssl&ic=1&sh=mail.host.tld&sp=3000&su=max@host.tld&spw=3242HS&ss=plain&sc=3",
        )?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(
                options,
                LoginOptions::V1 {
                    mail_pw: "secret".to_owned(),
                    imap_host: Some("imap.host.tld".to_owned()),
                    imap_port: Some(4000),
                    imap_username: Some("max".to_owned()),
                    imap_password: Some("87654".to_owned()),
                    imap_security: Some(Socket::Ssl),
                    smtp_host: Some("mail.host.tld".to_owned()),
                    smtp_port: Some(3000),
                    smtp_username: Some("max@host.tld".to_owned()),
                    smtp_password: Some("3242HS".to_owned()),
                    smtp_security: Some(Socket::Plain),
                    certificate_checks: Some(EnteredCertificateChecks::Strict),
                }
            );
        } else {
            bail!("wrong type")
        }
        Ok(())
    }

    #[test]
    fn uri_encoded_password() -> anyhow::Result<()> {
        let result = decode_login(
            "dclogin:email@host.tld?p=%7BDaehFl%3B%22as%40%21fhdodn5%24234%22%7B%7Dfg&v=1",
        )?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "email@host.tld".to_owned());
            assert_eq!(
                options,
                login_options_just_pw!("{DaehFl;\"as@!fhdodn5$234\"{}fg".to_owned())
            );
        } else {
            bail!("wrong type")
        }
        Ok(())
    }

    #[test]
    fn email_with_plus_extension() -> anyhow::Result<()> {
        let result = decode_login("dclogin:usename+extension@host?p=1234&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "usename+extension@host".to_owned());
            assert_eq!(options, login_options_just_pw!("1234".to_owned()));
        } else {
            bail!("wrong type")
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_dclogin_ipv4() -> anyhow::Result<()> {
        let result = decode_login("dclogin://test@[127.0.0.1]?p=1234&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "test@[127.0.0.1]".to_owned());
            assert_eq!(options, login_options_just_pw!("1234".to_owned()));
        } else {
            unreachable!("wrong type");
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_dclogin_ipv6() -> anyhow::Result<()> {
        let result =
            decode_login("dclogin://test@[2001:0db8:85a3:0000:0000:8a2e:0370:7334]?p=1234&v=1")?;
        if let Qr::Login { address, options } = result {
            assert_eq!(
                address,
                "test@[2001:0db8:85a3:0000:0000:8a2e:0370:7334]".to_owned()
            );
            assert_eq!(options, login_options_just_pw!("1234".to_owned()));
        } else {
            unreachable!("wrong type");
        }
        Ok(())
    }
}
