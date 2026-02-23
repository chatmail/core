//! # Proxy support.
//!
//! Delta Chat supports HTTP(S) CONNECT, SOCKS5 and Shadowsocks protocols.

use std::fmt;
use std::pin::Pin;

use anyhow::{Context as _, Result, bail, format_err};
use base64::Engine;
use bytes::{BufMut, BytesMut};
use fast_socks5::AuthenticationMethod;
use fast_socks5::Socks5Command;
use fast_socks5::client::Socks5Stream;
use fast_socks5::util::target_addr::ToTargetAddr;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode, utf8_percent_encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutStream;
use url::Url;

use crate::config::Config;
use crate::constants::NON_ALPHANUMERIC_WITHOUT_DOT;
use crate::context::Context;
use crate::net::connect_tcp;
use crate::net::session::SessionStream;
use crate::net::tls::wrap_rustls;
use crate::sql::Sql;

/// Default SOCKS5 port according to [RFC 1928](https://tools.ietf.org/html/rfc1928).
pub const DEFAULT_SOCKS_PORT: u16 = 1080;

#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    pub server_config: shadowsocks::config::ServerConfig,
}

impl PartialEq for ShadowsocksConfig {
    fn eq(&self, other: &Self) -> bool {
        self.server_config.to_url() == other.server_config.to_url()
    }
}

impl Eq for ShadowsocksConfig {}

impl ShadowsocksConfig {
    fn to_url(&self) -> String {
        self.server_config.to_url()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConfig {
    /// HTTP proxy host.
    pub host: String,

    /// HTTP proxy port.
    pub port: u16,

    /// Username and password for basic authentication.
    ///
    /// If set, `Proxy-Authorization` header is sent.
    pub user_password: Option<(String, String)>,
}

impl HttpConfig {
    fn from_url(url: Url) -> Result<Self> {
        let host = url
            .host_str()
            .context("HTTP proxy URL has no host")?
            .to_string();
        let port = url
            .port_or_known_default()
            .context("HTTP(S) URLs are guaranteed to return Some port")?;
        let user_password = if let Some(password) = url.password() {
            let username = percent_encoding::percent_decode_str(url.username())
                .decode_utf8()
                .context("HTTP(S) proxy username is not a valid UTF-8")?
                .to_string();
            let password = percent_encoding::percent_decode_str(password)
                .decode_utf8()
                .context("HTTP(S) proxy password is not a valid UTF-8")?
                .to_string();
            Some((username, password))
        } else {
            None
        };
        let http_config = HttpConfig {
            host,
            port,
            user_password,
        };
        Ok(http_config)
    }

    fn to_url(&self, scheme: &str) -> String {
        let host = utf8_percent_encode(&self.host, NON_ALPHANUMERIC_WITHOUT_DOT);
        if let Some((user, password)) = &self.user_password {
            let user = utf8_percent_encode(user, NON_ALPHANUMERIC);
            let password = utf8_percent_encode(password, NON_ALPHANUMERIC);
            format!("{scheme}://{user}:{password}@{host}:{}", self.port)
        } else {
            format!("{scheme}://{host}:{}", self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Config {
    pub host: String,
    pub port: u16,
    pub user_password: Option<(String, String)>,
}

impl Socks5Config {
    async fn connect(
        &self,
        context: &Context,
        target_host: &str,
        target_port: u16,
        load_dns_cache: bool,
    ) -> Result<Socks5Stream<Pin<Box<TimeoutStream<TcpStream>>>>> {
        let tcp_stream = connect_tcp(context, &self.host, self.port, load_dns_cache)
            .await
            .context("Failed to connect to SOCKS5 proxy")?;

        let authentication_method = if let Some((username, password)) = self.user_password.as_ref()
        {
            Some(AuthenticationMethod::Password {
                username: username.into(),
                password: password.into(),
            })
        } else {
            None
        };
        let mut socks_stream =
            Socks5Stream::use_stream(tcp_stream, authentication_method, Default::default()).await?;
        let target_addr = (target_host, target_port).to_target_addr()?;
        socks_stream
            .request(Socks5Command::TCPConnect, target_addr)
            .await?;

        Ok(socks_stream)
    }

    fn to_url(&self) -> String {
        let host = utf8_percent_encode(&self.host, NON_ALPHANUMERIC_WITHOUT_DOT);
        if let Some((user, password)) = &self.user_password {
            let user = utf8_percent_encode(user, NON_ALPHANUMERIC);
            let password = utf8_percent_encode(password, NON_ALPHANUMERIC);
            format!("socks5://{user}:{password}@{host}:{}", self.port)
        } else {
            format!("socks5://{host}:{}", self.port)
        }
    }
}

/// Configuration for the proxy through which all traffic
/// (except for iroh p2p connections)
/// will be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::large_enum_variant)]
pub enum ProxyConfig {
    /// HTTP proxy.
    Http(HttpConfig),

    /// HTTPS proxy.
    Https(HttpConfig),

    /// SOCKS5 proxy.
    Socks5(Socks5Config),

    /// Shadowsocks proxy.
    Shadowsocks(ShadowsocksConfig),
}

/// Constructs HTTP/1.1 `CONNECT` request for HTTP(S) proxy.
#[expect(clippy::arithmetic_side_effects)]
fn http_connect_request(host: &str, port: u16, auth: Option<(&str, &str)>) -> String {
    // According to <https://datatracker.ietf.org/doc/html/rfc7230#section-5.4>
    // clients MUST send `Host:` header in HTTP/1.1 requests,
    // so repeat the host there.
    let mut res = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((username, password)) = auth {
        res += "Proxy-Authorization: Basic ";
        res += &base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        res += "\r\n";
    }
    res += "\r\n";
    res
}

/// Sends HTTP/1.1 `CONNECT` request over given connection
/// to establish an HTTP tunnel.
///
/// Returns the same connection back so actual data can be tunneled over it.
async fn http_tunnel<T>(mut conn: T, host: &str, port: u16, auth: Option<(&str, &str)>) -> Result<T>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Send HTTP/1.1 CONNECT request.
    let request = http_connect_request(host, port, auth);
    conn.write_all(request.as_bytes()).await?;

    let mut buffer = BytesMut::with_capacity(4096);

    let res = loop {
        if !buffer.has_remaining_mut() {
            bail!("CONNECT response exceeded buffer size");
        }
        let n = conn.read_buf(&mut buffer).await?;
        if n == 0 {
            bail!("Unexpected end of CONNECT response");
        }

        let res = &buffer[..];
        if res.ends_with(b"\r\n\r\n") {
            // End of response is not reached, read more.
            break res;
        }
    };

    // Normally response looks like
    // `HTTP/1.1 200 Connection established\r\n\r\n`.
    if !res.starts_with(b"HTTP/") {
        bail!("Unexpected HTTP CONNECT response: {res:?}");
    }

    // HTTP-version followed by space has fixed length
    // according to RFC 7230:
    // <https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2>
    //
    // Normally status line starts with `HTTP/1.1 `.
    // We only care about 3-digit status code.
    let status_code = res
        .get(9..12)
        .context("HTTP status line does not contain a status code")?;

    // Interpret status code according to
    // <https://datatracker.ietf.org/doc/html/rfc7231#section-6>.
    if status_code == b"407" {
        Err(format_err!("Proxy Authentication Required"))
    } else if status_code.starts_with(b"2") {
        // Success.
        Ok(conn)
    } else {
        Err(format_err!(
            "Failed to establish HTTP CONNECT tunnel: {res:?}"
        ))
    }
}

impl ProxyConfig {
    /// Creates a new proxy configuration by parsing given proxy URL.
    pub fn from_url(url: &str) -> Result<Self> {
        let url = Url::parse(url).context("Cannot parse proxy URL")?;
        match url.scheme() {
            "http" => {
                let http_config = HttpConfig::from_url(url)?;
                Ok(Self::Http(http_config))
            }
            "https" => {
                let https_config = HttpConfig::from_url(url)?;
                Ok(Self::Https(https_config))
            }
            "ss" => {
                let server_config = shadowsocks::config::ServerConfig::from_url(url.as_str())?;
                let shadowsocks_config = ShadowsocksConfig { server_config };
                Ok(Self::Shadowsocks(shadowsocks_config))
            }

            // Because of `curl` convention,
            // `socks5` URL scheme may be expected to resolve domain names locally
            // with `socks5h` URL scheme meaning that hostnames are passed to the proxy.
            // Resolving hostnames locally is not supported
            // in Delta Chat when using a proxy
            // to prevent DNS leaks.
            // Because of this we do not distinguish
            // between `socks5` and `socks5h`.
            "socks5" => {
                let host = url
                    .host_str()
                    .context("socks5 URL has no host")?
                    .to_string();
                let port = url.port().unwrap_or(DEFAULT_SOCKS_PORT);
                let user_password = if let Some(password) = url.password() {
                    let username = percent_encoding::percent_decode_str(url.username())
                        .decode_utf8()
                        .context("SOCKS5 username is not a valid UTF-8")?
                        .to_string();
                    let password = percent_encoding::percent_decode_str(password)
                        .decode_utf8()
                        .context("SOCKS5 password is not a valid UTF-8")?
                        .to_string();
                    Some((username, password))
                } else {
                    None
                };
                let socks5_config = Socks5Config {
                    host,
                    port,
                    user_password,
                };
                Ok(Self::Socks5(socks5_config))
            }
            scheme => Err(format_err!("Unknown URL scheme {scheme:?}")),
        }
    }

    /// Serializes proxy config into an URL.
    ///
    /// This function can be used to normalize proxy URL
    /// by parsing it and serializing back.
    pub fn to_url(&self) -> String {
        match self {
            Self::Http(http_config) => http_config.to_url("http"),
            Self::Https(http_config) => http_config.to_url("https"),
            Self::Socks5(socks5_config) => socks5_config.to_url(),
            Self::Shadowsocks(shadowsocks_config) => shadowsocks_config.to_url(),
        }
    }

    /// Migrates legacy `socks5_host`, `socks5_port`, `socks5_user` and `socks5_password`
    /// config into `proxy_url` if `proxy_url` is unset or empty.
    ///
    /// Unsets `socks5_host`, `socks5_port`, `socks5_user` and `socks5_password` in any case.
    #[expect(clippy::arithmetic_side_effects)]
    async fn migrate_socks_config(sql: &Sql) -> Result<()> {
        if sql.get_raw_config("proxy_url").await?.is_none() {
            // Load legacy SOCKS5 settings.
            if let Some(host) = sql
                .get_raw_config("socks5_host")
                .await?
                .filter(|s| !s.is_empty())
            {
                let port: u16 = sql
                    .get_raw_config_int("socks5_port")
                    .await?
                    .unwrap_or(DEFAULT_SOCKS_PORT.into()) as u16;
                let user = sql.get_raw_config("socks5_user").await?.unwrap_or_default();
                let pass = sql
                    .get_raw_config("socks5_password")
                    .await?
                    .unwrap_or_default();

                let mut proxy_url = "socks5://".to_string();
                if !pass.is_empty() {
                    proxy_url += &percent_encode(user.as_bytes(), NON_ALPHANUMERIC).to_string();
                    proxy_url += ":";
                    proxy_url += &percent_encode(pass.as_bytes(), NON_ALPHANUMERIC).to_string();
                    proxy_url += "@";
                };
                proxy_url += &host;
                proxy_url += ":";
                proxy_url += &port.to_string();

                sql.set_raw_config("proxy_url", Some(&proxy_url)).await?;
            } else {
                sql.set_raw_config("proxy_url", Some("")).await?;
            }

            let socks5_enabled = sql.get_raw_config("socks5_enabled").await?;
            sql.set_raw_config("proxy_enabled", socks5_enabled.as_deref())
                .await?;
        }

        sql.set_raw_config("socks5_enabled", None).await?;
        sql.set_raw_config("socks5_host", None).await?;
        sql.set_raw_config("socks5_port", None).await?;
        sql.set_raw_config("socks5_user", None).await?;
        sql.set_raw_config("socks5_password", None).await?;
        Ok(())
    }

    /// Reads proxy configuration from the database.
    pub async fn load(context: &Context) -> Result<Option<Self>> {
        Self::migrate_socks_config(&context.sql)
            .await
            .context("Failed to migrate legacy SOCKS config")?;

        let enabled = context.get_config_bool(Config::ProxyEnabled).await?;
        if !enabled {
            return Ok(None);
        }

        let proxy_url = context
            .get_config(Config::ProxyUrl)
            .await?
            .unwrap_or_default();
        let proxy_url = proxy_url
            .split_once('\n')
            .map_or(proxy_url.clone(), |(first_url, _rest)| {
                first_url.to_string()
            });
        let proxy_config = Self::from_url(&proxy_url).context("Failed to parse proxy URL")?;
        Ok(Some(proxy_config))
    }

    /// If `load_dns_cache` is true, loads cached DNS resolution results.
    /// Use this only if the connection is going to be protected with TLS checks.
    pub(crate) async fn connect(
        &self,
        context: &Context,
        target_host: &str,
        target_port: u16,
        load_dns_cache: bool,
    ) -> Result<Box<dyn SessionStream>> {
        match self {
            ProxyConfig::Http(http_config) => {
                let load_cache = false;
                let tcp_stream = crate::net::connect_tcp(
                    context,
                    &http_config.host,
                    http_config.port,
                    load_cache,
                )
                .await?;
                let auth = if let Some((username, password)) = &http_config.user_password {
                    Some((username.as_str(), password.as_str()))
                } else {
                    None
                };
                let tunnel_stream = http_tunnel(tcp_stream, target_host, target_port, auth).await?;
                Ok(Box::new(tunnel_stream))
            }
            ProxyConfig::Https(https_config) => {
                let load_cache = true;
                let tcp_stream = crate::net::connect_tcp(
                    context,
                    &https_config.host,
                    https_config.port,
                    load_cache,
                )
                .await?;
                let use_sni = true;
                let tls_stream = wrap_rustls(
                    &https_config.host,
                    https_config.port,
                    use_sni,
                    "",
                    tcp_stream,
                    &context.tls_session_store,
                )
                .await?;
                let auth = if let Some((username, password)) = &https_config.user_password {
                    Some((username.as_str(), password.as_str()))
                } else {
                    None
                };
                let tunnel_stream = http_tunnel(tls_stream, target_host, target_port, auth).await?;
                Ok(Box::new(tunnel_stream))
            }
            ProxyConfig::Socks5(socks5_config) => {
                let socks5_stream = socks5_config
                    .connect(context, target_host, target_port, load_dns_cache)
                    .await?;
                Ok(Box::new(socks5_stream))
            }
            ProxyConfig::Shadowsocks(ShadowsocksConfig { server_config }) => {
                let shadowsocks_context = shadowsocks::context::Context::new_shared(
                    shadowsocks::config::ServerType::Local,
                );

                let tcp_stream = {
                    let server_addr = server_config.addr();
                    let host = server_addr.host();
                    let port = server_addr.port();
                    connect_tcp(context, &host, port, load_dns_cache)
                        .await
                        .context("Failed to connect to Shadowsocks proxy")?
                };

                let shadowsocks_stream = shadowsocks::ProxyClientStream::from_stream(
                    shadowsocks_context,
                    tcp_stream,
                    server_config,
                    (target_host.to_string(), target_port),
                );

                Ok(Box::new(shadowsocks_stream))
            }
        }
    }
}

impl fmt::Display for Socks5Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "host:{},port:{},user_password:{}",
            self.host,
            self.port,
            if let Some(user_password) = self.user_password.clone() {
                format!("user: {}, password: ***", user_password.0)
            } else {
                "user: None".to_string()
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_utils::TestContext;

    #[test]
    fn test_socks5_url() {
        let proxy_config = ProxyConfig::from_url("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Socks5(Socks5Config {
                host: "127.0.0.1".to_string(),
                port: 9050,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("socks5://foo:bar@127.0.0.1:9150").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Socks5(Socks5Config {
                host: "127.0.0.1".to_string(),
                port: 9150,
                user_password: Some(("foo".to_string(), "bar".to_string()))
            })
        );

        let proxy_config = ProxyConfig::from_url("socks5://%66oo:b%61r@127.0.0.1:9150").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Socks5(Socks5Config {
                host: "127.0.0.1".to_string(),
                port: 9150,
                user_password: Some(("foo".to_string(), "bar".to_string()))
            })
        );

        let proxy_config = ProxyConfig::from_url("socks5://127.0.0.1:80").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Socks5(Socks5Config {
                host: "127.0.0.1".to_string(),
                port: 80,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("socks5://127.0.0.1").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Socks5(Socks5Config {
                host: "127.0.0.1".to_string(),
                port: 1080,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Socks5(Socks5Config {
                host: "127.0.0.1".to_string(),
                port: 1080,
                user_password: None
            })
        );
    }

    #[test]
    fn test_http_url() {
        let proxy_config = ProxyConfig::from_url("http://127.0.0.1").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Http(HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 80,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("http://127.0.0.1:80").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Http(HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 80,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("http://127.0.0.1:443").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Http(HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 443,
                user_password: None
            })
        );
    }

    #[test]
    fn test_https_url() {
        let proxy_config = ProxyConfig::from_url("https://127.0.0.1").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Https(HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 443,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("https://127.0.0.1:80").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Https(HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 80,
                user_password: None
            })
        );

        let proxy_config = ProxyConfig::from_url("https://127.0.0.1:443").unwrap();
        assert_eq!(
            proxy_config,
            ProxyConfig::Https(HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 443,
                user_password: None
            })
        );
    }

    #[test]
    fn test_http_connect_request() {
        assert_eq!(
            http_connect_request("example.org", 143, Some(("aladdin", "opensesame"))),
            "CONNECT example.org:143 HTTP/1.1\r\nHost: example.org:143\r\nProxy-Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n"
        );
        assert_eq!(
            http_connect_request("example.net", 587, None),
            "CONNECT example.net:587 HTTP/1.1\r\nHost: example.net:587\r\n\r\n"
        );
    }

    #[test]
    fn test_shadowsocks_url() {
        // Example URL from <https://shadowsocks.org/doc/sip002.html>.
        let proxy_config =
            ProxyConfig::from_url("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1")
                .unwrap();
        assert!(matches!(proxy_config, ProxyConfig::Shadowsocks(_)));
    }

    #[test]
    fn test_invalid_proxy_url() {
        assert!(ProxyConfig::from_url("foobar://127.0.0.1:9050").is_err());
        assert!(ProxyConfig::from_url("abc").is_err());

        // This caused panic before shadowsocks 1.22.0.
        assert!(ProxyConfig::from_url("ss://foo:bar@127.0.0.1:9999").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_socks5_migration() -> Result<()> {
        let t = TestContext::new().await;

        // Test that config is migrated on attempt to load even if disabled.
        t.set_config(Config::Socks5Host, Some("127.0.0.1")).await?;
        t.set_config(Config::Socks5Port, Some("9050")).await?;

        let proxy_config = ProxyConfig::load(&t).await?;
        // Even though proxy is not enabled, config should be migrated.
        assert_eq!(proxy_config, None);

        assert_eq!(
            t.get_config(Config::ProxyUrl).await?.unwrap(),
            "socks5://127.0.0.1:9050"
        );
        Ok(())
    }

    // Test SOCKS5 setting migration if proxy was never configured.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_socks5_migration_unconfigured() -> Result<()> {
        let t = TestContext::new().await;

        // Try to load config to trigger migration.
        assert_eq!(ProxyConfig::load(&t).await?, None);

        assert_eq!(t.get_config(Config::ProxyEnabled).await?, None);
        assert_eq!(
            t.get_config(Config::ProxyUrl).await?.unwrap(),
            String::new()
        );
        Ok(())
    }

    // Test SOCKS5 setting migration if SOCKS5 host is empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_socks5_migration_empty() -> Result<()> {
        let t = TestContext::new().await;

        t.set_config(Config::Socks5Host, Some("")).await?;

        // Try to load config to trigger migration.
        assert_eq!(ProxyConfig::load(&t).await?, None);

        assert_eq!(t.get_config(Config::ProxyEnabled).await?, None);
        assert_eq!(
            t.get_config(Config::ProxyUrl).await?.unwrap(),
            String::new()
        );
        Ok(())
    }
}
