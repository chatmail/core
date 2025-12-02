//! TLS support.
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::net::session::SessionStream;

use tokio_rustls::rustls::client::ClientSessionStore;

pub async fn wrap_tls<'a>(
    strict_tls: bool,
    hostname: &str,
    port: u16,
    use_sni: bool,
    alpn: &str,
    stream: impl SessionStream + 'static,
    tls_session_store: &TlsSessionStore,
) -> Result<impl SessionStream + 'a> {
    if strict_tls {
        let tls_stream =
            wrap_rustls(hostname, port, use_sni, alpn, stream, tls_session_store).await?;
        let boxed_stream: Box<dyn SessionStream> = Box::new(tls_stream);
        Ok(boxed_stream)
    } else {
        // We use native_tls because it accepts 1024-bit RSA keys.
        // Rustls does not support them even if
        // certificate checks are disabled: <https://github.com/rustls/rustls/issues/234>.
        let alpns = if alpn.is_empty() {
            Box::from([])
        } else {
            Box::from([alpn])
        };
        let tls = async_native_tls::TlsConnector::new()
            .min_protocol_version(Some(async_native_tls::Protocol::Tlsv12))
            .use_sni(use_sni)
            .request_alpns(&alpns)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true);
        let tls_stream = tls.connect(hostname, stream).await?;
        let boxed_stream: Box<dyn SessionStream> = Box::new(tls_stream);
        Ok(boxed_stream)
    }
}

/// Map to store TLS session tickets.
///
/// Tickets are separated by port and ALPN
/// to avoid trying to use Postfix ticket for Dovecot and vice versa.
/// Doing so would not be a security issue,
/// but wastes the ticket and the opportunity to resume TLS session unnecessarily.
/// Rustls takes care of separating tickets that belong to different domain names.
#[derive(Debug)]
pub(crate) struct TlsSessionStore {
    sessions: Mutex<HashMap<(u16, String), Arc<dyn ClientSessionStore>>>,
}

// This is the default for TLS session store
// as of Rustls version 0.23.16,
// but we want to create multiple caches
// to separate them by port and ALPN.
const TLS_CACHE_SIZE: usize = 256;

impl TlsSessionStore {
    /// Creates a new TLS session store.
    ///
    /// One such store should be created per profile
    /// to keep TLS sessions independent.
    pub fn new() -> Self {
        Self {
            sessions: Default::default(),
        }
    }

    /// Returns session store for given port and ALPN.
    ///
    /// Rustls additionally separates sessions by hostname.
    pub fn get(&self, port: u16, alpn: &str) -> Arc<dyn ClientSessionStore> {
        Arc::clone(
            self.sessions
                .lock()
                .entry((port, alpn.to_string()))
                .or_insert_with(|| {
                    Arc::new(tokio_rustls::rustls::client::ClientSessionMemoryCache::new(
                        TLS_CACHE_SIZE,
                    ))
                }),
        )
    }
}

pub async fn wrap_rustls<'a>(
    hostname: &str,
    port: u16,
    use_sni: bool,
    alpn: &str,
    stream: impl SessionStream + 'a,
    tls_session_store: &TlsSessionStore,
) -> Result<impl SessionStream + 'a> {
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.alpn_protocols = if alpn.is_empty() {
        vec![]
    } else {
        vec![alpn.as_bytes().to_vec()]
    };

    // Enable TLS 1.3 session resumption
    // as defined in <https://www.rfc-editor.org/rfc/rfc8446#section-2.2>.
    //
    // Obsolete TLS 1.2 mechanisms defined in RFC 5246
    // and RFC 5077 have worse security
    // and are not worth increasing
    // attack surface: <https://words.filippo.io/we-need-to-talk-about-session-tickets/>.
    let resumption_store = tls_session_store.get(port, alpn);
    let resumption = tokio_rustls::rustls::client::Resumption::store(resumption_store)
        .tls12_resumption(tokio_rustls::rustls::client::Tls12Resumption::Disabled);
    config.resumption = resumption;
    config.enable_sni = use_sni;

    let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls_pki_types::ServerName::try_from(hostname)?.to_owned();
    let tls_stream = tls.connect(name, stream).await?;
    Ok(tls_stream)
}
