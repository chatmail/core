//! TLS support.
use std::sync::Arc;

use anyhow::Result;

use crate::net::session::SessionStream;

pub async fn wrap_tls<'a>(
    strict_tls: bool,
    hostname: &str,
    alpn: &[&str],
    stream: impl SessionStream + 'static,
) -> Result<impl SessionStream + 'a> {
    if strict_tls {
        let tls_stream = wrap_rustls(hostname, alpn, stream).await?;
        let boxed_stream: Box<dyn SessionStream> = Box::new(tls_stream);
        Ok(boxed_stream)
    } else {
        // We use native_tls because it accepts 1024-bit RSA keys.
        // Rustls does not support them even if
        // certificate checks are disabled: <https://github.com/rustls/rustls/issues/234>.
        let tls = async_native_tls::TlsConnector::new()
            .min_protocol_version(Some(async_native_tls::Protocol::Tlsv12))
            .request_alpns(alpn)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true);
        let tls_stream = tls.connect(hostname, stream).await?;
        let boxed_stream: Box<dyn SessionStream> = Box::new(tls_stream);
        Ok(boxed_stream)
    }
}

pub async fn wrap_rustls<'a>(
    hostname: &str,
    alpn: &[&str],
    stream: impl SessionStream + 'a,
) -> Result<impl SessionStream + 'a> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

    let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls_pki_types::ServerName::try_from(hostname)?.to_owned();
    let tls_stream = tls.connect(name, stream).await?;
    Ok(tls_stream)
}
