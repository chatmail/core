//! Custom TLS verification.
//!
//! We want to accept expired certificates.

use rustls::RootCertStore;
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use tokio_rustls::rustls;

use crate::net::tls::spki::spki_hash;

#[derive(Debug)]
pub(super) struct CustomCertificateVerifier {
    /// Root certificates.
    root_cert_store: RootCertStore,

    /// Expected SPKI hash as a base64 of SHA-256.
    spki_hash: Option<String>,
}

impl CustomCertificateVerifier {
    pub(super) fn new(spki_hash: Option<String>) -> Self {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            root_cert_store,
            spki_hash,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for CustomCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let parsed_certificate = ParsedCertificate::try_from(end_entity)?;

        let spki = parsed_certificate.subject_public_key_info();

        let provider = rustls::crypto::ring::default_provider();

        if let ServerName::DnsName(dns_name) = server_name
            && dns_name.as_ref().starts_with("_")
        {
            // Do not verify certificates for hostnames starting with `_`.
            // They are used for servers with self-signed certificates, e.g. for local testing.
            // Hostnames starting with `_` can have only self-signed TLS certificates or wildcard certificates.
            // It is not possible to get valid non-wildcard TLS certificates because CA/Browser Forum requirements
            // explicitly state that domains should start with a letter, digit or hyphen:
            // https://github.com/cabforum/servercert/blob/24f38fd4765e019db8bb1a8c56bf63c7115ce0b0/docs/BR.md
        } else if let Some(hash) = &self.spki_hash
            && spki_hash(&spki) == *hash
        {
            // Last time we successfully connected to this hostname with TLS checks,
            // SPKI had this hash.
            // It does not matter if certificate has now expired.
        } else {
            // verify_server_cert_signed_by_trust_anchor does no revocation checking:
            // <https://docs.rs/rustls/0.23.37/rustls/client/fn.verify_server_cert_signed_by_trust_anchor.html>
            // We don't do it either.
            verify_server_cert_signed_by_trust_anchor(
                &parsed_certificate,
                &self.root_cert_store,
                intermediates,
                now,
                provider.signature_verification_algorithms.all,
            )?;
        }

        // Verify server name unconditionally.
        //
        // We do this even for self-signed certificates when hostname starts with `_`
        // so we don't try to connect to captive portals
        // and fail on MITM certificates if they are generated once
        // and reused for all hostnames.
        verify_server_name(&parsed_certificate, server_name)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        let supported_schemes = &provider.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, supported_schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        let supported_schemes = &provider.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, supported_schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let provider = rustls::crypto::ring::default_provider();
        provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
