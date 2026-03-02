//! Dangerous TLS implementation of accepting invalid certificates for Rustls.

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls;

#[derive(Debug)]
pub(super) struct NoCertificateVerification();

impl NoCertificateVerification {
    pub(super) fn new() -> Self {
        Self()
    }
}

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
