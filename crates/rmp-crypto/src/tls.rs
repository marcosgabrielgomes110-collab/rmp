//! TLS 1.3 configuration for RMP.
//!
//! * Only TLS 1.3 is allowed.
//! * The default `aws-lc-rs` provider is used, with the hybrid post-quantum key
//!   exchange (`X25519MLKEM768`) preferred when the peer supports it.
//! * The verifier **records** the certificate fingerprint but does not pin it.
//!   Pinning is enforced by the client immediately after the handshake and
//!   before any credential is sent, which lets it explain a mismatch (old vs.
//!   new fingerprint) instead of surfacing an opaque rustls error.

use crate::error::CryptoError;
use crate::hostkey::{Fingerprint, HostKey};
use rmp_proto::ALPN;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    aws_lc_rs, verify_tls12_signature, verify_tls13_signature, CryptoProvider,
    WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::{Arc, Mutex};

/// Build the shared crypto provider (aws-lc-rs).
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

/// TLS 1.3-only server configuration presenting the host certificate.
pub fn server_config(host: &HostKey) -> Result<ServerConfig, CryptoError> {
    let cert = CertificateDer::from(host.cert_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(host.key_der().to_vec()));

    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

/// Handle to the fingerprint observed during a client handshake.
#[derive(Clone, Debug)]
pub struct ObservedFingerprint(Arc<Mutex<Option<Fingerprint>>>);

impl ObservedFingerprint {
    pub fn get(&self) -> Option<Fingerprint> {
        *self.0.lock().expect("fingerprint mutex poisoned")
    }
}

/// TLS 1.3-only client configuration that records the server certificate.
///
/// The certificate itself is self-signed, so it establishes no trust. The
/// observed fingerprint is returned through [`ObservedFingerprint`] and must be
/// compared against `known_hosts` by the caller *before* authentication.
pub fn client_config() -> Result<(ClientConfig, ObservedFingerprint), CryptoError> {
    let observed = ObservedFingerprint(Arc::new(Mutex::new(None)));
    let verifier = TofuVerifier {
        observed: observed.clone(),
        algs: aws_lc_rs::default_provider().signature_verification_algorithms,
    };

    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok((config, observed))
}

#[derive(Debug)]
struct TofuVerifier {
    observed: ObservedFingerprint,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = Fingerprint::of_cert_der(end_entity.as_ref());
        *self.observed.0.lock().expect("fingerprint mutex poisoned") = Some(fp);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_verifier() -> (TofuVerifier, ObservedFingerprint) {
        let observed = ObservedFingerprint(Arc::new(Mutex::new(None)));
        let v = TofuVerifier {
            observed: observed.clone(),
            algs: aws_lc_rs::default_provider().signature_verification_algorithms,
        };
        (v, observed)
    }

    fn call_verify(v: &TofuVerifier, cert_der: &[u8]) -> Result<(), rustls::Error> {
        let cert = CertificateDer::from(cert_der.to_vec());
        v.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("rmp").unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
    }

    #[test]
    fn accepts_and_records_fingerprint() {
        let hk = HostKey::generate().unwrap();
        let (v, observed) = make_verifier();
        assert!(call_verify(&v, hk.cert_der()).is_ok());
        assert_eq!(observed.get(), Some(hk.fingerprint()));
    }

    #[test]
    fn records_the_last_presented_certificate() {
        let first = HostKey::generate().unwrap();
        let second = HostKey::generate().unwrap();
        let (v, observed) = make_verifier();
        assert!(call_verify(&v, first.cert_der()).is_ok());
        assert!(call_verify(&v, second.cert_der()).is_ok());
        assert_eq!(observed.get(), Some(second.fingerprint()));
    }

    #[test]
    fn configs_build() {
        let hk = HostKey::generate().unwrap();
        let _srv = server_config(&hk).unwrap();
        let (_cli, _obs) = client_config().unwrap();
    }
}
