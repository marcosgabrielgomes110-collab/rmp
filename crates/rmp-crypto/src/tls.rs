//! TLS 1.3 configuration for RMP.
//!
//! * Only TLS 1.3 is allowed.
//! * The default `aws-lc-rs` provider is used, with the hybrid post-quantum key
//!   exchange (`X25519MLKEM768`) preferred when the peer supports it.
//! * The client authenticates the server by **pinning the certificate
//!   fingerprint** (trust-on-first-use). The handshake is aborted before any
//!   credential is sent if the fingerprint does not match the expected one.

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

/// TLS 1.3-only client configuration that pins the server certificate.
///
/// * `expected = Some(fp)` — only `fp` is accepted; anything else aborts the
///   handshake.
/// * `expected = None` — trust-on-first-use: any certificate is accepted and the
///   observed fingerprint is recorded in the returned [`ObservedFingerprint`].
pub fn client_config(
    expected: Option<Fingerprint>,
) -> Result<(ClientConfig, ObservedFingerprint), CryptoError> {
    let observed = ObservedFingerprint(Arc::new(Mutex::new(None)));
    let verifier = TofuVerifier {
        expected,
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
    expected: Option<Fingerprint>,
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

        if let Some(expected) = self.expected {
            if expected != fp {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        }

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

    fn make_verifier(expected: Option<Fingerprint>) -> (TofuVerifier, ObservedFingerprint) {
        let observed = ObservedFingerprint(Arc::new(Mutex::new(None)));
        let v = TofuVerifier {
            expected,
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
    fn tofu_accepts_and_records_when_unknown() {
        let hk = HostKey::generate().unwrap();
        let (v, observed) = make_verifier(None);
        assert!(call_verify(&v, hk.cert_der()).is_ok());
        assert_eq!(observed.get(), Some(hk.fingerprint()));
    }

    #[test]
    fn pin_accepts_matching_certificate() {
        let hk = HostKey::generate().unwrap();
        let (v, _observed) = make_verifier(Some(hk.fingerprint()));
        assert!(call_verify(&v, hk.cert_der()).is_ok());
    }

    #[test]
    fn pin_rejects_different_certificate() {
        let hk = HostKey::generate().unwrap();
        let other = HostKey::generate().unwrap();
        let (v, _observed) = make_verifier(Some(other.fingerprint()));
        assert!(matches!(
            call_verify(&v, hk.cert_der()),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            ))
        ));
    }

    #[test]
    fn configs_build() {
        let hk = HostKey::generate().unwrap();
        let _srv = server_config(&hk).unwrap();
        let (_cli, _obs) = client_config(None).unwrap();
        let (_cli2, _obs2) = client_config(Some(hk.fingerprint())).unwrap();
    }
}
