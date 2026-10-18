//! Server identity: an Ed25519 host key and its self-signed certificate.
//!
//! The certificate is self-signed and therefore establishes **no** trust by
//! itself — the client authenticates the server by pinning the certificate
//! fingerprint (trust-on-first-use, see [`crate::known_hosts`]).

use crate::error::CryptoError;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rmp_dirs::{HOST_CERT_FILE, HOST_KEY_FILE};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

/// A SHA-256 fingerprint of a certificate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Fingerprint of a DER-encoded certificate.
    pub fn of_cert_der(der: &[u8]) -> Self {
        Self::of_bytes(der)
    }

    /// Fingerprint of an arbitrary byte string (e.g. a public key).
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Fingerprint(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a hexadecimal fingerprint.
    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(s.trim()).map_err(|_| CryptoError::BadFingerprint)?;
        if raw.len() != 32 {
            return Err(CryptoError::BadFingerprint);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(Fingerprint(out))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Group in pairs separated by colons, like SSH.
        let hex = self.to_hex();
        let mut first = true;
        for chunk in hex.as_bytes().chunks(2) {
            if !first {
                f.write_str(":")?;
            }
            first = false;
            f.write_str(std::str::from_utf8(chunk).unwrap_or("??"))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// A loaded or freshly generated host identity.
pub struct HostKey {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    fingerprint: Fingerprint,
}

impl HostKey {
    /// Generate a fresh Ed25519 host key with a self-signed certificate.
    pub fn generate() -> Result<Self, CryptoError> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let params = CertificateParams::new(vec!["rmp".to_string()])?;
        let cert = params.self_signed(&key)?;
        let cert_der = cert.der().to_vec();
        Ok(HostKey {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            fingerprint: Fingerprint::of_cert_der(&cert_der),
            cert_der,
            key_der: key.serialize_der(),
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }

    /// Persist the certificate and private key in `dir`.
    ///
    /// On Unix the private key is written with mode `0600`.
    pub fn save(&self, dir: &Path) -> Result<(), CryptoError> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join(HOST_CERT_FILE);
        let key_path = dir.join(HOST_KEY_FILE);
        std::fs::write(&cert_path, self.cert_pem.as_bytes())?;
        write_private(&key_path, self.key_pem.as_bytes())?;
        Ok(())
    }

    /// Load a host key previously saved with [`HostKey::save`].
    pub fn load(dir: &Path) -> Result<Self, CryptoError> {
        let cert_pem = std::fs::read_to_string(dir.join(HOST_CERT_FILE))?;
        let key_pem = std::fs::read_to_string(dir.join(HOST_KEY_FILE))?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Load a host key from PEM strings.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, CryptoError> {
        let cert_der = pem_to_der(cert_pem).ok_or_else(|| {
            CryptoError::Rcgen("host certificate is not a valid PEM CERTIFICATE".into())
        })?;
        let key_der = pem_to_der(key_pem)
            .ok_or_else(|| CryptoError::Rcgen("host key is not a valid PEM PRIVATE KEY".into()))?;
        // Validate that the private key can be parsed as an Ed25519 PKCS#8 key.
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.clone());
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .map_err(|e| CryptoError::Rcgen(format!("invalid host private key: {e}")))?;

        Ok(HostKey {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            fingerprint: Fingerprint::of_cert_der(&cert_der),
            cert_der,
            key_der,
        })
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the private key.
        f.debug_struct("HostKey")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Extract the DER bytes from a single PEM block.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let begin = pem.find("-----BEGIN")?;
    let rest = &pem[begin..];
    let b64_start = rest.find('\n')? + 1;
    let end = rest[b64_start..].find("-----END")? + b64_start;
    let body: String = rest[b64_start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    // Base64 decode without pulling in an extra crate.
    base64_decode(&body)
}

/// Minimal standard-alphabet base64 decoder.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        if c == b'=' {
            break;
        }
        let v = lookup[c as usize];
        if v == 255 {
            return None;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Write a file containing secret material with restrictive permissions.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<(), CryptoError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // `OpenOptions::mode` only applies when the file is created. If it already
    // exists with looser permissions (for example after `rmp init --force`),
    // tighten it before writing the secret.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_roundtrip() {
        let hk = HostKey::generate().unwrap();
        let fp = hk.fingerprint();

        let restored = HostKey::from_pem(hk.cert_pem(), &hk.key_pem).unwrap();
        assert_eq!(restored.fingerprint(), fp);
        assert_eq!(restored.cert_der(), hk.cert_der());
        assert_eq!(restored.key_der(), hk.key_der());
    }

    #[test]
    fn fingerprint_hex_roundtrip() {
        let hk = HostKey::generate().unwrap();
        let fp = hk.fingerprint();
        let hex = fp.to_hex();
        assert_eq!(Fingerprint::from_hex(&hex).unwrap(), fp);
        assert!(Fingerprint::from_hex("zz").is_err());
        // Display uses colon separators.
        assert_eq!(fp.to_string().matches(':').count(), 31);
    }

    #[test]
    fn distinct_keys_have_distinct_fingerprints() {
        let a = HostKey::generate().unwrap().fingerprint();
        let b = HostKey::generate().unwrap().fingerprint();
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_fixes_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing secret must be tightened to 0600");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }
}
