//! Device keys: client-side Ed25519 identities used for passwordless login.
//!
//! After a first successful password login the client may *enroll* a device
//! key: the server stores the public key in `authorized_keys` and later logins
//! are authenticated by signing a server nonce (see
//! [`rmp_proto::key_auth_context`]).
//!
//! The private key is stored as hex-encoded 32-byte seed with mode `0600`.

use crate::error::CryptoError;
use crate::hostkey::{write_private, Fingerprint};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Length of an Ed25519 public key / seed.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A client device identity.
pub struct DeviceKey {
    signing: SigningKey,
}

impl DeviceKey {
    /// Generate a fresh random key.
    pub fn generate() -> Self {
        DeviceKey {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Build from a 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        let seed: [u8; PUBLIC_KEY_LEN] =
            seed.try_into().map_err(|_| CryptoError::BadKeyMaterial)?;
        Ok(DeviceKey {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The 32-byte seed (secret).
    pub fn seed(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.to_bytes()
    }

    /// Raw public key (32 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    /// Short fingerprint of the public key, for display.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_bytes(&self.public_key())
    }

    /// Sign a message with the device key.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }

    /// Persist the seed as hex with mode `0600`.
    pub fn save(&self, path: &Path) -> Result<(), CryptoError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // Best effort: restrict the containing directory to the owner.
            let _ = rmp_dirs::restrict_to_owner(parent);
        }
        let mut seed = self.seed();
        let encoded = Zeroizing::new(hex::encode(seed));
        seed.zeroize();
        write_private(path, encoded.as_bytes())
    }

    /// Load a seed previously saved with [`DeviceKey::save`].
    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        let text = std::fs::read_to_string(path)?;
        let seed = hex::decode(text.trim()).map_err(|_| CryptoError::BadKeyMaterial)?;
        Self::from_seed(&seed)
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private seed.
        f.debug_struct("DeviceKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// Verify a device-key signature. Returns `false` on any malformed input.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk): Result<[u8; PUBLIC_KEY_LEN], _> = public_key.try_into() else {
        return false;
    };
    let Ok(sig): Result<[u8; SIGNATURE_LEN], _> = signature.try_into() else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    verifying
        .verify(message, &Signature::from_bytes(&sig))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = DeviceKey::generate();
        let msg = b"hello rmp";
        let sig = key.sign(msg);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&key.public_key(), msg, &sig));
        assert!(!verify(&key.public_key(), b"other", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let a = DeviceKey::generate();
        let b = DeviceKey::generate();
        let sig = a.sign(b"x");
        assert!(!verify(&b.public_key(), b"x", &sig));
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(!verify(&[0u8; 10], b"x", &[0u8; 64]));
        assert!(!verify(&[0u8; 32], b"x", &[0u8; 10]));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identities").join("id.key");
        let key = DeviceKey::generate();
        let pk = key.public_key();
        let fp = key.fingerprint();
        key.save(&path).unwrap();

        let loaded = DeviceKey::load(&path).unwrap();
        assert_eq!(loaded.public_key(), pk);
        assert_eq!(loaded.fingerprint(), fp);
    }

    #[test]
    fn fingerprint_is_stable_and_public_key_is_32() {
        let key = DeviceKey::generate();
        assert_eq!(key.public_key().len(), PUBLIC_KEY_LEN);
        assert_eq!(key.fingerprint(), key.fingerprint());
    }
}
