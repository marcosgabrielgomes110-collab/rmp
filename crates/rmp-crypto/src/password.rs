//! Password authentication with OPAQUE (RFC 9807).
//!
//! OPAQUE is an *augmented* PAKE: the client proves knowledge of the password
//! without ever sending it, and the server only stores an opaque "password
//! file" that is useless for an offline dictionary attack by itself.
//!
//! The flow implemented here:
//!
//! 1. **Enrollment** (server-side setup): [`enroll`] runs the full registration
//!    locally and returns a [`PasswordFile`] derived from the chosen password.
//! 2. **Login**: [`client_start`] / [`server_start`] exchange one round, then
//!    [`client_finish`] / [`server_finish`] complete it. Both sides derive the
//!    same `session_key`, which is *not* used to encrypt traffic (QUIC/TLS
//!    already does that) but serves as proof of a successful authentication.

use crate::error::{opaque_err, CryptoError};
use crate::hostkey::write_private;
use opaque_ke::{
    argon2::Argon2, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh,
};
use rand::rngs::OsRng;
use sha2::Sha512;
use std::path::Path;
use zeroize::Zeroize;

/// The OPAQUE parameter set used by RMP.
///
/// * OPRF group: Ristretto255
/// * Key exchange: Triple Diffie-Hellman over Ristretto255 with SHA-512
/// * Key stretching: Argon2 (id) with conservative defaults
pub struct RmpCipherSuite;

impl opaque_ke::CipherSuite for RmpCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

/// Server-side OPAQUE setup (the server's long-term OPRF secret).
pub type Setup = ServerSetup<RmpCipherSuite>;

/// A serialized server-side registration record for one user.
#[derive(Clone)]
pub struct PasswordFile(Vec<u8>);

impl Drop for PasswordFile {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PasswordFile {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PasswordFile(bytes)
    }

    pub fn save(&self, path: &Path) -> Result<(), CryptoError> {
        write_private(path, &self.0)
    }

    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        Ok(PasswordFile(std::fs::read(path)?))
    }
}

/// Generate a fresh OPAQUE server setup.
pub fn new_setup() -> Setup {
    Setup::new(&mut OsRng)
}

/// Serialize the server setup so it can be persisted.
pub fn setup_to_bytes(setup: &Setup) -> Vec<u8> {
    setup.serialize().to_vec()
}

/// Deserialize a previously persisted server setup.
pub fn setup_from_bytes(bytes: &[u8]) -> Result<Setup, CryptoError> {
    Setup::deserialize(bytes).map_err(opaque_err)
}

/// Run a full local registration to derive a [`PasswordFile`].
///
/// This is what `rmp init` calls on the server after prompting for a password.
/// Both the client and server steps of registration run in-process; nothing
/// sensitive leaves the machine.
pub fn enroll(password: &[u8], username: &str, setup: &Setup) -> Result<PasswordFile, CryptoError> {
    let mut rng = OsRng;
    let client_reg =
        ClientRegistration::<RmpCipherSuite>::start(&mut rng, password).map_err(opaque_err)?;
    let server_reg =
        ServerRegistration::<RmpCipherSuite>::start(setup, client_reg.message, username.as_bytes())
            .map_err(opaque_err)?;
    let client_finish = client_reg
        .state
        .finish(
            &mut rng,
            password,
            server_reg.message,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(opaque_err)?;
    let file = ServerRegistration::<RmpCipherSuite>::finish(client_finish.message);
    Ok(PasswordFile(file.serialize().to_vec()))
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/// Opaque client state carried between [`client_start`] and [`client_finish`].
pub struct ClientLoginState(Vec<u8>);

impl Drop for ClientLoginState {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Opaque server state carried between [`server_start`] and [`server_finish`].
pub struct ServerLoginState(Vec<u8>);

impl Drop for ServerLoginState {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Client step 1: produce a credential request.
pub fn client_start(password: &[u8]) -> Result<(Vec<u8>, ClientLoginState), CryptoError> {
    let result = ClientLogin::<RmpCipherSuite>::start(&mut OsRng, password).map_err(opaque_err)?;
    Ok((
        result.message.serialize().to_vec(),
        ClientLoginState(result.state.serialize().to_vec()),
    ))
}

/// Server step 2: answer a credential request with a credential response.
///
/// `password_file` is `None` when the user is unknown; OPAQUE still produces a
/// well-formed, indistinguishable response so the server does not leak which
/// accounts exist.
pub fn server_start(
    setup: &Setup,
    password_file: Option<&PasswordFile>,
    request: &[u8],
    username: &str,
) -> Result<(Vec<u8>, ServerLoginState), CryptoError> {
    let cred_request = CredentialRequest::deserialize(request).map_err(opaque_err)?;
    let file = match password_file {
        Some(f) => Some(
            ServerRegistration::<RmpCipherSuite>::deserialize(f.as_bytes()).map_err(opaque_err)?,
        ),
        None => None,
    };
    let result = ServerLogin::start(
        &mut OsRng,
        setup,
        file,
        cred_request,
        username.as_bytes(),
        ServerLoginParameters::default(),
    )
    .map_err(opaque_err)?;
    Ok((
        result.message.serialize().to_vec(),
        ServerLoginState(result.state.serialize().to_vec()),
    ))
}

/// Client step 3: verify the server's response and produce the finalization.
///
/// Returns `(finalization, session_key)`. Fails with [`CryptoError::AuthFailed`]
/// if the password is wrong.
pub fn client_finish(
    state: ClientLoginState,
    response: &[u8],
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let state = ClientLogin::<RmpCipherSuite>::deserialize(&state.0).map_err(opaque_err)?;
    let response = CredentialResponse::deserialize(response).map_err(opaque_err)?;
    let result = state
        .finish(
            &mut OsRng,
            password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok((
        result.message.serialize().to_vec(),
        result.session_key.to_vec(),
    ))
}

/// Server step 4: verify the client's finalization.
///
/// Returns the `session_key`, which must equal the client's. Fails with
/// [`CryptoError::AuthFailed`] if the proof is invalid.
pub fn server_finish(
    state: &ServerLoginState,
    finalization: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let state = ServerLogin::<RmpCipherSuite>::deserialize(&state.0).map_err(opaque_err)?;
    let finalization = CredentialFinalization::deserialize(finalization).map_err(opaque_err)?;
    let result = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(result.session_key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "alice";

    #[test]
    fn successful_login_matches_session_keys() {
        let setup = new_setup();
        let file = enroll(b"correct horse battery staple", USER, &setup).unwrap();

        let (request, client_state) = client_start(b"correct horse battery staple").unwrap();
        let (response, server_state) = server_start(&setup, Some(&file), &request, USER).unwrap();
        let (finalization, client_key) =
            client_finish(client_state, &response, b"correct horse battery staple").unwrap();
        let server_key = server_finish(&server_state, &finalization).unwrap();

        assert_eq!(client_key, server_key);
        assert!(!client_key.is_empty());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let setup = new_setup();
        let file = enroll(b"right-password", USER, &setup).unwrap();

        let (request, client_state) = client_start(b"wrong-password").unwrap();
        let (response, server_state) = server_start(&setup, Some(&file), &request, USER).unwrap();
        // The client cannot complete the protocol with a wrong password.
        assert!(client_finish(client_state, &response, b"wrong-password").is_err());
        let _ = server_state;
    }

    #[test]
    fn unknown_user_does_not_error_on_server_start() {
        let setup = new_setup();
        let (request, _client_state) = client_start(b"whatever").unwrap();
        // No password file: still produces a response (no user enumeration).
        let (response, _state) = server_start(&setup, None, &request, USER).unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn setup_and_password_file_serialize() {
        let setup = new_setup();
        let bytes = setup_to_bytes(&setup);
        let restored = setup_from_bytes(&bytes).unwrap();

        let file = enroll(b"pw", USER, &setup).unwrap();
        // A file enrolled with the original setup must still verify with the
        // restored setup (same OPRF secret).
        let (request, client_state) = client_start(b"pw").unwrap();
        let (response, server_state) =
            server_start(&restored, Some(&file), &request, USER).unwrap();
        let (fin, _k) = client_finish(client_state, &response, b"pw").unwrap();
        assert!(server_finish(&server_state, &fin).is_ok());
    }
}
