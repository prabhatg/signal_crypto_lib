// signal_crypto_lib/src/protocol/x3dh.rs

use crate::types::*;
use crate::protocol::constants::*;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use std::collections::HashMap;

#[derive(Debug)]
pub enum X3DHError {
    InvalidKeySize,
    InvalidSignature,
    MissingOneTimePreKey,
    InvalidPreKeyBundle,
    CryptoError(String),
}

impl std::fmt::Display for X3DHError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            X3DHError::InvalidKeySize => write!(f, "Invalid key size"),
            X3DHError::InvalidSignature => write!(f, "Invalid signature"),
            X3DHError::MissingOneTimePreKey => write!(f, "Missing one-time prekey"),
            X3DHError::InvalidPreKeyBundle => write!(f, "Invalid prekey bundle"),
            X3DHError::CryptoError(e) => write!(f, "Crypto error: {}", e),
        }
    }
}

impl std::error::Error for X3DHError {}

/// Perform Diffie-Hellman key exchange
fn dh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, X3DHError> {
    if private_key.len() != DH_KEY_SIZE || public_key.len() != DH_KEY_SIZE {
        return Err(X3DHError::InvalidKeySize);
    }
    
    let private = StaticSecret::from(<[u8; 32]>::try_from(private_key)
        .map_err(|_| X3DHError::InvalidKeySize)?);
    let public = PublicKey::from(<[u8; 32]>::try_from(public_key)
        .map_err(|_| X3DHError::InvalidKeySize)?);
    
    Ok(private.diffie_hellman(&public).as_bytes().to_vec())
}

/// Calculate Associated Data for X3DH
fn calculate_associated_data(
    alice_identity: &[u8],
    bob_identity: &[u8],
) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(alice_identity);
    ad.extend_from_slice(bob_identity);
    ad
}

/// Verify a prekey bundle's signature
pub fn verify_prekey_bundle(bundle: &PreKeyBundle) -> Result<bool, X3DHError> {
    // Verify the signed prekey signature using Ed25519 identity key
    let identity_key = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(&bundle.identity_key_ed[..])
            .map_err(|_| X3DHError::InvalidKeySize)?
    ).map_err(|e| X3DHError::CryptoError(e.to_string()))?;
    
    let signature = Signature::from_bytes(
        &<[u8; 64]>::try_from(&bundle.signed_prekey_signature[..])
            .map_err(|_| X3DHError::InvalidKeySize)?
    );
    
    match identity_key.verify(&bundle.signed_prekey_public, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Alice's side: Create initial message
pub fn x3dh_alice_init(
    alice_identity: &IdentityKeyPair,
    alice_registration_id: u32,
    bob_bundle: &PreKeyBundle,
) -> Result<(X3DHInitialMessage, SessionState), X3DHError> {
    // Verify Bob's prekey bundle
    if !verify_prekey_bundle(bob_bundle)? {
        return Err(X3DHError::InvalidSignature);
    }
    
    // Generate ephemeral key pair (EK_A)
    let ephemeral_private = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_private);
    
    // Calculate DH values according to X3DH spec
    // DH1: IK_A * SPK_B (Alice's identity DH key with Bob's signed prekey)
    let dh1 = dh(&alice_identity.dh_private, &bob_bundle.signed_prekey_public)?;
    // DH2: EK_A * IK_B (Alice's ephemeral key with Bob's identity DH key)
    let dh2 = dh(&ephemeral_private.to_bytes(), &bob_bundle.identity_key)?;
    // DH3: EK_A * SPK_B (Alice's ephemeral key with Bob's signed prekey)
    let dh3 = dh(&ephemeral_private.to_bytes(), &bob_bundle.signed_prekey_public)?;
    
    let dh4 = if let (Some(otpk_id), Some(otpk)) = 
        (bob_bundle.one_time_prekey_id, &bob_bundle.one_time_prekey) {
        Some(dh(&ephemeral_private.to_bytes(), otpk)?)
    } else {
        None
    };
    
    // Calculate shared secret
    let shared_secret = X3DHSharedSecret {
        dh1,
        dh2,
        dh3,
        dh4,
        associated_data: calculate_associated_data(
            &alice_identity.ed_public,
            &bob_bundle.identity_key_ed,
        ),
    };
    
    // Derive initial keys
    let (root_key, chain_key) = derive_initial_keys(&shared_secret)?;
    
    // Create initial message
    let initial_message = X3DHInitialMessage {
        registration_id: alice_registration_id,
        one_time_prekey_id: bob_bundle.one_time_prekey_id,
        signed_prekey_id: bob_bundle.signed_prekey_id,
        base_key: ephemeral_public.as_bytes().to_vec(),
        identity_key: alice_identity.dh_public.clone(),      // X25519 DH key
        identity_key_ed: alice_identity.ed_public.clone(),   // Ed25519 signature key
        message: vec![], // Will be filled by Double Ratchet
    };
    
    // Create session state
    let session = SessionState {
        session_id: hex::encode(&root_key[..16]),
        registration_id: bob_bundle.registration_id,
        device_id: bob_bundle.device_id,
        dh_self_private: ephemeral_private.to_bytes().to_vec(),
        dh_self_public: ephemeral_public.as_bytes().to_vec(),
        dh_remote: Some(bob_bundle.signed_prekey_public.clone()),
        root_key: root_key.to_vec(),
        chain_key_send: Some(chain_key.to_vec()),
        chain_key_recv: None,
        header_key_send: None,
        header_key_recv: None,
        next_header_key_send: None,
        next_header_key_recv: None,
        n_send: 0,
        n_recv: 0,
        pn: 0,
        mk_skipped: HashMap::new(),
        max_skip: 1000, // Default maximum skipped messages
    };
    
    Ok((initial_message, session))
}

/// Bob's side: Process initial message
pub fn x3dh_bob_init(
    bob_identity: &IdentityKeyPair,
    bob_registration_id: u32,
    bob_signed_prekey: &SignedPreKey,
    bob_one_time_prekey: Option<&OneTimePreKey>,
    initial_message: &X3DHInitialMessage,
) -> Result<SessionState, X3DHError> {
    // Verify that we have the one-time prekey if it was used
    if let Some(otpk_id) = initial_message.one_time_prekey_id {
        if bob_one_time_prekey.is_none() ||
           bob_one_time_prekey.as_ref().unwrap().key_id != otpk_id {
            return Err(X3DHError::MissingOneTimePreKey);
        }
    }
    
    // Calculate DH values (Bob's perspective - same as Alice but with Bob's keys)
    // DH1: IK_A * SPK_B (Alice's identity DH key with Bob's signed prekey) - Bob computes SPK_B * IK_A
    let dh1 = dh(&bob_signed_prekey.private, &initial_message.identity_key)?;
    // DH2: EK_A * IK_B (Alice's ephemeral with Bob's identity) - Bob computes IK_B * EK_A
    let dh2 = dh(&bob_identity.dh_private, &initial_message.base_key)?;
    // DH3: EK_A * SPK_B (Alice's ephemeral with Bob's signed prekey) - Bob computes SPK_B * EK_A
    let dh3 = dh(&bob_signed_prekey.private, &initial_message.base_key)?;
    
    let dh4 = if let Some(otpk) = bob_one_time_prekey {
        Some(dh(&otpk.private, &initial_message.base_key)?)
    } else {
        None
    };
    
    // Calculate shared secret (same as Alice)
    let shared_secret = X3DHSharedSecret {
        dh1,
        dh2,
        dh3,
        dh4,
        associated_data: calculate_associated_data(
            &initial_message.identity_key_ed,
            &bob_identity.ed_public,
        ),
    };
    
    // Derive initial keys (same derivation as Alice)
    let (root_key, chain_key) = derive_initial_keys(&shared_secret)?;
    
    // Generate new DH key pair for Bob
    let bob_dh_private = StaticSecret::random_from_rng(OsRng);
    let bob_dh_public = PublicKey::from(&bob_dh_private);
    
    // Create session state - Bob receives what Alice sends
    let session = SessionState {
        session_id: hex::encode(&root_key[..16]),
        registration_id: initial_message.registration_id,
        device_id: 0, // Will be set by the application
        dh_self_private: bob_dh_private.to_bytes().to_vec(),
        dh_self_public: bob_dh_public.as_bytes().to_vec(),
        dh_remote: Some(initial_message.base_key.clone()),
        root_key: root_key.to_vec(),
        chain_key_send: None,
        chain_key_recv: Some(chain_key.to_vec()),
        header_key_send: None,
        header_key_recv: None,
        next_header_key_send: None,
        next_header_key_recv: None,
        n_send: 0,
        n_recv: 0,
        pn: 0,
        mk_skipped: HashMap::new(),
        max_skip: 1000, // Default maximum skipped messages
    };
    
    Ok(session)
}

/// Derive initial root and chain keys from X3DH shared secret
fn derive_initial_keys(shared_secret: &X3DHSharedSecret) -> Result<([u8; 32], [u8; 32]), X3DHError> {
    // Concatenate DH outputs
    let mut kdf_input = Vec::new();
    kdf_input.extend(&shared_secret.dh1);
    kdf_input.extend(&shared_secret.dh2);
    kdf_input.extend(&shared_secret.dh3);
    if let Some(ref dh4) = shared_secret.dh4 {
        kdf_input.extend(dh4);
    }
    
    // F = KDF(0xFF * 32 || DH1 || DH2 || DH3 || DH4)
    let mut f_input = vec![0xFF; 32];
    f_input.extend(&kdf_input);
    
    let hkdf = Hkdf::<Sha256>::new(None, &f_input);
    let mut output = [0u8; 64];
    hkdf.expand(&shared_secret.associated_data, &mut output)
        .map_err(|e| X3DHError::CryptoError(e.to_string()))?;
    
    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];
    root_key.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);
    
    Ok((root_key, chain_key))
}

/// Create a prekey bundle for publishing
pub fn create_prekey_bundle(
    identity: &IdentityKeyPair,
    registration_id: u32,
    device_id: u32,
    signed_prekey: &SignedPreKey,
    one_time_prekey: Option<&OneTimePreKey>,
) -> PreKeyBundle {
    PreKeyBundle {
        registration_id,
        device_id,
        identity_key: identity.dh_public.clone(),      // X25519 for DH
        identity_key_ed: identity.ed_public.clone(),   // Ed25519 for signatures
        signed_prekey_id: signed_prekey.key_id,
        signed_prekey_public: signed_prekey.public.clone(),
        signed_prekey_signature: signed_prekey.signature.clone(),
        one_time_prekey_id: one_time_prekey.map(|k| k.key_id),
        one_time_prekey: one_time_prekey.map(|k| k.public.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity_keypair;
    use crate::prekey::{generate_signed_prekey, generate_one_time_prekey};
    
    #[test]
    fn test_x3dh_key_agreement() {
        // Generate identities
        let alice_identity = generate_identity_keypair();
        let bob_identity = generate_identity_keypair();
        
        // Generate Bob's prekeys
        let bob_signed_prekey = generate_signed_prekey(&bob_identity, 1);
        let bob_one_time_prekey = generate_one_time_prekey(100);
        
        // Create Bob's prekey bundle
        let bob_bundle = create_prekey_bundle(
            &bob_identity,
            1234,  // registration_id
            1,     // device_id
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
        );
        
        // Alice initiates
        let (initial_msg, alice_session) = x3dh_alice_init(
            &alice_identity,
            5678,  // Alice's registration_id
            &bob_bundle,
        ).unwrap();
        
        // Bob processes the same initial message
        let bob_session = x3dh_bob_init(
            &bob_identity,
            1234,
            &bob_signed_prekey,
            Some(&bob_one_time_prekey),
            &initial_msg,
        ).unwrap();
        
        // Verify sessions have same root key
        assert_eq!(alice_session.root_key, bob_session.root_key);
        assert_eq!(alice_session.session_id, bob_session.session_id);
        
        // Verify that Alice has send chain and Bob has receive chain
        assert!(alice_session.chain_key_send.is_some());
        assert!(bob_session.chain_key_recv.is_some());
        
        // The chain keys should be the same since they're derived from the same shared secret
        assert_eq!(alice_session.chain_key_send, bob_session.chain_key_recv);
    }
    
    #[test]
    fn test_prekey_bundle_verification() {
        let identity = generate_identity_keypair();
        let signed_prekey = generate_signed_prekey(&identity, 1);
        
        let bundle = create_prekey_bundle(
            &identity,
            1234,
            1,
            &signed_prekey,
            None,
        );
        
        assert!(verify_prekey_bundle(&bundle).unwrap());
        
        // Corrupt the signature
        let mut bad_bundle = bundle.clone();
        bad_bundle.signed_prekey_signature[0] ^= 0xFF;
        assert!(!verify_prekey_bundle(&bad_bundle).unwrap());
    }
}