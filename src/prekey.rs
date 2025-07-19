/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Prekey generation and management for the Signal Protocol.
 * Handles signed prekeys and one-time prekeys for X3DH key agreement.
 */

// signal_crypto_lib/src/prekey.rs

use crate::types::{IdentityKeyPair, OneTimePreKey, SignedPreKey};
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, Signer};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_signed_prekey(identity: &IdentityKeyPair, key_id: u32) -> SignedPreKey {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    // Reconstruct the signing key from bytes
    let ed_secret_bytes: [u8; 32] = identity.ed_private.clone().try_into()
        .expect("Invalid Ed25519 secret key length");
    let ed_signing_key = SigningKey::from_bytes(&ed_secret_bytes);

    // Sign the X25519 public key
    let signature = ed_signing_key.sign(public.as_bytes());
    
    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    SignedPreKey {
        key_id,
        public: public.as_bytes().to_vec(),
        private: private.to_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
        timestamp,
    }
}

pub fn generate_one_time_prekey(key_id: u32) -> OneTimePreKey {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    OneTimePreKey {
        key_id,
        public: public.as_bytes().to_vec(),
        private: private.to_bytes().to_vec(),
    }
}

/// Generate a batch of one-time prekeys
pub fn generate_one_time_prekeys(start_id: u32, count: u32) -> Vec<OneTimePreKey> {
    (0..count)
        .map(|i| generate_one_time_prekey(start_id + i))
        .collect()
}

/// Check if a signed prekey has expired (older than 30 days)
pub fn is_signed_prekey_expired(prekey: &SignedPreKey) -> bool {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    
    const THIRTY_DAYS_IN_SECONDS: u64 = 30 * 24 * 60 * 60;
    current_time - prekey.timestamp > THIRTY_DAYS_IN_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity_keypair;
    
    #[test]
    fn test_signed_prekey_generation() {
        let identity = generate_identity_keypair();
        let signed_prekey = generate_signed_prekey(&identity, 1);
        
        assert_eq!(signed_prekey.key_id, 1);
        assert_eq!(signed_prekey.public.len(), 32);
        assert_eq!(signed_prekey.private.len(), 32);
        assert_eq!(signed_prekey.signature.len(), 64);
        assert!(signed_prekey.timestamp > 0);
    }
    
    #[test]
    fn test_one_time_prekey_batch_generation() {
        let prekeys = generate_one_time_prekeys(100, 10);
        
        assert_eq!(prekeys.len(), 10);
        for (i, prekey) in prekeys.iter().enumerate() {
            assert_eq!(prekey.key_id, 100 + i as u32);
            assert_eq!(prekey.public.len(), 32);
            assert_eq!(prekey.private.len(), 32);
        }
    }
}
