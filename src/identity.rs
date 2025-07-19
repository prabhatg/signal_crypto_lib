/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Identity key generation and management for the Signal Protocol.
 * Provides X25519 keys for Diffie-Hellman operations and Ed25519 keys for digital signatures.
 */

// signal_crypto_lib/src/identity.rs

use crate::types::IdentityKeyPair;
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub fn generate_identity_keypair() -> IdentityKeyPair {
    // Generate X25519 keys for Diffie-Hellman
    let dh_private = StaticSecret::random_from_rng(OsRng);
    let dh_public = PublicKey::from(&dh_private);
    
    // Generate Ed25519 keys for signatures
    let ed_signing_key = SigningKey::generate(&mut OsRng);
    let ed_verifying_key = ed_signing_key.verifying_key();

    IdentityKeyPair {
        dh_public: dh_public.as_bytes().to_vec(),
        dh_private: dh_private.to_bytes().to_vec(),
        ed_public: ed_verifying_key.to_bytes().to_vec(),
        ed_private: ed_signing_key.to_bytes().to_vec(),
    }
}
