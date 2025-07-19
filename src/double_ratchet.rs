/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Legacy Double Ratchet compatibility wrapper for backward compatibility.
 * Provides simplified encryption/decryption interface - use protocol::double_ratchet
 * for full-featured implementation with proper key management and forward secrecy.
 */

// signal_crypto_lib/src/double_ratchet.rs
// Legacy compatibility wrapper - use protocol::double_ratchet instead

use crate::types::{EncryptedMessage, SessionState};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::RngCore;

fn derive_key_and_nonce(chain_key: &[u8], message_index: u32) -> (Vec<u8>, Vec<u8>) {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut okm = [0u8; 44]; // 32 bytes key + 12 bytes nonce
    hk.expand(&message_index.to_be_bytes(), &mut okm).expect("HKDF expand failed");
    (okm[..32].to_vec(), okm[32..].to_vec())
}

pub fn encrypt(session: &mut SessionState, plaintext: &str) -> EncryptedMessage {
    // Use the send chain key if available, otherwise fallback
    let fallback_key = vec![0u8; 32];
    let chain_key = session.chain_key_send.as_ref()
        .unwrap_or(&fallback_key);
    
    let (key, nonce) = derive_key_and_nonce(chain_key, session.n_send);

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid AES key");
    let nonce = Nonce::from_slice(&nonce); // 96-bits

    let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: &[] })
        .expect("Encryption failed");

    session.n_send += 1;

    EncryptedMessage {
        ciphertext,
        associated_data: None,
        message_index: session.n_send - 1,
    }
}

pub fn decrypt(session: &mut SessionState, encrypted: &EncryptedMessage) -> String {
    // Use the receive chain key if available, otherwise fallback
    let fallback_key = vec![0u8; 32];
    let chain_key = session.chain_key_recv.as_ref()
        .unwrap_or(&fallback_key);
    
    let (key, nonce) = derive_key_and_nonce(chain_key, encrypted.message_index);

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid AES key");
    let nonce = Nonce::from_slice(&nonce);

    let plaintext = cipher.decrypt(nonce, Payload { msg: &encrypted.ciphertext, aad: &[] })
        .expect("Decryption failed");

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}
