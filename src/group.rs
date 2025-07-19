/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Group messaging functionality for the Signal Protocol.
 * Implements sender key generation and group message encryption/decryption.
 */

// signal_crypto_lib/src/group.rs

use crate::types::{EncryptedMessage, SenderKey};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::{RngCore, rngs::OsRng};
use rand::distributions::{Distribution, Standard};

pub fn generate_sender_key() -> SenderKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    SenderKey {
        key_id: OsRng.next_u32(),
        symmetric_key: key.to_vec(),
    }
}

pub fn encrypt_group_message(sender_key: &SenderKey, plaintext: &str) -> EncryptedMessage {
    let cipher = Aes256Gcm::new_from_slice(&sender_key.symmetric_key).expect("Invalid sender key");

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: &[] })
        .expect("Group encryption failed");

    EncryptedMessage {
        ciphertext,
        associated_data: Some(nonce_bytes.to_vec()),
        message_index: 0, // Not used for group messages
    }
}

pub fn decrypt_group_message(sender_key: &SenderKey, encrypted: &EncryptedMessage) -> String {
    let cipher = Aes256Gcm::new_from_slice(&sender_key.symmetric_key).expect("Invalid sender key");

    let nonce = Nonce::from_slice(
        &encrypted.associated_data.as_ref().expect("Missing nonce for group message")
    );

    let plaintext = cipher.decrypt(nonce, Payload { msg: &encrypted.ciphertext, aad: &[] })
        .expect("Group decryption failed");

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}
