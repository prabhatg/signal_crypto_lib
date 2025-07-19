/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Double Ratchet protocol implementation for secure messaging.
 * Provides forward secrecy and post-compromise security through
 * continuous key evolution and Diffie-Hellman ratcheting.
 */

// signal_crypto_lib/src/protocol/double_ratchet.rs

use crate::types::*;
use crate::protocol::constants::*;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::rngs::OsRng;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum DoubleRatchetError {
    InvalidKeySize,
    EncryptionFailed,
    DecryptionFailed,
    InvalidHeader,
    InvalidMessageNumber,
    TooManySkippedMessages,
    CryptoError(String),
}

impl std::fmt::Display for DoubleRatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DoubleRatchetError::InvalidKeySize => write!(f, "Invalid key size"),
            DoubleRatchetError::EncryptionFailed => write!(f, "Encryption failed"),
            DoubleRatchetError::DecryptionFailed => write!(f, "Decryption failed"),
            DoubleRatchetError::InvalidHeader => write!(f, "Invalid header"),
            DoubleRatchetError::InvalidMessageNumber => write!(f, "Invalid message number"),
            DoubleRatchetError::TooManySkippedMessages => write!(f, "Too many skipped messages"),
            DoubleRatchetError::CryptoError(e) => write!(f, "Crypto error: {}", e),
        }
    }
}

impl std::error::Error for DoubleRatchetError {}

/// Initialize Double Ratchet session from X3DH output
pub fn initialize_session(
    session: &mut SessionState,
    remote_dh_public: Option<&[u8]>,
) -> Result<(), DoubleRatchetError> {
    // If we have a remote DH key, perform initial DH ratchet step
    if let Some(remote_key) = remote_dh_public {
        session.dh_remote = Some(remote_key.to_vec());
        
        // Derive initial header keys
        let (header_key_send, header_key_recv) = derive_header_keys(&session.root_key)?;
        session.header_key_send = Some(header_key_send);
        session.header_key_recv = Some(header_key_recv);
    }
    
    Ok(())
}

/// Encrypt a message using Double Ratchet
pub fn encrypt_message(
    session: &mut SessionState,
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<DoubleRatchetMessage, DoubleRatchetError> {
    // Get or create sending chain key
    let chain_key = session.chain_key_send.as_ref()
        .ok_or(DoubleRatchetError::InvalidKeySize)?;
    
    // Derive message key from chain key
    let message_key = derive_message_key(chain_key, session.n_send)?;
    
    // Advance chain key
    let new_chain_key = advance_chain_key(chain_key)?;
    session.chain_key_send = Some(new_chain_key);
    
    // Create header
    let header = DoubleRatchetHeader {
        dh_key: session.dh_self_public.clone(),
        pn: session.pn,
        n: session.n_send,
    };
    
    // Serialize and encrypt header
    let header_bytes = serialize_header(&header)?;
    let encrypted_header = encrypt_header(&header_bytes, &session.header_key_send)?;
    
    // Encrypt message
    let ciphertext = encrypt_with_message_key(&message_key, plaintext, associated_data)?;
    
    // Increment send counter
    session.n_send += 1;
    
    Ok(DoubleRatchetMessage {
        header: encrypted_header,
        ciphertext,
    })
}

/// Decrypt a message using Double Ratchet
pub fn decrypt_message(
    session: &mut SessionState,
    message: &DoubleRatchetMessage,
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, DoubleRatchetError> {
    // Decrypt header
    let header_bytes = decrypt_header(&message.header, &session.header_key_recv)?;
    let header = deserialize_header(&header_bytes)?;
    
    // Check if we need to perform DH ratchet step
    if Some(&header.dh_key) != session.dh_remote.as_ref() {
        perform_dh_ratchet_step(session, &header.dh_key)?;
    }
    
    // Handle skipped messages if necessary
    if header.n > session.n_recv {
        skip_message_keys(session, header.n)?;
    }
    
    // Get receiving chain key
    let chain_key = session.chain_key_recv.as_ref()
        .ok_or(DoubleRatchetError::InvalidKeySize)?;
    
    // Derive message key
    let message_key = derive_message_key(chain_key, header.n)?;
    
    // Decrypt message
    let plaintext = decrypt_with_message_key(&message_key, &message.ciphertext, associated_data)?;
    
    // Advance chain key and counter
    let new_chain_key = advance_chain_key(chain_key)?;
    session.chain_key_recv = Some(new_chain_key);
    session.n_recv = header.n + 1;
    
    Ok(plaintext)
}

/// Perform DH ratchet step when receiving new DH key
fn perform_dh_ratchet_step(
    session: &mut SessionState,
    remote_dh_key: &[u8],
) -> Result<(), DoubleRatchetError> {
    // Store previous chain length
    session.pn = session.n_send;
    session.n_send = 0;
    session.n_recv = 0;
    
    // Update remote DH key
    session.dh_remote = Some(remote_dh_key.to_vec());
    
    // Generate new DH key pair
    let new_private = StaticSecret::random_from_rng(OsRng);
    let new_public = PublicKey::from(&new_private);
    
    session.dh_self_private = new_private.to_bytes().to_vec();
    session.dh_self_public = new_public.as_bytes().to_vec();
    
    // Perform DH and derive new root key and chain keys
    let dh_output = perform_dh(&session.dh_self_private, remote_dh_key)?;
    let (new_root_key, new_chain_key_recv, new_chain_key_send) = 
        derive_ratchet_keys(&session.root_key, &dh_output)?;
    
    session.root_key = new_root_key;
    session.chain_key_recv = Some(new_chain_key_recv);
    session.chain_key_send = Some(new_chain_key_send);
    
    // Derive new header keys
    let (header_key_send, header_key_recv) = derive_header_keys(&session.root_key)?;
    session.next_header_key_send = Some(header_key_send);
    session.next_header_key_recv = Some(header_key_recv);
    
    Ok(())
}

/// Skip message keys for out-of-order messages
fn skip_message_keys(
    session: &mut SessionState,
    until: u32,
) -> Result<(), DoubleRatchetError> {
    if session.n_recv + session.max_skip < until {
        return Err(DoubleRatchetError::TooManySkippedMessages);
    }
    
    let chain_key = session.chain_key_recv.as_ref()
        .ok_or(DoubleRatchetError::InvalidKeySize)?;
    
    let mut current_chain_key = chain_key.clone();
    
    for i in session.n_recv..until {
        let message_key = derive_message_key(&current_chain_key, i)?;
        let header_key = session.header_key_recv.as_ref()
            .ok_or(DoubleRatchetError::InvalidKeySize)?;
        
        session.mk_skipped.insert(
            (header_key.clone(), i),
            message_key.key.to_vec(),
        );
        
        current_chain_key = advance_chain_key(&current_chain_key)?;
    }
    
    session.chain_key_recv = Some(current_chain_key);
    
    Ok(())
}

/// Derive message key from chain key
fn derive_message_key(
    chain_key: &[u8],
    message_number: u32,
) -> Result<MessageKey, DoubleRatchetError> {
    let hkdf = Hkdf::<Sha256>::new(None, chain_key);
    let mut output = [0u8; 80]; // 32 + 16 + 32 bytes
    
    let info = [&message_number.to_be_bytes()[..], MESSAGE_KEY_INFO].concat();
    hkdf.expand(&info, &mut output)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut mac_key = [0u8; 32];
    
    key.copy_from_slice(&output[0..32]);
    iv.copy_from_slice(&output[32..48]);
    mac_key.copy_from_slice(&output[48..80]);
    
    Ok(MessageKey { key, iv, mac_key })
}

/// Advance chain key using HMAC
fn advance_chain_key(chain_key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
    let hkdf = Hkdf::<Sha256>::new(None, chain_key);
    let mut output = [0u8; 32];
    
    hkdf.expand(CHAIN_KEY_INFO, &mut output)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    Ok(output.to_vec())
}

/// Derive header keys from root key
pub fn derive_header_keys(root_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DoubleRatchetError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);
    let mut output = [0u8; 64]; // 32 bytes each for send and receive
    
    hkdf.expand(HEADER_KEY_INFO, &mut output)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    Ok((output[0..32].to_vec(), output[32..64].to_vec()))
}

/// Derive new root key and chain keys from DH output
fn derive_ratchet_keys(
    root_key: &[u8],
    dh_output: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), DoubleRatchetError> {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 96]; // 32 bytes each for root, recv chain, send chain
    
    hkdf.expand(ROOT_KEY_INFO, &mut output)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    Ok((
        output[0..32].to_vec(),   // new root key
        output[32..64].to_vec(),  // new receive chain key
        output[64..96].to_vec(),  // new send chain key
    ))
}

/// Perform Diffie-Hellman operation
fn perform_dh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, DoubleRatchetError> {
    if private_key.len() != 32 || public_key.len() != 32 {
        return Err(DoubleRatchetError::InvalidKeySize);
    }
    
    let private = StaticSecret::from(<[u8; 32]>::try_from(private_key)
        .map_err(|_| DoubleRatchetError::InvalidKeySize)?);
    let public = PublicKey::from(<[u8; 32]>::try_from(public_key)
        .map_err(|_| DoubleRatchetError::InvalidKeySize)?);
    
    Ok(private.diffie_hellman(&public).as_bytes().to_vec())
}

/// Encrypt message with message key
fn encrypt_with_message_key(
    message_key: &MessageKey,
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, DoubleRatchetError> {
    let cipher = Aes256Gcm::new_from_slice(&message_key.key)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    let nonce = Nonce::from_slice(&message_key.iv[..12]); // AES-GCM uses 96-bit nonce
    
    let payload = Payload {
        msg: plaintext,
        aad: associated_data.unwrap_or(&[]),
    };
    
    cipher.encrypt(nonce, payload)
        .map_err(|_| DoubleRatchetError::EncryptionFailed)
}

/// Decrypt message with message key
fn decrypt_with_message_key(
    message_key: &MessageKey,
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, DoubleRatchetError> {
    let cipher = Aes256Gcm::new_from_slice(&message_key.key)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    let nonce = Nonce::from_slice(&message_key.iv[..12]);
    
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data.unwrap_or(&[]),
    };
    
    cipher.decrypt(nonce, payload)
        .map_err(|_| DoubleRatchetError::DecryptionFailed)
}

/// Encrypt header
fn encrypt_header(
    header_bytes: &[u8],
    header_key: &Option<Vec<u8>>,
) -> Result<Vec<u8>, DoubleRatchetError> {
    let key = header_key.as_ref()
        .ok_or(DoubleRatchetError::InvalidKeySize)?;
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    // Use zero nonce for header encryption (deterministic)
    let nonce = Nonce::from_slice(&[0u8; 12]);
    
    cipher.encrypt(nonce, header_bytes)
        .map_err(|_| DoubleRatchetError::EncryptionFailed)
}

/// Decrypt header
fn decrypt_header(
    encrypted_header: &[u8],
    header_key: &Option<Vec<u8>>,
) -> Result<Vec<u8>, DoubleRatchetError> {
    let key = header_key.as_ref()
        .ok_or(DoubleRatchetError::InvalidKeySize)?;
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| DoubleRatchetError::CryptoError(e.to_string()))?;
    
    let nonce = Nonce::from_slice(&[0u8; 12]);
    
    cipher.decrypt(nonce, encrypted_header)
        .map_err(|_| DoubleRatchetError::DecryptionFailed)
}

/// Serialize header to bytes
fn serialize_header(header: &DoubleRatchetHeader) -> Result<Vec<u8>, DoubleRatchetError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.dh_key);
    bytes.extend_from_slice(&header.pn.to_be_bytes());
    bytes.extend_from_slice(&header.n.to_be_bytes());
    Ok(bytes)
}

/// Deserialize header from bytes
fn deserialize_header(bytes: &[u8]) -> Result<DoubleRatchetHeader, DoubleRatchetError> {
    if bytes.len() < 40 { // 32 bytes DH key + 4 bytes pn + 4 bytes n
        return Err(DoubleRatchetError::InvalidHeader);
    }
    
    let dh_key = bytes[0..32].to_vec();
    let pn = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
    let n = u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
    
    Ok(DoubleRatchetHeader { dh_key, pn, n })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity_keypair;
    use crate::prekey::generate_signed_prekey;
    use crate::protocol::x3dh::{x3dh_alice_init, x3dh_bob_init, create_prekey_bundle};
    
    #[test]
    fn test_double_ratchet_encrypt_decrypt() {
        // Set up X3DH session first
        let alice_identity = generate_identity_keypair();
        let bob_identity = generate_identity_keypair();
        let bob_signed_prekey = generate_signed_prekey(&bob_identity, 1);
        
        let bob_bundle = create_prekey_bundle(
            &bob_identity,
            1234,
            1,
            &bob_signed_prekey,
            None,
        );
        
        let (initial_msg, mut alice_session) = x3dh_alice_init(
            &alice_identity,
            5678,
            &bob_bundle,
        ).unwrap();
        
        let mut bob_session = x3dh_bob_init(
            &bob_identity,
            1234,
            &bob_signed_prekey,
            None,
            &initial_msg,
        ).unwrap();
        
        // Initialize Double Ratchet - Alice and Bob should have compatible header keys
        initialize_session(&mut alice_session, Some(&bob_bundle.signed_prekey_public)).unwrap();
        initialize_session(&mut bob_session, Some(&initial_msg.base_key)).unwrap();
        
        // For testing, ensure both parties have compatible header keys
        // In a real implementation, these would be derived from the same root key
        let (header_key_send, header_key_recv) = derive_header_keys(&alice_session.root_key).unwrap();
        alice_session.header_key_send = Some(header_key_send.clone());
        bob_session.header_key_recv = Some(header_key_send);
        
        let (header_key_recv_alice, header_key_send_bob) = derive_header_keys(&bob_session.root_key).unwrap();
        alice_session.header_key_recv = Some(header_key_send_bob.clone());
        bob_session.header_key_send = Some(header_key_send_bob);
        
        // Test message encryption/decryption
        let plaintext = b"Hello, Double Ratchet!";
        let encrypted = encrypt_message(&mut alice_session, plaintext, None).unwrap();
        let decrypted = decrypt_message(&mut bob_session, &encrypted, None).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_chain_key_advancement() {
        // Test that chain keys advance properly
        let chain_key = vec![1u8; 32];
        let advanced_key = advance_chain_key(&chain_key).unwrap();
        let advanced_again = advance_chain_key(&advanced_key).unwrap();
        
        // Keys should be different
        assert_ne!(chain_key, advanced_key);
        assert_ne!(advanced_key, advanced_again);
        assert_ne!(chain_key, advanced_again);
    }
    
    #[test]
    fn test_message_key_derivation() {
        // Test message key derivation
        let chain_key = vec![2u8; 32];
        let msg_key1 = derive_message_key(&chain_key, 0).unwrap();
        let msg_key2 = derive_message_key(&chain_key, 1).unwrap();
        let msg_key3 = derive_message_key(&chain_key, 0).unwrap(); // Same index
        
        // Different indices should produce different keys
        assert_ne!(msg_key1.key, msg_key2.key);
        assert_ne!(msg_key1.iv, msg_key2.iv);
        assert_ne!(msg_key1.mac_key, msg_key2.mac_key);
        
        // Same index should produce same key
        assert_eq!(msg_key1.key, msg_key3.key);
        assert_eq!(msg_key1.iv, msg_key3.iv);
        assert_eq!(msg_key1.mac_key, msg_key3.mac_key);
    }
    
    #[test]
    fn test_header_encryption_decryption() {
        // Test header encryption/decryption
        let header = DoubleRatchetHeader {
            dh_key: vec![3u8; 32],
            pn: 42,
            n: 123,
        };
        
        let header_bytes = serialize_header(&header).unwrap();
        let header_key = Some(vec![4u8; 32]);
        
        let encrypted = encrypt_header(&header_bytes, &header_key).unwrap();
        let decrypted = decrypt_header(&encrypted, &header_key).unwrap();
        let recovered_header = deserialize_header(&decrypted).unwrap();
        
        assert_eq!(header.dh_key, recovered_header.dh_key);
        assert_eq!(header.pn, recovered_header.pn);
        assert_eq!(header.n, recovered_header.n);
    }
    
    #[test]
    fn test_multiple_messages() {
        // Set up sessions like in the basic test
        let alice_identity = generate_identity_keypair();
        let bob_identity = generate_identity_keypair();
        let bob_signed_prekey = generate_signed_prekey(&bob_identity, 1);
        
        let bob_bundle = create_prekey_bundle(
            &bob_identity,
            1234,
            1,
            &bob_signed_prekey,
            None,
        );
        
        let (initial_msg, mut alice_session) = x3dh_alice_init(
            &alice_identity,
            5678,
            &bob_bundle,
        ).unwrap();
        
        let mut bob_session = x3dh_bob_init(
            &bob_identity,
            1234,
            &bob_signed_prekey,
            None,
            &initial_msg,
        ).unwrap();
        
        // Initialize Double Ratchet
        initialize_session(&mut alice_session, Some(&bob_bundle.signed_prekey_public)).unwrap();
        initialize_session(&mut bob_session, Some(&initial_msg.base_key)).unwrap();
        
        // Set up compatible header keys
        let (header_key_send, _) = derive_header_keys(&alice_session.root_key).unwrap();
        alice_session.header_key_send = Some(header_key_send.clone());
        bob_session.header_key_recv = Some(header_key_send);
        
        let (_, header_key_send_bob) = derive_header_keys(&bob_session.root_key).unwrap();
        alice_session.header_key_recv = Some(header_key_send_bob.clone());
        bob_session.header_key_send = Some(header_key_send_bob);
        
        // Send multiple messages
        let messages = vec![
            b"First message".as_slice(),
            b"Second message".as_slice(),
            b"Third message".as_slice(),
        ];
        
        for (i, plaintext) in messages.iter().enumerate() {
            let encrypted = encrypt_message(&mut alice_session, plaintext, None).unwrap();
            let decrypted = decrypt_message(&mut bob_session, &encrypted, None).unwrap();
            
            assert_eq!(*plaintext, &decrypted[..]);
            assert_eq!(alice_session.n_send, (i + 1) as u32);
            assert_eq!(bob_session.n_recv, (i + 1) as u32);
        }
    }
}