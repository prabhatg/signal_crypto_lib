/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Sesame group messaging protocol implementation.
 * Provides secure group communication with sender key distribution,
 * message authentication, and support for out-of-order message delivery.
 */

// signal_crypto_lib/src/protocol/sesame.rs

use crate::types::*;
use crate::protocol::constants::*;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::rngs::OsRng;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum SesameError {
    InvalidKeySize,
    InvalidSignature,
    InvalidSenderKey,
    InvalidMessageNumber,
    EncryptionFailed,
    DecryptionFailed,
    InvalidMessage,
    UnknownSender,
    OutOfOrderMessage,
    CryptoError(String),
}

impl std::fmt::Display for SesameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SesameError::InvalidKeySize => write!(f, "Invalid key size"),
            SesameError::InvalidSignature => write!(f, "Invalid signature"),
            SesameError::InvalidSenderKey => write!(f, "Invalid sender key"),
            SesameError::InvalidMessageNumber => write!(f, "Invalid message number"),
            SesameError::EncryptionFailed => write!(f, "Encryption failed"),
            SesameError::DecryptionFailed => write!(f, "Decryption failed"),
            SesameError::InvalidMessage => write!(f, "Invalid message"),
            SesameError::UnknownSender => write!(f, "Unknown sender"),
            SesameError::OutOfOrderMessage => write!(f, "Out of order message"),
            SesameError::CryptoError(e) => write!(f, "Crypto error: {}", e),
        }
    }
}

impl std::error::Error for SesameError {}

/// Sender Key Distribution Message for establishing group keys
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyDistributionMessage {
    pub distribution_id: Vec<u8>,      // Unique identifier for this distribution
    pub chain_id: u32,                 // Chain identifier
    pub iteration: u32,                // Iteration within the chain
    pub chain_key: Vec<u8>,            // Current chain key
    pub signing_key: Vec<u8>,          // Ed25519 public signing key
    pub signature: Vec<u8>,            // Signature over the message
}

/// Complete Sesame message structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SesameMessage {
    pub sender_key_id: u32,            // Sender key identifier
    pub message_number: u32,           // Message number in the chain
    pub ciphertext: Vec<u8>,           // Encrypted message content
    pub signature: Vec<u8>,            // Ed25519 signature for authentication
}

/// Sender chain state for a specific sender in a group
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SenderChainState {
    pub sender_id: String,
    pub chain_key: Vec<u8>,
    pub message_number: u32,
    pub signing_key_public: Vec<u8>,   // Ed25519 public key for verification
    pub signing_key_private: Option<Vec<u8>>, // Ed25519 private key (only for own chain)
}

/// Group session state managing multiple sender chains
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupSessionState {
    pub group_id: String,
    pub own_sender_id: String,
    pub sender_chains: HashMap<String, SenderChainState>,
    pub skipped_message_keys: HashMap<(String, u32), Vec<u8>>, // (sender_id, msg_num) -> key
    pub max_skip: u32,
}

impl GroupSessionState {
    /// Create a new group session
    pub fn new(group_id: &str, own_sender_id: &str) -> Self {
        Self {
            group_id: group_id.to_string(),
            own_sender_id: own_sender_id.to_string(),
            sender_chains: HashMap::new(),
            skipped_message_keys: HashMap::new(),
            max_skip: 1000,
        }
    }

    /// Add a sender to the group using their distribution message
    pub fn add_sender(
        &mut self,
        sender_id: &str,
        distribution_msg: &SenderKeyDistributionMessage,
    ) -> Result<(), SesameError> {
        // Verify the distribution message signature
        verify_distribution_message(distribution_msg)?;

        let chain_state = SenderChainState {
            sender_id: sender_id.to_string(),
            chain_key: distribution_msg.chain_key.clone(),
            message_number: distribution_msg.iteration,
            signing_key_public: distribution_msg.signing_key.clone(),
            signing_key_private: None, // Only the sender has their private key
        };

        self.sender_chains.insert(sender_id.to_string(), chain_state);
        Ok(())
    }

    /// Initialize own sender chain
    pub fn initialize_own_chain(&mut self) -> Result<SenderKeyDistributionMessage, SesameError> {
        // Generate signing key pair
        let signing_key = SigningKey::generate(&mut OsRng);
        let signing_key_public = signing_key.verifying_key();

        // Generate initial chain key
        let initial_chain_key = generate_initial_chain_key(&self.group_id, &self.own_sender_id)?;

        let chain_state = SenderChainState {
            sender_id: self.own_sender_id.clone(),
            chain_key: initial_chain_key.clone(),
            message_number: 0,
            signing_key_public: signing_key_public.as_bytes().to_vec(),
            signing_key_private: Some(signing_key.as_bytes().to_vec()),
        };

        self.sender_chains.insert(self.own_sender_id.clone(), chain_state);

        // Create distribution message
        let distribution_id = generate_distribution_id(&self.group_id, &self.own_sender_id)?;
        let mut distribution_msg = SenderKeyDistributionMessage {
            distribution_id,
            chain_id: 0,
            iteration: 0,
            chain_key: initial_chain_key,
            signing_key: signing_key_public.as_bytes().to_vec(),
            signature: vec![],
        };

        // Sign the distribution message
        let message_bytes = serialize_distribution_message(&distribution_msg)?;
        let signature = signing_key.sign(&message_bytes);
        distribution_msg.signature = signature.to_bytes().to_vec();

        Ok(distribution_msg)
    }

    /// Encrypt a message for the group
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<SesameMessage, SesameError> {
        let chain_state = self.sender_chains.get_mut(&self.own_sender_id)
            .ok_or(SesameError::UnknownSender)?;

        // Derive message key from current chain key
        let message_key = derive_sesame_message_key(&chain_state.chain_key, chain_state.message_number)?;

        // Encrypt the message
        let ciphertext = encrypt_with_sesame_key(&message_key, plaintext, associated_data)?;

        // Advance the chain
        chain_state.chain_key = advance_sesame_chain_key(&chain_state.chain_key)?;
        let current_message_number = chain_state.message_number;
        chain_state.message_number += 1;

        // Create message structure
        let mut message = SesameMessage {
            sender_key_id: 0, // Will be set by the application
            message_number: current_message_number,
            ciphertext,
            signature: vec![],
        };

        // Sign the message
        if let Some(private_key_bytes) = &chain_state.signing_key_private {
            let signing_key = SigningKey::from_bytes(
                &<[u8; 32]>::try_from(private_key_bytes.as_slice())
                    .map_err(|_| SesameError::InvalidKeySize)?
            );

            let message_bytes = serialize_sesame_message(&message)?;
            let signature = signing_key.sign(&message_bytes);
            message.signature = signature.to_bytes().to_vec();
        }

        Ok(message)
    }

    /// Decrypt a message from a group member
    pub fn decrypt_message(
        &mut self,
        sender_id: &str,
        message: &SesameMessage,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, SesameError> {
        // First, verify the message signature
        {
            let chain_state = self.sender_chains.get(sender_id)
                .ok_or(SesameError::UnknownSender)?;
            verify_sesame_message(message, &chain_state.signing_key_public)?;
        }

        // Handle out-of-order messages
        {
            let chain_state = self.sender_chains.get(sender_id)
                .ok_or(SesameError::UnknownSender)?;
            if message.message_number > chain_state.message_number {
                self.skip_message_keys(sender_id, message.message_number)?;
            }
        }

        // Check if we have a skipped key for this message
        if let Some(message_key) = self.skipped_message_keys.remove(&(sender_id.to_string(), message.message_number)) {
            return decrypt_with_sesame_key(&message_key, &message.ciphertext, associated_data);
        }

        // Get chain state and derive message key
        let chain_state = self.sender_chains.get_mut(sender_id)
            .ok_or(SesameError::UnknownSender)?;

        let message_key = derive_sesame_message_key(&chain_state.chain_key, message.message_number)?;

        // Decrypt the message
        let plaintext = decrypt_with_sesame_key(&message_key, &message.ciphertext, associated_data)?;

        // Advance chain state if this is the next expected message
        if message.message_number == chain_state.message_number {
            chain_state.chain_key = advance_sesame_chain_key(&chain_state.chain_key)?;
            chain_state.message_number += 1;
        }

        Ok(plaintext)
    }

    /// Skip message keys for out-of-order messages
    fn skip_message_keys(&mut self, sender_id: &str, until: u32) -> Result<(), SesameError> {
        let chain_state = self.sender_chains.get_mut(sender_id)
            .ok_or(SesameError::UnknownSender)?;

        if chain_state.message_number + self.max_skip < until {
            return Err(SesameError::OutOfOrderMessage);
        }

        let mut current_chain_key = chain_state.chain_key.clone();
        
        for i in chain_state.message_number..until {
            let message_key = derive_sesame_message_key(&current_chain_key, i)?;
            self.skipped_message_keys.insert(
                (sender_id.to_string(), i),
                message_key.to_vec(),
            );
            current_chain_key = advance_sesame_chain_key(&current_chain_key)?;
        }

        chain_state.chain_key = current_chain_key;
        chain_state.message_number = until;

        Ok(())
    }
}

/// Generate initial chain key for a sender
fn generate_initial_chain_key(group_id: &str, sender_id: &str) -> Result<Vec<u8>, SesameError> {
    let info = format!("SesameChainKey-{}-{}", group_id, sender_id);
    let hkdf = Hkdf::<Sha256>::new(None, sender_id.as_bytes());
    let mut output = [0u8; 32];
    
    hkdf.expand(info.as_bytes(), &mut output)
        .map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    Ok(output.to_vec())
}

/// Generate distribution ID
fn generate_distribution_id(group_id: &str, sender_id: &str) -> Result<Vec<u8>, SesameError> {
    let info = format!("SesameDistribution-{}-{}", group_id, sender_id);
    let hkdf = Hkdf::<Sha256>::new(None, info.as_bytes());
    let mut output = [0u8; 16];
    
    hkdf.expand(b"DistributionID", &mut output)
        .map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    Ok(output.to_vec())
}

/// Derive message key from chain key
fn derive_sesame_message_key(chain_key: &[u8], message_number: u32) -> Result<[u8; 32], SesameError> {
    let hkdf = Hkdf::<Sha256>::new(None, chain_key);
    let mut output = [0u8; 32];
    
    let info = [&message_number.to_be_bytes()[..], b"SesameMessageKey"].concat();
    hkdf.expand(&info, &mut output)
        .map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    Ok(output)
}

/// Advance chain key
fn advance_sesame_chain_key(chain_key: &[u8]) -> Result<Vec<u8>, SesameError> {
    let hkdf = Hkdf::<Sha256>::new(None, chain_key);
    let mut output = [0u8; 32];
    
    hkdf.expand(b"SesameChainAdvance", &mut output)
        .map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    Ok(output.to_vec())
}

/// Encrypt with Sesame message key
fn encrypt_with_sesame_key(
    key: &[u8; 32],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, SesameError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    // Use message number as nonce (first 12 bytes of key derivation)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&key[..12]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let payload = Payload {
        msg: plaintext,
        aad: associated_data.unwrap_or(&[]),
    };
    
    cipher.encrypt(nonce, payload)
        .map_err(|_| SesameError::EncryptionFailed)
}

/// Decrypt with Sesame message key
fn decrypt_with_sesame_key(
    key: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, SesameError> {
    if key.len() != 32 {
        return Err(SesameError::InvalidKeySize);
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&key[..12]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data.unwrap_or(&[]),
    };
    
    cipher.decrypt(nonce, payload)
        .map_err(|_| SesameError::DecryptionFailed)
}

/// Verify distribution message signature
fn verify_distribution_message(msg: &SenderKeyDistributionMessage) -> Result<(), SesameError> {
    let verifying_key = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(&msg.signing_key[..])
            .map_err(|_| SesameError::InvalidKeySize)?
    ).map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    let signature = Signature::from_bytes(
        &<[u8; 64]>::try_from(&msg.signature[..])
            .map_err(|_| SesameError::InvalidKeySize)?
    );
    
    let message_bytes = serialize_distribution_message(msg)?;
    
    verifying_key.verify(&message_bytes, &signature)
        .map_err(|_| SesameError::InvalidSignature)
}

/// Verify Sesame message signature
fn verify_sesame_message(msg: &SesameMessage, public_key: &[u8]) -> Result<(), SesameError> {
    let verifying_key = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(public_key)
            .map_err(|_| SesameError::InvalidKeySize)?
    ).map_err(|e| SesameError::CryptoError(e.to_string()))?;
    
    let signature = Signature::from_bytes(
        &<[u8; 64]>::try_from(&msg.signature[..])
            .map_err(|_| SesameError::InvalidKeySize)?
    );
    
    let message_bytes = serialize_sesame_message(msg)?;
    
    verifying_key.verify(&message_bytes, &signature)
        .map_err(|_| SesameError::InvalidSignature)
}

/// Serialize distribution message for signing
fn serialize_distribution_message(msg: &SenderKeyDistributionMessage) -> Result<Vec<u8>, SesameError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&msg.distribution_id);
    bytes.extend_from_slice(&msg.chain_id.to_be_bytes());
    bytes.extend_from_slice(&msg.iteration.to_be_bytes());
    bytes.extend_from_slice(&msg.chain_key);
    bytes.extend_from_slice(&msg.signing_key);
    Ok(bytes)
}

/// Serialize Sesame message for signing
fn serialize_sesame_message(msg: &SesameMessage) -> Result<Vec<u8>, SesameError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&msg.sender_key_id.to_be_bytes());
    bytes.extend_from_slice(&msg.message_number.to_be_bytes());
    bytes.extend_from_slice(&msg.ciphertext);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_session_creation() {
        let session = GroupSessionState::new("test_group", "alice");
        assert_eq!(session.group_id, "test_group");
        assert_eq!(session.own_sender_id, "alice");
        assert!(session.sender_chains.is_empty());
    }

    #[test]
    fn test_own_chain_initialization() {
        let mut session = GroupSessionState::new("test_group", "alice");
        let distribution_msg = session.initialize_own_chain().unwrap();
        
        assert!(!distribution_msg.distribution_id.is_empty());
        assert!(!distribution_msg.chain_key.is_empty());
        assert!(!distribution_msg.signing_key.is_empty());
        assert!(!distribution_msg.signature.is_empty());
        
        // Verify we can find our own chain
        assert!(session.sender_chains.contains_key("alice"));
    }

    #[test]
    fn test_group_messaging() {
        // Create two group sessions
        let mut alice_session = GroupSessionState::new("test_group", "alice");
        let mut bob_session = GroupSessionState::new("test_group", "bob");
        
        // Initialize Alice's chain
        let alice_distribution = alice_session.initialize_own_chain().unwrap();
        
        // Initialize Bob's chain
        let bob_distribution = bob_session.initialize_own_chain().unwrap();
        
        // Add each other to their sessions
        alice_session.add_sender("bob", &bob_distribution).unwrap();
        bob_session.add_sender("alice", &alice_distribution).unwrap();
        
        // Alice sends a message
        let plaintext = b"Hello group from Alice!";
        let encrypted = alice_session.encrypt_message(plaintext, None).unwrap();
        
        // Bob receives and decrypts the message
        let decrypted = bob_session.decrypt_message("alice", &encrypted, None).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_chain_key_advancement() {
        let chain_key = vec![1u8; 32];
        let advanced = advance_sesame_chain_key(&chain_key).unwrap();
        let advanced_again = advance_sesame_chain_key(&advanced).unwrap();
        
        assert_ne!(chain_key, advanced);
        assert_ne!(advanced, advanced_again);
        assert_ne!(chain_key, advanced_again);
    }

    #[test]
    fn test_message_key_derivation() {
        let chain_key = vec![2u8; 32];
        let key1 = derive_sesame_message_key(&chain_key, 0).unwrap();
        let key2 = derive_sesame_message_key(&chain_key, 1).unwrap();
        let key3 = derive_sesame_message_key(&chain_key, 0).unwrap();
        
        assert_ne!(key1, key2);
        assert_eq!(key1, key3); // Same input should give same output
    }
}