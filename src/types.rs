// signal_crypto_lib/src/types.rs

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IdentityKeyPair {
    pub dh_public: Vec<u8>,    // X25519 public key for DH
    pub dh_private: Vec<u8>,   // X25519 private key for DH
    pub ed_public: Vec<u8>,    // Ed25519 public key for signatures
    pub ed_private: Vec<u8>,   // Ed25519 private key for signatures
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub public: Vec<u8>,   // X25519 public key
    pub private: Vec<u8>,  // X25519 private key (kept secret)
    pub signature: Vec<u8>, // Ed25519 signature over public
    pub timestamp: u64,    // When this key was created
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub key_id: u32,
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub registration_id: u32,           // Device registration ID
    pub device_id: u32,                 // Device ID
    pub identity_key: Vec<u8>,          // X25519 public key for DH operations
    pub identity_key_ed: Vec<u8>,       // Ed25519 public key for signatures
    pub signed_prekey_id: u32,          // ID of the signed prekey
    pub signed_prekey_public: Vec<u8>,  // X25519 public key
    pub signed_prekey_signature: Vec<u8>, // Ed25519 signature
    pub one_time_prekey_id: Option<u32>, // ID of one-time prekey (if present)
    pub one_time_prekey: Option<Vec<u8>>, // X25519 public key (if present)
}

// X3DH Initial Message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3DHInitialMessage {
    pub registration_id: u32,
    pub one_time_prekey_id: Option<u32>,
    pub signed_prekey_id: u32,
    pub base_key: Vec<u8>,  // Ephemeral public key (EK_A)
    pub identity_key: Vec<u8>, // Sender's identity DH key (IK_A) - X25519 for DH
    pub identity_key_ed: Vec<u8>, // Sender's identity Ed25519 key for signatures
    pub message: Vec<u8>,  // First Double Ratchet message
}

// Double Ratchet Header (unencrypted part)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleRatchetHeader {
    pub dh_key: Vec<u8>,    // DH ratchet public key
    pub pn: u32,            // Previous chain message count
    pub n: u32,             // Message number
}

// Complete Double Ratchet message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleRatchetMessage {
    pub header: Vec<u8>,     // Encrypted header
    pub ciphertext: Vec<u8>, // Encrypted message body
}

// Message key for encryption/decryption
#[derive(Debug, Clone)]
pub struct MessageKey {
    pub key: [u8; 32],      // AES-256 key
    pub iv: [u8; 16],       // AES IV
    pub mac_key: [u8; 32],  // HMAC key
}

// Chain key for ratcheting
#[derive(Debug, Clone)]
pub struct ChainKey {
    pub key: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub associated_data: Option<Vec<u8>>,
    pub message_index: u32,
}

// Complete Session State for Double Ratchet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub registration_id: u32,
    pub device_id: u32,
    
    // DH Ratchet State
    pub dh_self_private: Vec<u8>,      // Current DH private key
    pub dh_self_public: Vec<u8>,       // Current DH public key
    pub dh_remote: Option<Vec<u8>>,    // Remote DH public key
    
    // Root Key
    pub root_key: Vec<u8>,             // Root key for deriving chain keys
    
    // Chain Keys
    pub chain_key_send: Option<Vec<u8>>, // Sending chain key
    pub chain_key_recv: Option<Vec<u8>>, // Receiving chain key
    
    // Header Keys for header encryption
    pub header_key_send: Option<Vec<u8>>, // Header encryption key for sending
    pub header_key_recv: Option<Vec<u8>>, // Header encryption key for receiving
    pub next_header_key_send: Option<Vec<u8>>, // Next header key for sending
    pub next_header_key_recv: Option<Vec<u8>>, // Next header key for receiving
    
    // Message Counters
    pub n_send: u32,                   // Send message number
    pub n_recv: u32,                   // Receive message number
    pub pn: u32,                       // Previous chain length
    
    // Skipped Message Keys: (header_key, message_number) -> message_key
    pub mk_skipped: HashMap<(Vec<u8>, u32), Vec<u8>>, // Skipped message keys
    
    // Maximum number of skipped message keys to store
    pub max_skip: u32,
}

// X3DH Shared Secret components
#[derive(Debug, Clone)]
pub struct X3DHSharedSecret {
    pub dh1: Vec<u8>,
    pub dh2: Vec<u8>,
    pub dh3: Vec<u8>,
    pub dh4: Option<Vec<u8>>,
    pub associated_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKey {
    pub key_id: u32,
    pub symmetric_key: Vec<u8>,
}

/// General Signal Protocol error type
#[derive(Debug, Clone)]
pub enum SignalError {
    /// Cryptographic operation failed
    CryptographicError(String),
    /// Invalid input provided
    InvalidInput(String),
    /// Authentication failed
    AuthenticationFailed(String),
    /// Session not found or invalid
    SessionError(String),
    /// Network or I/O error
    NetworkError(String),
    /// Database operation failed
    DatabaseError(String),
    /// Serialization/deserialization error
    SerializationError(String),
    /// Protocol version mismatch
    ProtocolError(String),
    /// Key derivation or management error
    KeyError(String),
    /// Message decryption failed
    DecryptionError(String),
    /// Message encryption failed
    EncryptionError(String),
    /// Invalid message format
    InvalidMessage(String),
    /// Rate limiting or quota exceeded
    RateLimitExceeded(String),
    /// Permission denied
    PermissionDenied(String),
    /// Resource not found
    NotFound(String),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            SignalError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            SignalError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            SignalError::SessionError(msg) => write!(f, "Session error: {}", msg),
            SignalError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            SignalError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            SignalError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            SignalError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            SignalError::KeyError(msg) => write!(f, "Key error: {}", msg),
            SignalError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            SignalError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            SignalError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            SignalError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {}", msg),
            SignalError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            SignalError::NotFound(msg) => write!(f, "Not found: {}", msg),
            SignalError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for SignalError {}
