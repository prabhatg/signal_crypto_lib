// signal_crypto_lib/src/security.rs
// Enhanced security features for Signal Protocol implementation

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Maximum age for messages to prevent replay attacks (24 hours)
const MAX_MESSAGE_AGE_SECS: u64 = 24 * 60 * 60;

/// Maximum number of recent message hashes to store for replay detection
const MAX_RECENT_MESSAGES: usize = 10000;

/// Maximum allowed clock skew between sender and receiver (5 minutes)
const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// Security errors that can occur during message processing
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityError {
    ReplayAttack,
    MessageTooOld,
    MessageFromFuture,
    InvalidMessageOrder,
    RateLimitExceeded,
    InvalidTimestamp,
    DuplicateMessage,
}

/// Message metadata for security validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub timestamp: u64,
    pub sender_id: String,
    pub message_number: u64,
    pub session_id: String,
}

/// Replay protection state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProtection {
    /// Recent message hashes for duplicate detection
    recent_messages: VecDeque<(Vec<u8>, u64)>, // (hash, timestamp)
    /// Last seen message number per sender
    last_message_numbers: HashMap<String, u64>,
    /// Message rate limiting per sender
    rate_limits: HashMap<String, RateLimit>,
}

/// Rate limiting state per sender
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimit {
    message_count: u32,
    window_start: u64,
    window_duration: u64, // seconds
    max_messages: u32,
}

impl ReplayProtection {
    /// Create new replay protection instance
    pub fn new() -> Self {
        Self {
            recent_messages: VecDeque::new(),
            last_message_numbers: HashMap::new(),
            rate_limits: HashMap::new(),
        }
    }

    /// Validate message against replay attacks and security policies
    pub fn validate_message(
        &mut self,
        message_data: &[u8],
        metadata: &MessageMetadata,
    ) -> Result<(), SecurityError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Validate timestamp
        self.validate_timestamp(metadata.timestamp, current_time)?;

        // 2. Check for replay attacks
        self.check_replay_attack(message_data, metadata.timestamp)?;

        // 3. Validate message ordering
        self.validate_message_order(&metadata.sender_id, metadata.message_number)?;

        // 4. Check rate limits
        self.check_rate_limit(&metadata.sender_id, current_time)?;

        // 5. Update state
        self.update_state(message_data, metadata, current_time);

        Ok(())
    }

    /// Validate message timestamp
    fn validate_timestamp(&self, msg_timestamp: u64, current_time: u64) -> Result<(), SecurityError> {
        // Check if message is too old
        if current_time > msg_timestamp + MAX_MESSAGE_AGE_SECS {
            return Err(SecurityError::MessageTooOld);
        }

        // Check if message is from the future (accounting for clock skew)
        if msg_timestamp > current_time + MAX_CLOCK_SKEW_SECS {
            return Err(SecurityError::MessageFromFuture);
        }

        Ok(())
    }

    /// Check for replay attacks using message hash
    fn check_replay_attack(&self, message_data: &[u8], timestamp: u64) -> Result<(), SecurityError> {
        let message_hash = self.compute_message_hash(message_data, timestamp);
        
        // Check if we've seen this exact message before
        for (stored_hash, _) in &self.recent_messages {
            if stored_hash == &message_hash {
                return Err(SecurityError::ReplayAttack);
            }
        }

        Ok(())
    }

    /// Validate message ordering per sender
    fn validate_message_order(&self, sender_id: &str, message_number: u64) -> Result<(), SecurityError> {
        if let Some(&last_number) = self.last_message_numbers.get(sender_id) {
            // Allow some out-of-order delivery, but not too far back
            if message_number <= last_number.saturating_sub(100) {
                return Err(SecurityError::InvalidMessageOrder);
            }
        }

        Ok(())
    }

    /// Check rate limits per sender
    fn check_rate_limit(&mut self, sender_id: &str, current_time: u64) -> Result<(), SecurityError> {
        let rate_limit = self.rate_limits.entry(sender_id.to_string()).or_insert(RateLimit {
            message_count: 0,
            window_start: current_time,
            window_duration: 60, // 1 minute window
            max_messages: 100,   // 100 messages per minute
        });

        // Reset window if expired
        if current_time >= rate_limit.window_start + rate_limit.window_duration {
            rate_limit.message_count = 0;
            rate_limit.window_start = current_time;
        }

        // Check if rate limit exceeded
        if rate_limit.message_count >= rate_limit.max_messages {
            return Err(SecurityError::RateLimitExceeded);
        }

        rate_limit.message_count += 1;
        Ok(())
    }

    /// Update internal state after successful validation
    fn update_state(&mut self, message_data: &[u8], metadata: &MessageMetadata, current_time: u64) {
        // Add message hash to recent messages
        let message_hash = self.compute_message_hash(message_data, metadata.timestamp);
        self.recent_messages.push_back((message_hash, metadata.timestamp));

        // Trim old messages
        while self.recent_messages.len() > MAX_RECENT_MESSAGES {
            self.recent_messages.pop_front();
        }

        // Remove expired message hashes
        let cutoff_time = current_time.saturating_sub(MAX_MESSAGE_AGE_SECS);
        while let Some((_, timestamp)) = self.recent_messages.front() {
            if *timestamp < cutoff_time {
                self.recent_messages.pop_front();
            } else {
                break;
            }
        }

        // Update last message number
        let current_last = self.last_message_numbers.get(&metadata.sender_id).copied().unwrap_or(0);
        if metadata.message_number > current_last {
            self.last_message_numbers.insert(metadata.sender_id.clone(), metadata.message_number);
        }
    }

    /// Compute secure hash of message for replay detection
    fn compute_message_hash(&self, message_data: &[u8], timestamp: u64) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message_data);
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize().to_vec()
    }

    /// Clean up expired state
    pub fn cleanup_expired(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Remove expired message hashes
        let cutoff_time = current_time.saturating_sub(MAX_MESSAGE_AGE_SECS);
        while let Some((_, timestamp)) = self.recent_messages.front() {
            if *timestamp < cutoff_time {
                self.recent_messages.pop_front();
            } else {
                break;
            }
        }

        // Clean up old rate limit entries
        self.rate_limits.retain(|_, rate_limit| {
            current_time < rate_limit.window_start + rate_limit.window_duration + 3600 // Keep for 1 hour after window
        });
    }
}

/// Secure memory operations
pub struct SecureMemory;

impl SecureMemory {
    /// Securely zero memory
    pub fn zero(data: &mut [u8]) {
        // Use volatile write to prevent compiler optimization
        for byte in data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }

    /// Constant-time comparison to prevent timing attacks
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }

        result == 0
    }

    /// Generate cryptographically secure random bytes
    pub fn random_bytes(len: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}

/// Key derivation with additional security measures
pub struct SecureKeyDerivation;

impl SecureKeyDerivation {
    /// Derive key with domain separation and additional entropy
    pub fn derive_key(
        input_key: &[u8],
        salt: &[u8],
        info: &[u8],
        domain: &str,
        output_len: usize,
    ) -> Result<Vec<u8>, &'static str> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        // Add domain separation to prevent key reuse across different contexts
        let mut domain_separated_info = Vec::new();
        domain_separated_info.extend_from_slice(domain.as_bytes());
        domain_separated_info.push(0x00); // Separator
        domain_separated_info.extend_from_slice(info);

        let hk = Hkdf::<Sha256>::new(Some(salt), input_key);
        let mut output = vec![0u8; output_len];
        
        hk.expand(&domain_separated_info, &mut output)
            .map_err(|_| "Key derivation failed")?;

        Ok(output)
    }

    /// Derive multiple keys from a single input with different domains
    pub fn derive_multiple_keys(
        input_key: &[u8],
        salt: &[u8],
        domains: &[(&str, usize)], // (domain, key_length) pairs
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut keys = Vec::new();
        
        for (domain, key_len) in domains {
            let key = Self::derive_key(input_key, salt, b"", domain, *key_len)?;
            keys.push(key);
        }

        Ok(keys)
    }
}

/// Message authentication with additional security checks
pub struct MessageAuthenticator;

impl MessageAuthenticator {
    /// Compute HMAC with additional metadata
    pub fn compute_hmac(
        key: &[u8],
        message: &[u8],
        metadata: &MessageMetadata,
    ) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        
        // Include metadata in HMAC to prevent tampering
        mac.update(message);
        mac.update(&metadata.timestamp.to_be_bytes());
        mac.update(metadata.sender_id.as_bytes());
        mac.update(&metadata.message_number.to_be_bytes());
        mac.update(metadata.session_id.as_bytes());
        
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC with constant-time comparison
    pub fn verify_hmac(
        key: &[u8],
        message: &[u8],
        metadata: &MessageMetadata,
        expected_hmac: &[u8],
    ) -> bool {
        let computed_hmac = Self::compute_hmac(key, message, metadata);
        SecureMemory::constant_time_eq(&computed_hmac, expected_hmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_protection_basic() {
        let mut protection = ReplayProtection::new();
        let message = b"test message";
        let metadata = MessageMetadata {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            sender_id: "alice".to_string(),
            message_number: 1,
            session_id: "session1".to_string(),
        };

        // First message should be accepted
        assert!(protection.validate_message(message, &metadata).is_ok());

        // Same message should be rejected (replay attack)
        assert_eq!(
            protection.validate_message(message, &metadata),
            Err(SecurityError::ReplayAttack)
        );
    }

    #[test]
    fn test_message_ordering() {
        let mut protection = ReplayProtection::new();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Send messages in order
        for i in 1..=5 {
            let message = format!("message {}", i);
            let metadata = MessageMetadata {
                timestamp: current_time,
                sender_id: "alice".to_string(),
                message_number: i,
                session_id: "session1".to_string(),
            };
            assert!(protection.validate_message(message.as_bytes(), &metadata).is_ok());
        }

        // Very old message should be rejected
        let old_metadata = MessageMetadata {
            timestamp: current_time,
            sender_id: "alice".to_string(),
            message_number: 1, // Much older than current (5)
            session_id: "session1".to_string(),
        };
        // This should still work as it's within the allowed window
        assert!(protection.validate_message(b"old message", &old_metadata).is_ok());
    }

    #[test]
    fn test_timestamp_validation() {
        let mut protection = ReplayProtection::new();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Message too old
        let old_metadata = MessageMetadata {
            timestamp: current_time - MAX_MESSAGE_AGE_SECS - 1,
            sender_id: "alice".to_string(),
            message_number: 1,
            session_id: "session1".to_string(),
        };
        assert_eq!(
            protection.validate_message(b"old message", &old_metadata),
            Err(SecurityError::MessageTooOld)
        );

        // Message from future
        let future_metadata = MessageMetadata {
            timestamp: current_time + MAX_CLOCK_SKEW_SECS + 1,
            sender_id: "alice".to_string(),
            message_number: 1,
            session_id: "session1".to_string(),
        };
        assert_eq!(
            protection.validate_message(b"future message", &future_metadata),
            Err(SecurityError::MessageFromFuture)
        );
    }

    #[test]
    fn test_secure_memory_operations() {
        // Test constant time comparison
        assert!(SecureMemory::constant_time_eq(b"hello", b"hello"));
        assert!(!SecureMemory::constant_time_eq(b"hello", b"world"));
        assert!(!SecureMemory::constant_time_eq(b"hello", b"hell"));

        // Test memory zeroing
        let mut data = vec![0xAA; 32];
        SecureMemory::zero(&mut data);
        assert_eq!(data, vec![0; 32]);

        // Test random bytes generation
        let random1 = SecureMemory::random_bytes(32);
        let random2 = SecureMemory::random_bytes(32);
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2); // Should be different
    }

    #[test]
    fn test_key_derivation() {
        let input_key = b"master key";
        let salt = b"salt";
        
        // Test single key derivation
        let key1 = SecureKeyDerivation::derive_key(
            input_key, salt, b"info", "domain1", 32
        ).unwrap();
        let key2 = SecureKeyDerivation::derive_key(
            input_key, salt, b"info", "domain2", 32
        ).unwrap();
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Different domains should produce different keys

        // Test multiple key derivation
        let domains = [("encryption", 32), ("authentication", 32), ("header", 16)];
        let keys = SecureKeyDerivation::derive_multiple_keys(input_key, salt, &domains).unwrap();
        
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].len(), 32);
        assert_eq!(keys[1].len(), 32);
        assert_eq!(keys[2].len(), 16);
        
        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_message_authentication() {
        let key = b"authentication key";
        let message = b"test message";
        let metadata = MessageMetadata {
            timestamp: 1234567890,
            sender_id: "alice".to_string(),
            message_number: 42,
            session_id: "session1".to_string(),
        };

        let hmac = MessageAuthenticator::compute_hmac(key, message, &metadata);
        assert!(MessageAuthenticator::verify_hmac(key, message, &metadata, &hmac));

        // Wrong key should fail
        let wrong_key = b"wrong key";
        assert!(!MessageAuthenticator::verify_hmac(wrong_key, message, &metadata, &hmac));

        // Modified message should fail
        let wrong_message = b"modified message";
        assert!(!MessageAuthenticator::verify_hmac(key, wrong_message, &metadata, &hmac));
    }
}