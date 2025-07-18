//! Unit tests for Double Ratchet messaging protocol
//! 
//! Tests the Double Ratchet protocol implementation for secure messaging
//! with forward secrecy, post-compromise security, and message ordering.

use signal_crypto_lib::*;
use crate::common::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Test basic Double Ratchet initialization and first message
    #[tokio::test]
    async fn test_double_ratchet_initialization() {
        let mut ctx = TestContext::with_default();
        
        // Create Alice and Bob identities
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        
        // Perform X3DH to get shared secret
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let bob_one_time_prekeys = generate_one_time_prekeys(1);
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
        };
        
        let (shared_secret, alice_ephemeral_key) = 
            x3dh_initiate(&alice_identity, &bob_prekey_bundle).unwrap();
        
        // Initialize Double Ratchet sessions
        let mut alice_session = time_operation!(ctx, "double_ratchet_init_alice", {
            DoubleRatchetSession::init_alice(&shared_secret, &bob_identity.public_key)
        });
        
        let mut bob_session = time_operation!(ctx, "double_ratchet_init_bob", {
            DoubleRatchetSession::init_bob(
                &shared_secret,
                &bob_signed_prekey.private_key,
                &alice_ephemeral_key.public_key,
            )
        });
        
        assert!(alice_session.is_ok(), "Alice session initialization should succeed");
        assert!(bob_session.is_ok(), "Bob session initialization should succeed");
        
        let mut alice_session = alice_session.unwrap();
        let mut bob_session = bob_session.unwrap();
        
        // Test first message from Alice to Bob
        let message = b"Hello Bob!";
        let encrypted_message = time_operation!(ctx, "double_ratchet_encrypt", {
            alice_session.encrypt(message)
        });
        
        assert!(encrypted_message.is_ok(), "Message encryption should succeed");
        let encrypted_message = encrypted_message.unwrap();
        
        // Verify message structure
        ProtocolAssertions::assert_valid_double_ratchet_message(&encrypted_message, 
            "First encrypted message");
        
        // Decrypt message at Bob's end
        let decrypted_message = time_operation!(ctx, "double_ratchet_decrypt", {
            bob_session.decrypt(&encrypted_message)
        });
        
        assert!(decrypted_message.is_ok(), "Message decryption should succeed");
        let decrypted_message = decrypted_message.unwrap();
        
        assert_eq!(decrypted_message, message, "Decrypted message should match original");
        
        // Verify cryptographic properties
        CryptoAssertions::assert_sufficient_entropy(&encrypted_message.ciphertext, 7.0, 
            "Encrypted message");
        CryptoAssertions::assert_appears_random(&encrypted_message.ciphertext, 
            "Encrypted message");
        
        println!("✓ Double Ratchet initialization test passed");
    }

    /// Test bidirectional messaging with key ratcheting
    #[tokio::test]
    async fn test_double_ratchet_bidirectional_messaging() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        // Alice sends first message
        let alice_msg1 = b"Hello from Alice!";
        let encrypted_msg1 = alice_session.encrypt(alice_msg1).unwrap();
        let decrypted_msg1 = bob_session.decrypt(&encrypted_msg1).unwrap();
        assert_eq!(decrypted_msg1, alice_msg1);
        
        // Bob responds (triggers DH ratchet)
        let bob_msg1 = b"Hello from Bob!";
        let encrypted_bob_msg1 = bob_session.encrypt(bob_msg1).unwrap();
        let decrypted_bob_msg1 = alice_session.decrypt(&encrypted_bob_msg1).unwrap();
        assert_eq!(decrypted_bob_msg1, bob_msg1);
        
        // Alice sends another message (new chain)
        let alice_msg2 = b"How are you?";
        let encrypted_msg2 = alice_session.encrypt(alice_msg2).unwrap();
        let decrypted_msg2 = bob_session.decrypt(&encrypted_msg2).unwrap();
        assert_eq!(decrypted_msg2, alice_msg2);
        
        // Bob sends multiple messages
        let bob_messages = [b"I'm good!", b"Thanks for asking!", b"How about you?"];
        let mut encrypted_bob_messages = Vec::new();
        
        for msg in &bob_messages {
            let encrypted = bob_session.encrypt(msg).unwrap();
            encrypted_bob_messages.push(encrypted);
        }
        
        // Alice decrypts Bob's messages
        for (i, encrypted) in encrypted_bob_messages.iter().enumerate() {
            let decrypted = alice_session.decrypt(encrypted).unwrap();
            assert_eq!(decrypted, bob_messages[i]);
        }
        
        // Verify forward secrecy: old keys should be deleted
        SecurityAssertions::assert_forward_secrecy(&alice_session, &bob_session, 
            "After bidirectional messaging");
        
        println!("✓ Double Ratchet bidirectional messaging test passed");
    }

    /// Test out-of-order message delivery
    #[tokio::test]
    async fn test_double_ratchet_out_of_order_messages() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        // Alice sends multiple messages
        let messages = [
            b"Message 1",
            b"Message 2", 
            b"Message 3",
            b"Message 4",
            b"Message 5",
        ];
        
        let mut encrypted_messages = Vec::new();
        for msg in &messages {
            let encrypted = alice_session.encrypt(msg).unwrap();
            encrypted_messages.push(encrypted);
        }
        
        // Deliver messages out of order: 1, 3, 2, 5, 4
        let delivery_order = [0, 2, 1, 4, 3];
        let mut decrypted_messages = vec![None; messages.len()];
        
        for &index in &delivery_order {
            let decrypted = bob_session.decrypt(&encrypted_messages[index]).unwrap();
            decrypted_messages[index] = Some(decrypted);
        }
        
        // Verify all messages were decrypted correctly
        for (i, original) in messages.iter().enumerate() {
            assert_eq!(decrypted_messages[i].as_ref().unwrap(), original,
                "Message {} should be decrypted correctly", i + 1);
        }
        
        // Verify message chain integrity
        ProtocolAssertions::assert_message_chain_integrity(&bob_session, 
            "After out-of-order delivery");
        
        println!("✓ Double Ratchet out-of-order messages test passed");
    }

    /// Test skipped message handling
    #[tokio::test]
    async fn test_double_ratchet_skipped_messages() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        // Alice sends messages 1, 2, 3, 4, 5
        let messages = [
            b"Message 1",
            b"Message 2", 
            b"Message 3",
            b"Message 4",
            b"Message 5",
        ];
        
        let mut encrypted_messages = Vec::new();
        for msg in &messages {
            let encrypted = alice_session.encrypt(msg).unwrap();
            encrypted_messages.push(encrypted);
        }
        
        // Bob receives only messages 1, 3, and 5 (2 and 4 are skipped)
        let received_indices = [0, 2, 4];
        
        for &index in &received_indices {
            let decrypted = bob_session.decrypt(&encrypted_messages[index]).unwrap();
            assert_eq!(decrypted, messages[index]);
        }
        
        // Later, Bob receives the skipped messages 2 and 4
        let skipped_indices = [1, 3];
        
        for &index in &skipped_indices {
            let decrypted = bob_session.decrypt(&encrypted_messages[index]).unwrap();
            assert_eq!(decrypted, messages[index]);
        }
        
        // Verify skipped message keys are properly managed
        ProtocolAssertions::assert_skipped_keys_management(&bob_session, 
            "After processing skipped messages");
        
        println!("✓ Double Ratchet skipped messages test passed");
    }

    /// Test message replay protection
    #[tokio::test]
    async fn test_double_ratchet_replay_protection() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        // Alice sends a message
        let message = b"Original message";
        let encrypted_message = alice_session.encrypt(message).unwrap();
        
        // Bob decrypts it successfully
        let decrypted = bob_session.decrypt(&encrypted_message).unwrap();
        assert_eq!(decrypted, message);
        
        // Attempt to decrypt the same message again (replay attack)
        let replay_result = bob_session.decrypt(&encrypted_message);
        assert!(replay_result.is_err(), "Replay attack should be detected");
        
        match replay_result.unwrap_err() {
            DoubleRatchetError::ReplayAttack => {
                println!("✓ Correctly detected replay attack");
            }
            other => panic!("Expected ReplayAttack error, got: {:?}", other),
        }
        
        // Verify session state is not corrupted by replay attempt
        let new_message = b"New message after replay attempt";
        let new_encrypted = alice_session.encrypt(new_message).unwrap();
        let new_decrypted = bob_session.decrypt(&new_encrypted).unwrap();
        assert_eq!(new_decrypted, new_message);
        
        println!("✓ Double Ratchet replay protection test passed");
    }

    /// Test forward secrecy properties
    #[tokio::test]
    async fn test_double_ratchet_forward_secrecy() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        // Exchange several messages to advance the ratchet
        let messages = [
            (b"Alice message 1", true),
            (b"Bob message 1", false),
            (b"Alice message 2", true),
            (b"Alice message 3", true),
            (b"Bob message 2", false),
            (b"Bob message 3", false),
        ];
        
        let mut all_encrypted = Vec::new();
        
        for (msg, is_alice) in &messages {
            let encrypted = if *is_alice {
                alice_session.encrypt(msg).unwrap()
            } else {
                bob_session.encrypt(msg).unwrap()
            };
            
            let _decrypted = if *is_alice {
                bob_session.decrypt(&encrypted).unwrap()
            } else {
                alice_session.decrypt(&encrypted).unwrap()
            };
            
            all_encrypted.push(encrypted);
        }
        
        // Simulate key compromise: extract current session state
        let alice_state_snapshot = alice_session.export_state();
        let bob_state_snapshot = bob_session.export_state();
        
        // Continue messaging after "compromise"
        let post_compromise_msg = b"Message after compromise";
        let post_encrypted = alice_session.encrypt(post_compromise_msg).unwrap();
        let post_decrypted = bob_session.decrypt(&post_encrypted).unwrap();
        assert_eq!(post_decrypted, post_compromise_msg);
        
        // Verify that compromised state cannot decrypt future messages
        SecurityAssertions::assert_forward_secrecy_after_compromise(
            &alice_state_snapshot,
            &bob_state_snapshot,
            &post_encrypted,
            "Forward secrecy after key compromise"
        );
        
        // Verify that old messages cannot be decrypted with current state
        SecurityAssertions::assert_past_message_protection(
            &alice_session,
            &bob_session,
            &all_encrypted[0],
            "Protection of past messages"
        );
        
        println!("✓ Double Ratchet forward secrecy test passed");
    }

    /// Test post-compromise security
    #[tokio::test]
    async fn test_double_ratchet_post_compromise_security() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        // Normal messaging before compromise
        let pre_msg = b"Message before compromise";
        let pre_encrypted = alice_session.encrypt(pre_msg).unwrap();
        let pre_decrypted = bob_session.decrypt(&pre_encrypted).unwrap();
        assert_eq!(pre_decrypted, pre_msg);
        
        // Simulate compromise: attacker gets session state
        let compromised_alice_state = alice_session.export_state();
        let compromised_bob_state = bob_session.export_state();
        
        // Continue normal operation (DH ratchet step heals the compromise)
        let healing_msg = b"Bob's healing message";
        let healing_encrypted = bob_session.encrypt(healing_msg).unwrap();
        let healing_decrypted = alice_session.decrypt(&healing_encrypted).unwrap();
        assert_eq!(healing_decrypted, healing_msg);
        
        // Alice responds (completes the healing)
        let post_healing_msg = b"Alice's post-healing message";
        let post_healing_encrypted = alice_session.encrypt(post_healing_msg).unwrap();
        let post_healing_decrypted = bob_session.decrypt(&post_healing_encrypted).unwrap();
        assert_eq!(post_healing_decrypted, post_healing_msg);
        
        // Verify that compromised state cannot decrypt post-healing messages
        SecurityAssertions::assert_post_compromise_security(
            &compromised_alice_state,
            &compromised_bob_state,
            &post_healing_encrypted,
            "Post-compromise security after healing"
        );
        
        // Continue secure messaging
        let secure_msg = b"Secure message after healing";
        let secure_encrypted = bob_session.encrypt(secure_msg).unwrap();
        let secure_decrypted = alice_session.decrypt(&secure_encrypted).unwrap();
        assert_eq!(secure_decrypted, secure_msg);
        
        println!("✓ Double Ratchet post-compromise security test passed");
    }

    /// Test message authentication and integrity
    #[tokio::test]
    async fn test_double_ratchet_message_authentication() {
        let mut ctx = TestContext::with_default();
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        let message = b"Authenticated message";
        let encrypted_message = alice_session.encrypt(message).unwrap();
        
        // Test tampering with ciphertext
        let mut tampered_message = encrypted_message.clone();
        tampered_message.ciphertext[0] ^= 0xFF;
        
        let tampered_result = bob_session.decrypt(&tampered_message);
        assert!(tampered_result.is_err(), "Tampered ciphertext should be rejected");
        
        // Test tampering with header
        let mut tampered_header = encrypted_message.clone();
        tampered_header.header.dh_public_key[0] ^= 0xFF;
        
        let header_tampered_result = bob_session.decrypt(&tampered_header);
        assert!(header_tampered_result.is_err(), "Tampered header should be rejected");
        
        // Test tampering with MAC
        let mut tampered_mac = encrypted_message.clone();
        tampered_mac.mac[0] ^= 0xFF;
        
        let mac_tampered_result = bob_session.decrypt(&tampered_mac);
        assert!(mac_tampered_result.is_err(), "Tampered MAC should be rejected");
        
        // Verify original message still decrypts correctly
        let decrypted = bob_session.decrypt(&encrypted_message).unwrap();
        assert_eq!(decrypted, message);
        
        // Verify authentication properties
        SecurityAssertions::assert_message_authentication(&encrypted_message, 
            "Double Ratchet message authentication");
        
        println!("✓ Double Ratchet message authentication test passed");
    }

    /// Test performance characteristics
    #[tokio::test]
    async fn test_double_ratchet_performance() {
        let mut ctx = TestContext::with_default();
        
        if !ctx.config.performance_mode {
            println!("⏭ Skipping performance test (not in performance mode)");
            return;
        }
        
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        let message = b"Performance test message";
        let benchmark = BenchmarkRunner::new()
            .with_iterations(1000)
            .with_warmup(100);
        
        // Benchmark encryption
        let encrypt_result = benchmark.run("double_ratchet_encrypt", || {
            alice_session.encrypt(message)
                .map_err(|e| format!("Encryption error: {:?}", e))
        });
        
        encrypt_result.print_summary();
        
        // Benchmark decryption
        let encrypted_message = alice_session.encrypt(message).unwrap();
        let decrypt_result = benchmark.run("double_ratchet_decrypt", || {
            bob_session.decrypt(&encrypted_message)
                .map_err(|e| format!("Decryption error: {:?}", e))
        });
        
        decrypt_result.print_summary();
        
        // Verify performance requirements
        assert!(encrypt_result.avg_duration.as_millis() < 5, 
            "Encryption should complete in under 5ms on average");
        assert!(decrypt_result.avg_duration.as_millis() < 5,
            "Decryption should complete in under 5ms on average");
        assert!(encrypt_result.ops_per_second > 200.0,
            "Encryption should support at least 200 operations per second");
        assert!(decrypt_result.ops_per_second > 200.0,
            "Decryption should support at least 200 operations per second");
        
        println!("✓ Double Ratchet performance test passed");
    }

    /// Test concurrent message processing
    #[tokio::test]
    async fn test_double_ratchet_concurrent_processing() {
        let mut ctx = TestContext::with_default();
        
        let (alice_session, bob_session) = create_test_sessions(&mut ctx).await;
        
        // Use Arc<Mutex<>> for thread-safe access
        let alice_session = std::sync::Arc::new(std::sync::Mutex::new(alice_session));
        let bob_session = std::sync::Arc::new(std::sync::Mutex::new(bob_session));
        
        let mut handles = Vec::new();
        
        // Launch concurrent encryption operations
        for i in 0..10 {
            let alice_session = alice_session.clone();
            let message = format!("Concurrent message {}", i);
            
            let handle = tokio::spawn(async move {
                let mut session = alice_session.lock().unwrap();
                session.encrypt(message.as_bytes())
            });
            
            handles.push(handle);
        }
        
        // Wait for all encryptions to complete
        let mut encrypted_messages = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent encryption should succeed");
            encrypted_messages.push(result.unwrap());
        }
        
        // Decrypt all messages
        for encrypted in encrypted_messages {
            let mut session = bob_session.lock().unwrap();
            let decrypted = session.decrypt(&encrypted).unwrap();
            assert!(decrypted.starts_with(b"Concurrent message"));
        }
        
        println!("✓ Double Ratchet concurrent processing test passed");
    }

    /// Test error handling and edge cases
    #[tokio::test]
    async fn test_double_ratchet_error_handling() {
        let mut ctx = TestContext::with_default();
        
        // Test initialization with invalid parameters
        let invalid_secret = vec![]; // Empty secret
        let dummy_key = vec![0u8; 32];
        
        let result = DoubleRatchetSession::init_alice(&invalid_secret, &dummy_key);
        assert!(result.is_err(), "Should fail with invalid shared secret");
        
        // Test with malformed messages
        let (mut alice_session, mut bob_session) = create_test_sessions(&mut ctx).await;
        
        let malformed_message = DoubleRatchetMessage {
            header: MessageHeader {
                dh_public_key: vec![], // Invalid key
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: vec![],
            mac: vec![],
        };
        
        let result = bob_session.decrypt(&malformed_message);
        assert!(result.is_err(), "Should fail with malformed message");
        
        // Test error message safety
        if let Err(error) = result {
            let error_message = format!("{:?}", error);
            let sensitive_data = [
                &hex::encode(&alice_session.export_state().root_key),
            ];
            
            ErrorAssertions::assert_safe_error_messages(&error, &sensitive_data, 
                "Double Ratchet error messages");
        }
        
        println!("✓ Double Ratchet error handling test passed");
    }
}

/// Helper functions for Double Ratchet testing

/// Create test sessions for Alice and Bob
async fn create_test_sessions(ctx: &mut TestContext) -> (DoubleRatchetSession, DoubleRatchetSession) {
    let alice_identity = ctx.create_test_identity("alice");
    let bob_identity = ctx.create_test_identity("bob");
    
    // Perform X3DH to get shared secret
    let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
    let bob_one_time_prekeys = generate_one_time_prekeys(1);
    
    let bob_prekey_bundle = PreKeyBundle {
        identity_key: bob_identity.public_key.clone(),
        signed_prekey: bob_signed_prekey.public_key.clone(),
        signed_prekey_signature: bob_signed_prekey.signature.clone(),
        one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
    };
    
    let (shared_secret, alice_ephemeral_key) = 
        x3dh_initiate(&alice_identity, &bob_prekey_bundle).unwrap();
    
    let alice_session = DoubleRatchetSession::init_alice(&shared_secret, &bob_identity.public_key).unwrap();
    let bob_session = DoubleRatchetSession::init_bob(
        &shared_secret,
        &bob_signed_prekey.private_key,
        &alice_ephemeral_key.public_key,
    ).unwrap();
    
    (alice_session, bob_session)
}

/// Mock Double Ratchet implementation for testing

#[derive(Debug, Clone)]
pub struct DoubleRatchetSession {
    root_key: Vec<u8>,
    sending_chain_key: Option<Vec<u8>>,
    receiving_chain_key: Option<Vec<u8>>,
    dh_keypair: Option<KeyPair>,
    dh_remote_public: Option<Vec<u8>>,
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_chain_length: u32,
    skipped_keys: HashMap<(Vec<u8>, u32), Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct DoubleRatchetMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub dh_public_key: Vec<u8>,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub root_key: Vec<u8>,
    pub chain_keys: HashMap<String, Vec<u8>>,
    pub message_numbers: HashMap<String, u32>,
}

#[derive(Debug)]
pub enum DoubleRatchetError {
    InvalidKey(String),
    InvalidMessage(String),
    ReplayAttack,
    AuthenticationFailed,
    DecryptionFailed,
}

impl DoubleRatchetSession {
    pub fn init_alice(shared_secret: &[u8], bob_public_key: &[u8]) -> Result<Self, DoubleRatchetError> {
        if shared_secret.is_empty() || bob_public_key.is_empty() {
            return Err(DoubleRatchetError::InvalidKey("Empty key material".to_string()));
        }
        
        let root_key = derive_root_key(shared_secret);
        let dh_keypair = generate_keypair();
        
        Ok(Self {
            root_key,
            sending_chain_key: None,
            receiving_chain_key: None,
            dh_keypair: Some(dh_keypair),
            dh_remote_public: Some(bob_public_key.to_vec()),
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        })
    }
    
    pub fn init_bob(
        shared_secret: &[u8],
        bob_private_key: &[u8],
        alice_public_key: &[u8],
    ) -> Result<Self, DoubleRatchetError> {
        if shared_secret.is_empty() || bob_private_key.is_empty() || alice_public_key.is_empty() {
            return Err(DoubleRatchetError::InvalidKey("Empty key material".to_string()));
        }
        
        let root_key = derive_root_key(shared_secret);
        
        Ok(Self {
            root_key,
            sending_chain_key: None,
            receiving_chain_key: None,
            dh_keypair: None,
            dh_remote_public: Some(alice_public_key.to_vec()),
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        })
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<DoubleRatchetMessage, DoubleRatchetError> {
        // Simplified encryption for testing
        if self.sending_chain_key.is_none() {
            self.sending_chain_key = Some(derive_chain_key(&self.root_key, b"sending"));
        }
        
        let message_key = derive_message_key(self.sending_chain_key.as_ref().unwrap(), self.sending_message_number);
        let ciphertext = encrypt_with_key(&message_key, plaintext);
        
        let header = MessageHeader {
            dh_public_key: self.dh_keypair.as_ref()
                .map(|kp| kp.public_key.clone())
                .unwrap_or_else(|| vec![0u8; 32]),
            previous_chain_length: self.previous_chain_length,
            message_number: self.sending_message_number,
        };
        
        let mac = compute_mac(&message_key, &header, &ciphertext);
        
        self.sending_message_number += 1;
        
        Ok(DoubleRatchetMessage {
            header,
            ciphertext,
            mac,
        })
    }
    
    pub fn decrypt(&mut self, message: &DoubleRatchetMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        // Validate message structure
        if message.header.dh_public_key.is_empty() || 
           message.ciphertext.is_empty() || 
           message.mac.is_empty() {
            return Err(DoubleRatchetError::InvalidMessage("Malformed message".to_string()));
        }
        
        // Check for replay attacks
        let message_id = (message.header.dh_public_key.clone(), message.header.message_number);
        if self.skipped_keys.contains_key(&message_id) {
            return Err(DoubleRatchetError::ReplayAttack);
        }
        
        // Simplified decryption for testing
        if self.receiving_chain_key.is_none() {
            self.receiving_chain_key = Some(derive_chain_key(&self.root_key, b"receiving"));
        }
        
        let message_key = derive_message_key(self.receiving_chain_key.as_ref().unwrap(), message.header.message_number);
        
        // Verify MAC
        let expected_mac = compute_mac(&message_key, &message.header, &message.ciphertext);
        if expected_mac != message.mac {
            return Err(DoubleRatchetError::AuthenticationFailed);
        }
        
        // Decrypt
        let plaintext = decrypt_with_key(&message_key, &message.ciphertext)
            .map_err(|_| DoubleRatchetError::DecryptionFailed)?;
        
        self.receiving_message_number = message.header.message_number + 1;
        
        Ok(plaintext)
    }
    
    pub fn export_state(&self) -> SessionState {
        let mut chain_keys = HashMap::new();
        if let Some(ref key) = self.sending_chain_key {
            chain_keys.insert("sending".to_string(), key.clone());
        }
        if let Some(ref key) = self.receiving_chain_key {
            chain_keys.insert("receiving".to_string(), key.clone());
        }
        
        let mut message_numbers = HashMap::new();
        message_numbers.insert("sending".to_string(), self.sending_message_number);
        message_numbers.insert("receiving".to_string(), self.receiving_message_number);
        
        SessionState {
            root_key: self.root_key.clone(),
            chain_keys,
            message_numbers,
        }
    }
}

/// Helper functions for cryptographic operations

fn derive_root_key(shared_secret: &[u8]) -> Vec<u8> {
    // Simplified root key derivation for testing
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"root_key");
    hasher.update(shared_secret);
    hasher.finalize().to_vec()
}

fn derive_chain_key(root_key: &[u8], info: &[u8]) -> Vec<u8> {
    // Simplified chain key derivation for testing
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"chain_key");
    hasher.update(root_key);
    hasher.update(info);
    hasher.finalize().to_vec()
}

fn derive_message_key(chain_key: &[u8], message_number: u32) -> Vec<u8> {
    // Simplified message key derivation for testing
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"message_key");
    hasher.update(chain_key);
    hasher.update(&message_number.to_be_bytes());
    hasher.finalize().to_vec()
}

fn encrypt_with_key(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Simplified encryption for testing (XOR cipher)
    let mut ciphertext = Vec::new();
    for (i, &byte) in plaintext.iter().enumerate() {
        let key_byte = key[i % key.len()];
        ciphertext.push(byte ^ key_byte);
    }
    ciphertext
}

fn decrypt_with_key(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    // Simplified decryption for testing (XOR cipher)
    let mut plaintext = Vec::new();
    for (i, &byte) in ciphertext.iter().enumerate() {
        let key_byte = key[i % key.len()];
        plaintext.push(byte ^ key_byte);
    }
    Ok(plaintext)
}

fn compute_mac(key: &[u8], header: &MessageHeader, ciphertext: &[u8]) -> Vec<u8> {
    // Simplified MAC computation for testing
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"mac");
    hasher.update(key);
    hasher.update(&header.dh_public_key);
    hasher.update(&header.previous_chain_length.to_be_bytes());
    hasher.update(&header.message_number.to_be_bytes());
    hasher.update(ciphertext);
    hasher.finalize()[..16].to_vec() // Truncate to 16 bytes
}

// Re-use helper functions from X3DH tests
use super::x3dh::{generate_signed_prekey, generate_one_time_prekeys, x3dh_initiate, PreKeyBundle, KeyPair};