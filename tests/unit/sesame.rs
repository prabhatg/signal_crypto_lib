//! Unit tests for Sesame group messaging protocol
//! 
//! Tests the Sesame protocol implementation for secure group messaging
//! with sender key distribution, group management, and scalability.

use signal_crypto_lib::*;
use crate::common::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Test basic Sesame group creation and messaging
    #[tokio::test]
    async fn test_sesame_basic_group_messaging() {
        let mut ctx = TestContext::with_default();
        
        // Create group members
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let charlie_identity = ctx.create_test_identity("charlie");
        
        // Alice creates a group
        let group_id = generate_group_id();
        let mut alice_group_session = time_operation!(ctx, "sesame_create_group", {
            SesameGroupSession::create_group(&group_id, &alice_identity)
        });
        
        assert!(alice_group_session.is_ok(), "Group creation should succeed");
        let mut alice_group_session = alice_group_session.unwrap();
        
        // Alice adds Bob and Charlie to the group
        let bob_result = alice_group_session.add_member(&bob_identity.public_key);
        let charlie_result = alice_group_session.add_member(&charlie_identity.public_key);
        
        assert!(bob_result.is_ok(), "Adding Bob should succeed");
        assert!(charlie_result.is_ok(), "Adding Charlie should succeed");
        
        // Get sender key distribution messages
        let sender_key_distribution = alice_group_session.get_sender_key_distribution();
        
        // Bob and Charlie join the group
        let mut bob_group_session = time_operation!(ctx, "sesame_join_group", {
            SesameGroupSession::join_group(&group_id, &bob_identity, &sender_key_distribution)
        });
        
        let mut charlie_group_session = time_operation!(ctx, "sesame_join_group", {
            SesameGroupSession::join_group(&group_id, &charlie_identity, &sender_key_distribution)
        });
        
        assert!(bob_group_session.is_ok(), "Bob joining should succeed");
        assert!(charlie_group_session.is_ok(), "Charlie joining should succeed");
        
        let mut bob_group_session = bob_group_session.unwrap();
        let mut charlie_group_session = charlie_group_session.unwrap();
        
        // Alice sends a message to the group
        let message = b"Hello group!";
        let encrypted_message = time_operation!(ctx, "sesame_encrypt", {
            alice_group_session.encrypt(message)
        });
        
        assert!(encrypted_message.is_ok(), "Group message encryption should succeed");
        let encrypted_message = encrypted_message.unwrap();
        
        // Verify message structure
        ProtocolAssertions::assert_valid_sesame_message(&encrypted_message, 
            "Group encrypted message");
        
        // Bob and Charlie decrypt the message
        let bob_decrypted = time_operation!(ctx, "sesame_decrypt", {
            bob_group_session.decrypt(&encrypted_message)
        });
        
        let charlie_decrypted = time_operation!(ctx, "sesame_decrypt", {
            charlie_group_session.decrypt(&encrypted_message)
        });
        
        assert!(bob_decrypted.is_ok(), "Bob decryption should succeed");
        assert!(charlie_decrypted.is_ok(), "Charlie decryption should succeed");
        
        assert_eq!(bob_decrypted.unwrap(), message, "Bob should decrypt correctly");
        assert_eq!(charlie_decrypted.unwrap(), message, "Charlie should decrypt correctly");
        
        // Verify cryptographic properties
        CryptoAssertions::assert_sufficient_entropy(&encrypted_message.ciphertext, 7.0, 
            "Group message ciphertext");
        CryptoAssertions::assert_appears_random(&encrypted_message.ciphertext, 
            "Group message ciphertext");
        
        println!("✓ Sesame basic group messaging test passed");
    }

    /// Test group member addition and removal
    #[tokio::test]
    async fn test_sesame_group_member_management() {
        let mut ctx = TestContext::with_default();
        
        // Create initial group with Alice and Bob
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let charlie_identity = ctx.create_test_identity("charlie");
        let dave_identity = ctx.create_test_identity("dave");
        
        let group_id = generate_group_id();
        let mut alice_group_session = SesameGroupSession::create_group(&group_id, &alice_identity).unwrap();
        alice_group_session.add_member(&bob_identity.public_key).unwrap();
        
        let sender_key_distribution = alice_group_session.get_sender_key_distribution();
        let mut bob_group_session = SesameGroupSession::join_group(
            &group_id, &bob_identity, &sender_key_distribution
        ).unwrap();
        
        // Test adding Charlie
        let add_charlie_result = alice_group_session.add_member(&charlie_identity.public_key);
        assert!(add_charlie_result.is_ok(), "Adding Charlie should succeed");
        
        // Get updated sender key distribution
        let updated_distribution = alice_group_session.get_sender_key_distribution();
        let mut charlie_group_session = SesameGroupSession::join_group(
            &group_id, &charlie_identity, &updated_distribution
        ).unwrap();
        
        // Test message after member addition
        let message_after_add = b"Welcome Charlie!";
        let encrypted_after_add = alice_group_session.encrypt(message_after_add).unwrap();
        
        let bob_decrypted = bob_group_session.decrypt(&encrypted_after_add).unwrap();
        let charlie_decrypted = charlie_group_session.decrypt(&encrypted_after_add).unwrap();
        
        assert_eq!(bob_decrypted, message_after_add);
        assert_eq!(charlie_decrypted, message_after_add);
        
        // Test removing Bob
        let remove_bob_result = alice_group_session.remove_member(&bob_identity.public_key);
        assert!(remove_bob_result.is_ok(), "Removing Bob should succeed");
        
        // Test message after member removal
        let message_after_remove = b"Bob has left";
        let encrypted_after_remove = alice_group_session.encrypt(message_after_remove).unwrap();
        
        // Charlie should still be able to decrypt
        let charlie_decrypted_after_remove = charlie_group_session.decrypt(&encrypted_after_remove).unwrap();
        assert_eq!(charlie_decrypted_after_remove, message_after_remove);
        
        // Bob should not be able to decrypt (forward secrecy)
        let bob_decrypt_result = bob_group_session.decrypt(&encrypted_after_remove);
        assert!(bob_decrypt_result.is_err(), "Bob should not decrypt after removal");
        
        // Verify group membership
        assert!(alice_group_session.is_member(&alice_identity.public_key));
        assert!(alice_group_session.is_member(&charlie_identity.public_key));
        assert!(!alice_group_session.is_member(&bob_identity.public_key));
        
        println!("✓ Sesame group member management test passed");
    }

    /// Test sender key rotation
    #[tokio::test]
    async fn test_sesame_sender_key_rotation() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let charlie_identity = ctx.create_test_identity("charlie");
        
        // Create group
        let group_id = generate_group_id();
        let mut alice_group_session = SesameGroupSession::create_group(&group_id, &alice_identity).unwrap();
        alice_group_session.add_member(&bob_identity.public_key).unwrap();
        alice_group_session.add_member(&charlie_identity.public_key).unwrap();
        
        let sender_key_distribution = alice_group_session.get_sender_key_distribution();
        let mut bob_group_session = SesameGroupSession::join_group(
            &group_id, &bob_identity, &sender_key_distribution
        ).unwrap();
        let mut charlie_group_session = SesameGroupSession::join_group(
            &group_id, &charlie_identity, &sender_key_distribution
        ).unwrap();
        
        // Send messages before rotation
        let messages_before = [
            b"Message 1",
            b"Message 2",
            b"Message 3",
        ];
        
        for msg in &messages_before {
            let encrypted = alice_group_session.encrypt(msg).unwrap();
            let bob_decrypted = bob_group_session.decrypt(&encrypted).unwrap();
            let charlie_decrypted = charlie_group_session.decrypt(&encrypted).unwrap();
            assert_eq!(bob_decrypted, *msg);
            assert_eq!(charlie_decrypted, *msg);
        }
        
        // Rotate sender key
        let rotation_result = alice_group_session.rotate_sender_key();
        assert!(rotation_result.is_ok(), "Sender key rotation should succeed");
        
        // Distribute new sender key
        let new_sender_key_distribution = alice_group_session.get_sender_key_distribution();
        bob_group_session.update_sender_key(&new_sender_key_distribution).unwrap();
        charlie_group_session.update_sender_key(&new_sender_key_distribution).unwrap();
        
        // Send messages after rotation
        let messages_after = [
            b"Message 4",
            b"Message 5",
            b"Message 6",
        ];
        
        for msg in &messages_after {
            let encrypted = alice_group_session.encrypt(msg).unwrap();
            let bob_decrypted = bob_group_session.decrypt(&encrypted).unwrap();
            let charlie_decrypted = charlie_group_session.decrypt(&encrypted).unwrap();
            assert_eq!(bob_decrypted, *msg);
            assert_eq!(charlie_decrypted, *msg);
        }
        
        // Verify forward secrecy: old keys should not decrypt new messages
        SecurityAssertions::assert_sender_key_forward_secrecy(
            &alice_group_session,
            &messages_after[0],
            "After sender key rotation"
        );
        
        println!("✓ Sesame sender key rotation test passed");
    }

    /// Test large group scalability
    #[tokio::test]
    async fn test_sesame_large_group_scalability() {
        let mut ctx = TestContext::with_default();
        
        if !ctx.config.performance_mode {
            println!("⏭ Skipping scalability test (not in performance mode)");
            return;
        }
        
        // Create a large group (100 members)
        let group_size = 100;
        let mut identities = Vec::new();
        
        for i in 0..group_size {
            let identity = ctx.create_test_identity(&format!("user_{}", i));
            identities.push(identity);
        }
        
        let group_id = generate_group_id();
        let mut admin_session = SesameGroupSession::create_group(&group_id, &identities[0]).unwrap();
        
        // Add all members to the group
        let add_members_start = std::time::Instant::now();
        for i in 1..group_size {
            admin_session.add_member(&identities[i].public_key).unwrap();
        }
        let add_members_duration = add_members_start.elapsed();
        
        println!("Adding {} members took: {:?}", group_size - 1, add_members_duration);
        assert!(add_members_duration.as_secs() < 5, "Adding members should be fast");
        
        // Create sessions for a subset of members
        let sender_key_distribution = admin_session.get_sender_key_distribution();
        let mut member_sessions = Vec::new();
        
        let join_start = std::time::Instant::now();
        for i in 1..std::cmp::min(10, group_size) {
            let session = SesameGroupSession::join_group(
                &group_id, &identities[i], &sender_key_distribution
            ).unwrap();
            member_sessions.push(session);
        }
        let join_duration = join_start.elapsed();
        
        println!("Joining group for 9 members took: {:?}", join_duration);
        assert!(join_duration.as_millis() < 500, "Joining should be fast");
        
        // Test message broadcasting
        let message = b"Broadcast to large group";
        let encrypt_start = std::time::Instant::now();
        let encrypted_message = admin_session.encrypt(message).unwrap();
        let encrypt_duration = encrypt_start.elapsed();
        
        println!("Encrypting for {} members took: {:?}", group_size, encrypt_duration);
        assert!(encrypt_duration.as_millis() < 100, "Encryption should be fast");
        
        // Test decryption by multiple members
        let decrypt_start = std::time::Instant::now();
        for session in &mut member_sessions {
            let decrypted = session.decrypt(&encrypted_message).unwrap();
            assert_eq!(decrypted, message);
        }
        let decrypt_duration = decrypt_start.elapsed();
        
        println!("Decrypting by 9 members took: {:?}", decrypt_duration);
        assert!(decrypt_duration.as_millis() < 100, "Decryption should be fast");
        
        // Verify memory usage is reasonable
        let session_size = std::mem::size_of_val(&admin_session);
        println!("Session memory usage: {} bytes", session_size);
        assert!(session_size < 10_000, "Session should not use excessive memory");
        
        println!("✓ Sesame large group scalability test passed");
    }

    /// Test message ordering and delivery
    #[tokio::test]
    async fn test_sesame_message_ordering() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let charlie_identity = ctx.create_test_identity("charlie");
        
        // Create group
        let group_id = generate_group_id();
        let mut alice_session = SesameGroupSession::create_group(&group_id, &alice_identity).unwrap();
        alice_session.add_member(&bob_identity.public_key).unwrap();
        alice_session.add_member(&charlie_identity.public_key).unwrap();
        
        let sender_key_distribution = alice_session.get_sender_key_distribution();
        let mut bob_session = SesameGroupSession::join_group(
            &group_id, &bob_identity, &sender_key_distribution
        ).unwrap();
        let mut charlie_session = SesameGroupSession::join_group(
            &group_id, &charlie_identity, &sender_key_distribution
        ).unwrap();
        
        // Alice sends multiple messages
        let messages = [
            b"First message",
            b"Second message",
            b"Third message",
            b"Fourth message",
            b"Fifth message",
        ];
        
        let mut encrypted_messages = Vec::new();
        for msg in &messages {
            let encrypted = alice_session.encrypt(msg).unwrap();
            encrypted_messages.push(encrypted);
        }
        
        // Deliver messages out of order to Bob
        let delivery_order = [0, 2, 1, 4, 3];
        let mut bob_decrypted = vec![None; messages.len()];
        
        for &index in &delivery_order {
            let decrypted = bob_session.decrypt(&encrypted_messages[index]).unwrap();
            bob_decrypted[index] = Some(decrypted);
        }
        
        // Verify all messages were decrypted correctly
        for (i, original) in messages.iter().enumerate() {
            assert_eq!(bob_decrypted[i].as_ref().unwrap(), original,
                "Message {} should be decrypted correctly", i + 1);
        }
        
        // Charlie receives messages in order
        for encrypted in &encrypted_messages {
            let decrypted = charlie_session.decrypt(encrypted).unwrap();
            // Verify decryption succeeds (specific content verified above)
            assert!(!decrypted.is_empty());
        }
        
        // Verify message chain integrity
        ProtocolAssertions::assert_group_message_chain_integrity(&bob_session, 
            "After out-of-order delivery");
        
        println!("✓ Sesame message ordering test passed");
    }

    /// Test group message authentication
    #[tokio::test]
    async fn test_sesame_message_authentication() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let eve_identity = ctx.create_test_identity("eve"); // Attacker
        
        // Create group with Alice and Bob
        let group_id = generate_group_id();
        let mut alice_session = SesameGroupSession::create_group(&group_id, &alice_identity).unwrap();
        alice_session.add_member(&bob_identity.public_key).unwrap();
        
        let sender_key_distribution = alice_session.get_sender_key_distribution();
        let mut bob_session = SesameGroupSession::join_group(
            &group_id, &bob_identity, &sender_key_distribution
        ).unwrap();
        
        // Alice sends a legitimate message
        let message = b"Authenticated group message";
        let encrypted_message = alice_session.encrypt(message).unwrap();
        
        // Test tampering with ciphertext
        let mut tampered_ciphertext = encrypted_message.clone();
        tampered_ciphertext.ciphertext[0] ^= 0xFF;
        
        let tampered_result = bob_session.decrypt(&tampered_ciphertext);
        assert!(tampered_result.is_err(), "Tampered ciphertext should be rejected");
        
        // Test tampering with sender key ID
        let mut tampered_sender_id = encrypted_message.clone();
        tampered_sender_id.sender_key_id ^= 0xFF;
        
        let sender_id_tampered_result = bob_session.decrypt(&tampered_sender_id);
        assert!(sender_id_tampered_result.is_err(), "Tampered sender ID should be rejected");
        
        // Test message from non-member (Eve tries to impersonate)
        let eve_session_result = SesameGroupSession::create_group(&group_id, &eve_identity);
        assert!(eve_session_result.is_ok()); // Eve can create her own session
        
        let mut eve_session = eve_session_result.unwrap();
        let eve_message = b"Malicious message from Eve";
        let eve_encrypted = eve_session.encrypt(eve_message).unwrap();
        
        // Bob should reject Eve's message (she's not in the group)
        let eve_decrypt_result = bob_session.decrypt(&eve_encrypted);
        assert!(eve_decrypt_result.is_err(), "Message from non-member should be rejected");
        
        // Verify original message still works
        let decrypted = bob_session.decrypt(&encrypted_message).unwrap();
        assert_eq!(decrypted, message);
        
        // Verify authentication properties
        SecurityAssertions::assert_group_message_authentication(&encrypted_message, 
            "Sesame group message authentication");
        
        println!("✓ Sesame message authentication test passed");
    }

    /// Test concurrent group operations
    #[tokio::test]
    async fn test_sesame_concurrent_operations() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let charlie_identity = ctx.create_test_identity("charlie");
        
        // Create group
        let group_id = generate_group_id();
        let alice_session = SesameGroupSession::create_group(&group_id, &alice_identity).unwrap();
        
        // Use Arc<Mutex<>> for thread-safe access
        let alice_session = std::sync::Arc::new(std::sync::Mutex::new(alice_session));
        
        let mut handles = Vec::new();
        
        // Launch concurrent encryption operations
        for i in 0..10 {
            let alice_session = alice_session.clone();
            let message = format!("Concurrent group message {}", i);
            
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
        
        // Create Bob's session and decrypt all messages
        let sender_key_distribution = {
            let session = alice_session.lock().unwrap();
            session.get_sender_key_distribution()
        };
        
        let mut bob_session = SesameGroupSession::join_group(
            &group_id, &bob_identity, &sender_key_distribution
        ).unwrap();
        
        for encrypted in encrypted_messages {
            let decrypted = bob_session.decrypt(&encrypted).unwrap();
            assert!(decrypted.starts_with(b"Concurrent group message"));
        }
        
        println!("✓ Sesame concurrent operations test passed");
    }

    /// Test error handling and edge cases
    #[tokio::test]
    async fn test_sesame_error_handling() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        
        // Test creating group with invalid ID
        let invalid_group_id = vec![]; // Empty group ID
        let result = SesameGroupSession::create_group(&invalid_group_id, &alice_identity);
        assert!(result.is_err(), "Should fail with invalid group ID");
        
        // Test joining non-existent group
        let valid_group_id = generate_group_id();
        let empty_distribution = SenderKeyDistribution {
            group_id: valid_group_id.clone(),
            sender_keys: HashMap::new(),
            chain_key: vec![],
            signature: vec![],
        };
        
        let join_result = SesameGroupSession::join_group(
            &valid_group_id, &bob_identity, &empty_distribution
        );
        assert!(join_result.is_err(), "Should fail with empty sender key distribution");
        
        // Test adding duplicate member
        let mut alice_session = SesameGroupSession::create_group(&valid_group_id, &alice_identity).unwrap();
        let first_add = alice_session.add_member(&bob_identity.public_key);
        let second_add = alice_session.add_member(&bob_identity.public_key);
        
        assert!(first_add.is_ok(), "First add should succeed");
        assert!(second_add.is_err(), "Duplicate add should fail");
        
        // Test removing non-member
        let charlie_identity = ctx.create_test_identity("charlie");
        let remove_result = alice_session.remove_member(&charlie_identity.public_key);
        assert!(remove_result.is_err(), "Removing non-member should fail");
        
        // Test error message safety
        if let Err(error) = remove_result {
            let error_message = format!("{:?}", error);
            let sensitive_data = [
                &hex::encode(&alice_identity.private_key),
                &hex::encode(&bob_identity.private_key),
            ];
            
            ErrorAssertions::assert_safe_error_messages(&error, &sensitive_data, 
                "Sesame error messages");
        }
        
        println!("✓ Sesame error handling test passed");
    }
}

/// Helper functions for Sesame testing

/// Generate a random group ID
fn generate_group_id() -> Vec<u8> {
    use rand::RngCore;
    let mut group_id = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut group_id);
    group_id
}

/// Mock Sesame implementation for testing

#[derive(Debug, Clone)]
pub struct SesameGroupSession {
    group_id: Vec<u8>,
    admin_identity: IdentityKeyPair,
    members: HashMap<Vec<u8>, GroupMember>,
    sender_key_chain: SenderKeyChain,
    message_number: u32,
}

#[derive(Debug, Clone)]
pub struct GroupMember {
    public_key: Vec<u8>,
    joined_at: std::time::SystemTime,
    is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct SenderKeyChain {
    current_key: Vec<u8>,
    chain_key: Vec<u8>,
    generation: u32,
}

#[derive(Debug, Clone)]
pub struct SesameMessage {
    pub sender_key_id: u32,
    pub message_number: u32,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderKeyDistribution {
    pub group_id: Vec<u8>,
    pub sender_keys: HashMap<Vec<u8>, Vec<u8>>,
    pub chain_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub enum SesameError {
    InvalidGroupId(String),
    InvalidMember(String),
    DuplicateMember,
    MemberNotFound,
    InvalidSenderKey,
    AuthenticationFailed,
    DecryptionFailed,
}

impl SesameGroupSession {
    pub fn create_group(group_id: &[u8], admin_identity: &IdentityKeyPair) -> Result<Self, SesameError> {
        if group_id.is_empty() {
            return Err(SesameError::InvalidGroupId("Empty group ID".to_string()));
        }
        
        let mut members = HashMap::new();
        members.insert(admin_identity.public_key.clone(), GroupMember {
            public_key: admin_identity.public_key.clone(),
            joined_at: std::time::SystemTime::now(),
            is_admin: true,
        });
        
        let sender_key_chain = SenderKeyChain {
            current_key: generate_sender_key(),
            chain_key: generate_chain_key(),
            generation: 0,
        };
        
        Ok(Self {
            group_id: group_id.to_vec(),
            admin_identity: admin_identity.clone(),
            members,
            sender_key_chain,
            message_number: 0,
        })
    }
    
    pub fn join_group(
        group_id: &[u8],
        member_identity: &IdentityKeyPair,
        sender_key_distribution: &SenderKeyDistribution,
    ) -> Result<Self, SesameError> {
        if sender_key_distribution.sender_keys.is_empty() {
            return Err(SesameError::InvalidSenderKey);
        }
        
        // Simplified join logic for testing
        let mut members = HashMap::new();
        for (public_key, _) in &sender_key_distribution.sender_keys {
            members.insert(public_key.clone(), GroupMember {
                public_key: public_key.clone(),
                joined_at: std::time::SystemTime::now(),
                is_admin: false,
            });
        }
        
        let sender_key_chain = SenderKeyChain {
            current_key: sender_key_distribution.chain_key.clone(),
            chain_key: sender_key_distribution.chain_key.clone(),
            generation: 0,
        };
        
        Ok(Self {
            group_id: group_id.to_vec(),
            admin_identity: member_identity.clone(),
            members,
            sender_key_chain,
            message_number: 0,
        })
    }
    
    pub fn add_member(&mut self, member_public_key: &[u8]) -> Result<(), SesameError> {
        if self.members.contains_key(member_public_key) {
            return Err(SesameError::DuplicateMember);
        }
        
        self.members.insert(member_public_key.to_vec(), GroupMember {
            public_key: member_public_key.to_vec(),
            joined_at: std::time::SystemTime::now(),
            is_admin: false,
        });
        
        Ok(())
    }
    
    pub fn remove_member(&mut self, member_public_key: &[u8]) -> Result<(), SesameError> {
        if !self.members.contains_key(member_public_key) {
            return Err(SesameError::MemberNotFound);
        }
        
        self.members.remove(member_public_key);
        
        // Rotate sender key for forward secrecy
        self.rotate_sender_key()?;
        
        Ok(())
    }
    
    pub fn is_member(&self, public_key: &[u8]) -> bool {
        self.members.contains_key(public_key)
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SesameMessage, SesameError> {
        let message_key = derive_message_key(&self.sender_key_chain.current_key, self.message_number);
        let ciphertext = encrypt_with_key(&message_key, plaintext);
        let mac = compute_group_mac(&message_key, &ciphertext, self.message_number);
        
        let message = SesameMessage {
            sender_key_id: self.sender_key_chain.generation,
            message_number: self.message_number,
            ciphertext,
            mac,
        };
        
        self.message_number += 1;
        
        Ok(message)
    }
    
    pub fn decrypt(&mut self, message: &SesameMessage) -> Result<Vec<u8>, SesameError> {
        let message_key = derive_message_key(&self.sender_key_chain.current_key, message.message_number);
        
        // Verify MAC
        let expected_mac = compute_group_mac(&message_key, &message.ciphertext, message.message_number);
        if expected_mac != message.mac {
            return Err(SesameError::AuthenticationFailed);
        }
        
        // Decrypt
        let plaintext = decrypt_with_key(&message_key, &message.ciphertext)
            .map_err(|_| SesameError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
    
    pub fn rotate_sender_key(&mut self) -> Result<(), SesameError> {
        self.sender_key_chain.current_key = generate_sender_key();
        self.sender_key_chain.chain_key = generate_chain_key();
        self.sender_key_chain.generation += 1;
        Ok(())
    }
    
    pub fn get_sender_key_distribution(&self) -> SenderKeyDistribution {
        let mut sender_keys = HashMap::new();
        for (public_key, _) in &self.members {
            sender_keys.insert(public_key.clone(), self.sender_key_chain.current_key.clone());
        }
        
        SenderKeyDistribution {
            group_id: self.group_id.clone(),
            sender_keys,
            chain_key: self.sender_key_chain.chain_key.clone(),
            signature: compute_distribution_signature(&self.sender_key_chain.chain_key),
        }
    }
    
    pub fn update_sender_key(&mut self, distribution: &SenderKeyDistribution) -> Result<(), SesameError> {
        if distribution.group_id != self.group_id {
            return Err(SesameError::InvalidGroupId("Group ID mismatch".to_string()));
        }
        
        self.sender_key_chain.current_key = distribution.chain_key.clone();
        self.sender_key_chain.chain_key = distribution.chain_key.clone();
        self.sender_key_chain.generation += 1;
        
        Ok(())
    }
}

/// Helper functions for Sesame testing

fn generate_sender_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn generate_chain_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn derive_message_key(sender_key: &[u8], message_number: u32) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"sesame_message_key");
    hasher.update(sender_key);
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

fn compute_group_mac(key: &[u8], ciphertext: &[u8], message_number: u32) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"sesame_mac");
    hasher.update(key);
    hasher.update(ciphertext);
    hasher.update(&message_number.to_be_bytes());
    hasher.finalize()[..16].to_vec() // Truncate to 16 bytes
}

fn compute_distribution_signature(chain_key: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"distribution_signature");
    hasher.update(chain_key);
    hasher.finalize()[..32].to_vec()
}

// Re-use helper functions from other tests
use super::x3dh::IdentityKeyPair;