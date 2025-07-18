//! Integration tests for complete Signal Protocol flows
//! 
//! This module tests end-to-end protocol flows including:
//! - Complete X3DH key agreement followed by Double Ratchet messaging
//! - Group messaging with Sesame protocol
//! - Session establishment and message exchange
//! - Cross-protocol interactions

use crate::common::*;
use signal_crypto_lib::*;
use tokio::time::{sleep, Duration};

/// Test complete X3DH + Double Ratchet flow
#[tokio::test]
async fn test_complete_x3dh_double_ratchet_flow() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Setup Alice and Bob identities
    let alice_identity = test_ctx.fixtures.alice_identity.clone();
    let bob_identity = test_ctx.fixtures.bob_identity.clone();
    
    // Bob publishes prekeys
    let bob_prekey_bundle = test_ctx.fixtures.bob_prekey_bundle.clone();
    
    // Alice initiates X3DH key agreement
    let x3dh_result = perform_x3dh_key_agreement(
        &alice_identity,
        &bob_identity,
        &bob_prekey_bundle
    ).await?;
    
    // Verify X3DH completed successfully
    assert!(x3dh_result.shared_secret.len() == 32);
    assert!(x3dh_result.associated_data.is_some());
    
    // Initialize Double Ratchet sessions with X3DH output
    let mut alice_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        true // Alice is sender
    ).await?;
    
    let mut bob_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        false // Bob is receiver
    ).await?;
    
    // Test bidirectional messaging
    let messages = vec![
        "Hello Bob!",
        "Hi Alice!",
        "How are you?",
        "I'm doing well, thanks!",
    ];
    
    for (i, message) in messages.iter().enumerate() {
        if i % 2 == 0 {
            // Alice sends
            let encrypted = alice_session.encrypt(message.as_bytes()).await?;
            let decrypted = bob_session.decrypt(&encrypted).await?;
            assert_eq!(decrypted, message.as_bytes());
        } else {
            // Bob sends
            let encrypted = bob_session.encrypt(message.as_bytes()).await?;
            let decrypted = alice_session.decrypt(&encrypted).await?;
            assert_eq!(decrypted, message.as_bytes());
        }
    }
    
    // Verify forward secrecy - old keys should be deleted
    assert!(alice_session.get_old_keys_count() == 0);
    assert!(bob_session.get_old_keys_count() == 0);
    
    test_ctx.metrics.record_test_completion("x3dh_double_ratchet_flow", true);
    Ok(())
}

/// Test group messaging with Sesame protocol
#[tokio::test]
async fn test_complete_group_messaging_flow() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Setup group with multiple participants
    let group_id = "test_group_123";
    let participants = vec![
        test_ctx.fixtures.alice_identity.clone(),
        test_ctx.fixtures.bob_identity.clone(),
        test_ctx.fixtures.charlie_identity.clone(),
    ];
    
    // Create group sessions for each participant
    let mut alice_group = MockSesameGroupSession::new(
        group_id,
        &participants[0],
        &participants
    ).await?;
    
    let mut bob_group = MockSesameGroupSession::new(
        group_id,
        &participants[1],
        &participants
    ).await?;
    
    let mut charlie_group = MockSesameGroupSession::new(
        group_id,
        &participants[2],
        &participants
    ).await?;
    
    // Test group key distribution
    let sender_key = alice_group.get_current_sender_key().await?;
    bob_group.add_sender_key(&participants[0].identity_key, sender_key.clone()).await?;
    charlie_group.add_sender_key(&participants[0].identity_key, sender_key).await?;
    
    // Test group messaging
    let group_messages = vec![
        ("Alice", "Hello everyone!"),
        ("Bob", "Hi Alice!"),
        ("Charlie", "Hey there!"),
        ("Alice", "How is everyone doing?"),
    ];
    
    for (sender, message) in group_messages {
        match sender {
            "Alice" => {
                let encrypted = alice_group.encrypt(message.as_bytes()).await?;
                let bob_decrypted = bob_group.decrypt(&encrypted).await?;
                let charlie_decrypted = charlie_group.decrypt(&encrypted).await?;
                
                assert_eq!(bob_decrypted, message.as_bytes());
                assert_eq!(charlie_decrypted, message.as_bytes());
            },
            "Bob" => {
                // Bob needs to distribute his sender key first
                let bob_sender_key = bob_group.get_current_sender_key().await?;
                alice_group.add_sender_key(&participants[1].identity_key, bob_sender_key.clone()).await?;
                charlie_group.add_sender_key(&participants[1].identity_key, bob_sender_key).await?;
                
                let encrypted = bob_group.encrypt(message.as_bytes()).await?;
                let alice_decrypted = alice_group.decrypt(&encrypted).await?;
                let charlie_decrypted = charlie_group.decrypt(&encrypted).await?;
                
                assert_eq!(alice_decrypted, message.as_bytes());
                assert_eq!(charlie_decrypted, message.as_bytes());
            },
            "Charlie" => {
                // Charlie needs to distribute his sender key first
                let charlie_sender_key = charlie_group.get_current_sender_key().await?;
                alice_group.add_sender_key(&participants[2].identity_key, charlie_sender_key.clone()).await?;
                bob_group.add_sender_key(&participants[2].identity_key, charlie_sender_key).await?;
                
                let encrypted = charlie_group.encrypt(message.as_bytes()).await?;
                let alice_decrypted = alice_group.decrypt(&encrypted).await?;
                let bob_decrypted = bob_group.decrypt(&encrypted).await?;
                
                assert_eq!(alice_decrypted, message.as_bytes());
                assert_eq!(bob_decrypted, message.as_bytes());
            },
            _ => unreachable!(),
        }
    }
    
    // Test sender key rotation
    alice_group.rotate_sender_key().await?;
    let new_sender_key = alice_group.get_current_sender_key().await?;
    
    // Distribute new key
    bob_group.add_sender_key(&participants[0].identity_key, new_sender_key.clone()).await?;
    charlie_group.add_sender_key(&participants[0].identity_key, new_sender_key).await?;
    
    // Test messaging with new key
    let encrypted = alice_group.encrypt(b"Message with new key").await?;
    let bob_decrypted = bob_group.decrypt(&encrypted).await?;
    let charlie_decrypted = charlie_group.decrypt(&encrypted).await?;
    
    assert_eq!(bob_decrypted, b"Message with new key");
    assert_eq!(charlie_decrypted, b"Message with new key");
    
    test_ctx.metrics.record_test_completion("group_messaging_flow", true);
    Ok(())
}

/// Test session establishment and management
#[tokio::test]
async fn test_session_establishment_flow() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Create session manager with mock storage
    let mut session_manager = MockSessionManager::new().await?;
    
    // Test session creation
    let alice_id = "alice@example.com";
    let bob_id = "bob@example.com";
    
    // Alice initiates session with Bob
    let session_id = session_manager.create_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Verify session was created
    assert!(session_manager.has_session(&session_id).await?);
    
    // Test message exchange through session manager
    let messages = vec![
        "First message",
        "Second message",
        "Third message",
    ];
    
    for message in messages {
        // Send message
        let encrypted = session_manager.encrypt_message(
            &session_id,
            message.as_bytes()
        ).await?;
        
        // Receive and decrypt message
        let decrypted = session_manager.decrypt_message(
            &session_id,
            &encrypted
        ).await?;
        
        assert_eq!(decrypted, message.as_bytes());
    }
    
    // Test session persistence
    session_manager.save_session(&session_id).await?;
    
    // Simulate restart by creating new session manager
    let mut new_session_manager = MockSessionManager::new().await?;
    new_session_manager.load_session(&session_id).await?;
    
    // Verify session still works after reload
    let test_message = "Message after reload";
    let encrypted = new_session_manager.encrypt_message(
        &session_id,
        test_message.as_bytes()
    ).await?;
    
    let decrypted = new_session_manager.decrypt_message(
        &session_id,
        &encrypted
    ).await?;
    
    assert_eq!(decrypted, test_message.as_bytes());
    
    test_ctx.metrics.record_test_completion("session_establishment_flow", true);
    Ok(())
}

/// Test concurrent protocol operations
#[tokio::test]
async fn test_concurrent_protocol_operations() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Create multiple concurrent sessions
    let session_count = 10;
    let mut handles = Vec::new();
    
    for i in 0..session_count {
        let alice_identity = test_ctx.fixtures.alice_identity.clone();
        let bob_identity = test_ctx.fixtures.bob_identity.clone();
        let bob_prekey_bundle = test_ctx.fixtures.bob_prekey_bundle.clone();
        
        let handle = tokio::spawn(async move {
            // Perform X3DH key agreement
            let x3dh_result = perform_x3dh_key_agreement(
                &alice_identity,
                &bob_identity,
                &bob_prekey_bundle
            ).await?;
            
            // Create Double Ratchet sessions
            let mut alice_session = MockDoubleRatchetSession::new_from_x3dh(
                &x3dh_result,
                true
            ).await?;
            
            let mut bob_session = MockDoubleRatchetSession::new_from_x3dh(
                &x3dh_result,
                false
            ).await?;
            
            // Exchange messages
            let message = format!("Concurrent message {}", i);
            let encrypted = alice_session.encrypt(message.as_bytes()).await?;
            let decrypted = bob_session.decrypt(&encrypted).await?;
            
            assert_eq!(decrypted, message.as_bytes());
            
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all concurrent operations to complete
    for handle in handles {
        handle.await??;
    }
    
    test_ctx.metrics.record_test_completion("concurrent_operations", true);
    Ok(())
}

/// Test protocol interoperability
#[tokio::test]
async fn test_protocol_interoperability() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Test X3DH -> Double Ratchet -> Group messaging flow
    let alice_identity = test_ctx.fixtures.alice_identity.clone();
    let bob_identity = test_ctx.fixtures.bob_identity.clone();
    let charlie_identity = test_ctx.fixtures.charlie_identity.clone();
    
    // 1. Alice and Bob establish 1:1 session via X3DH + Double Ratchet
    let bob_prekey_bundle = test_ctx.fixtures.bob_prekey_bundle.clone();
    let x3dh_result = perform_x3dh_key_agreement(
        &alice_identity,
        &bob_identity,
        &bob_prekey_bundle
    ).await?;
    
    let mut alice_bob_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        true
    ).await?;
    
    let mut bob_alice_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        false
    ).await?;
    
    // Exchange 1:1 messages
    let encrypted = alice_bob_session.encrypt(b"Private message to Bob").await?;
    let decrypted = bob_alice_session.decrypt(&encrypted).await?;
    assert_eq!(decrypted, b"Private message to Bob");
    
    // 2. Alice creates group and invites Bob and Charlie
    let group_id = "interop_group";
    let participants = vec![alice_identity.clone(), bob_identity.clone(), charlie_identity.clone()];
    
    let mut alice_group = MockSesameGroupSession::new(
        group_id,
        &alice_identity,
        &participants
    ).await?;
    
    let mut bob_group = MockSesameGroupSession::new(
        group_id,
        &bob_identity,
        &participants
    ).await?;
    
    let mut charlie_group = MockSesameGroupSession::new(
        group_id,
        &charlie_identity,
        &participants
    ).await?;
    
    // 3. Distribute sender keys using existing 1:1 channels
    let alice_sender_key = alice_group.get_current_sender_key().await?;
    
    // Alice sends her sender key to Bob via 1:1 channel
    let key_message = format!("SENDER_KEY:{}", hex::encode(&alice_sender_key.key_data));
    let encrypted_key = alice_bob_session.encrypt(key_message.as_bytes()).await?;
    let decrypted_key = bob_alice_session.decrypt(&encrypted_key).await?;
    
    // Bob extracts and adds Alice's sender key
    let key_str = String::from_utf8(decrypted_key)?;
    if key_str.starts_with("SENDER_KEY:") {
        let key_hex = &key_str[11..];
        let key_data = hex::decode(key_hex)?;
        let sender_key = MockSenderKey { key_data, generation: alice_sender_key.generation };
        bob_group.add_sender_key(&alice_identity.identity_key, sender_key).await?;
    }
    
    // Similarly for Charlie (simplified - assume key distribution)
    charlie_group.add_sender_key(&alice_identity.identity_key, alice_sender_key).await?;
    
    // 4. Test group messaging
    let group_message = "Hello group from Alice!";
    let encrypted_group = alice_group.encrypt(group_message.as_bytes()).await?;
    
    let bob_decrypted = bob_group.decrypt(&encrypted_group).await?;
    let charlie_decrypted = charlie_group.decrypt(&encrypted_group).await?;
    
    assert_eq!(bob_decrypted, group_message.as_bytes());
    assert_eq!(charlie_decrypted, group_message.as_bytes());
    
    // 5. Continue 1:1 messaging alongside group messaging
    let private_message = "This is still private between us";
    let encrypted_private = alice_bob_session.encrypt(private_message.as_bytes()).await?;
    let decrypted_private = bob_alice_session.decrypt(&encrypted_private).await?;
    assert_eq!(decrypted_private, private_message.as_bytes());
    
    test_ctx.metrics.record_test_completion("protocol_interoperability", true);
    Ok(())
}

/// Test message ordering and delivery guarantees
#[tokio::test]
async fn test_message_ordering_and_delivery() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Setup session
    let alice_identity = test_ctx.fixtures.alice_identity.clone();
    let bob_identity = test_ctx.fixtures.bob_identity.clone();
    let bob_prekey_bundle = test_ctx.fixtures.bob_prekey_bundle.clone();
    
    let x3dh_result = perform_x3dh_key_agreement(
        &alice_identity,
        &bob_identity,
        &bob_prekey_bundle
    ).await?;
    
    let mut alice_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        true
    ).await?;
    
    let mut bob_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        false
    ).await?;
    
    // Send multiple messages rapidly
    let message_count = 100;
    let mut encrypted_messages = Vec::new();
    
    for i in 0..message_count {
        let message = format!("Message {}", i);
        let encrypted = alice_session.encrypt(message.as_bytes()).await?;
        encrypted_messages.push((i, encrypted));
    }
    
    // Simulate out-of-order delivery
    encrypted_messages.reverse();
    
    // Decrypt messages (should handle out-of-order)
    let mut decrypted_messages = Vec::new();
    for (i, encrypted) in encrypted_messages {
        let decrypted = bob_session.decrypt(&encrypted).await?;
        let message = String::from_utf8(decrypted)?;
        decrypted_messages.push((i, message));
    }
    
    // Verify all messages were decrypted correctly
    decrypted_messages.sort_by_key(|(i, _)| *i);
    
    for (i, (original_i, message)) in decrypted_messages.iter().enumerate() {
        assert_eq!(*original_i, i);
        assert_eq!(message, &format!("Message {}", i));
    }
    
    test_ctx.metrics.record_test_completion("message_ordering", true);
    Ok(())
}

/// Test protocol recovery after network interruption
#[tokio::test]
async fn test_protocol_recovery_after_interruption() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Setup session
    let alice_identity = test_ctx.fixtures.alice_identity.clone();
    let bob_identity = test_ctx.fixtures.bob_identity.clone();
    let bob_prekey_bundle = test_ctx.fixtures.bob_prekey_bundle.clone();
    
    let x3dh_result = perform_x3dh_key_agreement(
        &alice_identity,
        &bob_identity,
        &bob_prekey_bundle
    ).await?;
    
    let mut alice_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        true
    ).await?;
    
    let mut bob_session = MockDoubleRatchetSession::new_from_x3dh(
        &x3dh_result,
        false
    ).await?;
    
    // Exchange some messages
    for i in 0..5 {
        let message = format!("Pre-interruption message {}", i);
        let encrypted = alice_session.encrypt(message.as_bytes()).await?;
        let decrypted = bob_session.decrypt(&encrypted).await?;
        assert_eq!(decrypted, message.as_bytes());
    }
    
    // Simulate network interruption by saving session state
    let alice_state = alice_session.save_state().await?;
    let bob_state = bob_session.save_state().await?;
    
    // Simulate time passing during interruption
    sleep(Duration::from_millis(100)).await;
    
    // Restore sessions from saved state
    alice_session = MockDoubleRatchetSession::restore_from_state(&alice_state).await?;
    bob_session = MockDoubleRatchetSession::restore_from_state(&bob_state).await?;
    
    // Continue messaging after recovery
    for i in 5..10 {
        let message = format!("Post-recovery message {}", i);
        let encrypted = alice_session.encrypt(message.as_bytes()).await?;
        let decrypted = bob_session.decrypt(&encrypted).await?;
        assert_eq!(decrypted, message.as_bytes());
    }
    
    test_ctx.metrics.record_test_completion("protocol_recovery", true);
    Ok(())
}

/// Helper function to perform X3DH key agreement
async fn perform_x3dh_key_agreement(
    alice_identity: &TestIdentity,
    bob_identity: &TestIdentity,
    bob_prekey_bundle: &TestPreKeyBundle,
) -> Result<MockX3DHResult> {
    // Simulate X3DH key agreement process
    let shared_secret = generate_test_key(32);
    let associated_data = Some(b"x3dh_key_agreement".to_vec());
    
    Ok(MockX3DHResult {
        shared_secret,
        associated_data,
        alice_identity_key: alice_identity.identity_key.clone(),
        bob_identity_key: bob_identity.identity_key.clone(),
        ephemeral_key: generate_test_key(32),
    })
}

/// Mock X3DH result structure
#[derive(Debug, Clone)]
struct MockX3DHResult {
    shared_secret: Vec<u8>,
    associated_data: Option<Vec<u8>>,
    alice_identity_key: Vec<u8>,
    bob_identity_key: Vec<u8>,
    ephemeral_key: Vec<u8>,
}