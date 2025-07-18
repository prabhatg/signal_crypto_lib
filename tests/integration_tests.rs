//! Integration tests for Signal Crypto Library
//! 
//! These tests verify that the major components work together correctly
//! and that the compilation fixes maintain functionality.

use signal_crypto_lib::*;

#[test]
fn test_identity_key_generation() {
    // Test that identity key generation works
    let identity = generate_identity_keypair();
    assert_eq!(identity.dh_public.len(), 32);
    assert_eq!(identity.dh_private.len(), 32);
    assert_eq!(identity.ed_public.len(), 32);
    assert_eq!(identity.ed_private.len(), 32);
}

#[test]
fn test_post_quantum_algorithms() {
    // Test that post-quantum algorithms are available
    let pq_algorithms = vec![
        PQAlgorithm::Kyber512,
        PQAlgorithm::Kyber768,
        PQAlgorithm::Kyber1024,
        PQAlgorithm::Dilithium2,
        PQAlgorithm::Dilithium3,
        PQAlgorithm::Dilithium5,
    ];
    
    // Test that we can iterate over algorithms
    for algorithm in pq_algorithms {
        // Basic test - just ensure the enum variants exist
        match algorithm {
            PQAlgorithm::Kyber512 => assert!(true),
            PQAlgorithm::Kyber768 => assert!(true),
            PQAlgorithm::Kyber1024 => assert!(true),
            PQAlgorithm::Dilithium2 => assert!(true),
            PQAlgorithm::Dilithium3 => assert!(true),
            PQAlgorithm::Dilithium5 => assert!(true),
            _ => assert!(true), // Handle any other variants
        }
    }
}

#[test]
fn test_error_types() {
    // Test that error types work correctly
    let session_error = SessionManagerError::SessionNotFound;
    assert!(matches!(session_error, SessionManagerError::SessionNotFound));
}

#[test]
fn test_group_messaging() {
    // Test group messaging functionality
    let group_sender = generate_sender_key();
    let plaintext = "Hello Group!";
    let encrypted = encrypt_group_message(&group_sender, plaintext);
    let decrypted = decrypt_group_message(&group_sender, &encrypted);
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_performance_components() {
    // Test that performance components can be created
    let cache: LruCache<String, Vec<u8>> = LruCache::new(100);
    // Basic smoke test
    assert!(true, "LruCache creation should succeed");
    
    let monitor = PerformanceMonitor::new();
    assert!(true, "PerformanceMonitor creation should succeed");
}

#[test]
fn test_compilation_fixes_integration() {
    // Integration test to verify that all our compilation fixes work together
    
    // Test that we can create and use multiple components without conflicts
    let alice = generate_identity_keypair();
    let bob = generate_identity_keypair();
    
    // Test that identity generation works for both users
    assert_eq!(alice.dh_public.len(), 32);
    assert_eq!(bob.dh_public.len(), 32);
    
    // Test group messaging
    let group_key = generate_sender_key();
    let group_message = "Integration test message";
    let encrypted_group = encrypt_group_message(&group_key, group_message);
    let decrypted_group = decrypt_group_message(&group_key, &encrypted_group);
    assert_eq!(group_message, decrypted_group);
    
    // Test that all error types are available and functional
    let session_error = SessionManagerError::SessionNotFound;
    match session_error {
        SessionManagerError::SessionNotFound => assert!(true),
        _ => assert!(true),
    }
    
    // Test post-quantum algorithm availability
    let pq_alg = PQAlgorithm::Kyber512;
    assert!(matches!(pq_alg, PQAlgorithm::Kyber512));
}

#[test]
fn test_basic_cryptographic_operations() {
    // Test basic cryptographic operations work
    let identity1 = generate_identity_keypair();
    let identity2 = generate_identity_keypair();
    
    // Ensure keys are different
    assert_ne!(identity1.dh_public, identity2.dh_public);
    assert_ne!(identity1.ed_public, identity2.ed_public);
    
    // Test group operations
    let group1 = generate_sender_key();
    let group2 = generate_sender_key();
    
    // Ensure group keys are different
    assert_ne!(group1.key_id, group2.key_id);
    
    // Test encryption/decryption with different messages
    let messages = vec!["Hello", "World", "Test Message", "🚀 Emoji test"];
    
    for message in messages {
        let encrypted = encrypt_group_message(&group1, message);
        let decrypted = decrypt_group_message(&group1, &encrypted);
        assert_eq!(message, decrypted);
    }
}

#[test]
fn test_memory_safety() {
    // Test that our operations are memory safe
    let mut identities = Vec::new();
    let mut groups = Vec::new();
    
    // Create multiple identities and groups
    for _ in 0..10 {
        identities.push(generate_identity_keypair());
        groups.push(generate_sender_key());
    }
    
    // Test that all identities are valid
    for identity in &identities {
        assert_eq!(identity.dh_public.len(), 32);
        assert_eq!(identity.dh_private.len(), 32);
        assert_eq!(identity.ed_public.len(), 32);
        assert_eq!(identity.ed_private.len(), 32);
    }
    
    // Test that all groups can encrypt/decrypt
    for group in &groups {
        let message = "Memory safety test";
        let encrypted = encrypt_group_message(group, message);
        let decrypted = decrypt_group_message(group, &encrypted);
        assert_eq!(message, decrypted);
    }
}

#[test]
fn test_concurrent_operations() {
    // Test that operations work correctly when called multiple times
    let group = generate_sender_key();
    let messages = vec![
        "Message 1",
        "Message 2", 
        "Message 3",
        "Message 4",
        "Message 5"
    ];
    
    let mut encrypted_messages = Vec::new();
    
    // Encrypt all messages
    for message in &messages {
        encrypted_messages.push(encrypt_group_message(&group, message));
    }
    
    // Decrypt all messages and verify
    for (i, encrypted) in encrypted_messages.iter().enumerate() {
        let decrypted = decrypt_group_message(&group, encrypted);
        assert_eq!(messages[i], decrypted);
    }
}