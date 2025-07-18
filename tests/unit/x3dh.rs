//! Unit tests for X3DH key agreement protocol
//! 
//! Tests the Extended Triple Diffie-Hellman key agreement protocol
//! implementation for correctness, security properties, and edge cases.

use signal_crypto_lib::*;
use crate::common::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Test basic X3DH key agreement between two parties
    #[tokio::test]
    async fn test_x3dh_basic_key_agreement() {
        let mut ctx = TestContext::with_default();
        
        // Generate Alice's identity and keys
        let alice_identity = ctx.create_test_identity("alice");
        let alice_signed_prekey = generate_signed_prekey(&alice_identity.private_key);
        let alice_one_time_prekeys = generate_one_time_prekeys(10);
        
        // Generate Bob's identity and keys
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let bob_one_time_prekeys = generate_one_time_prekeys(10);
        
        // Alice initiates X3DH with Bob
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
        };
        
        let alice_result = time_operation!(ctx, "x3dh_initiate", {
            x3dh_initiate(&alice_identity, &bob_prekey_bundle)
        });
        
        assert!(alice_result.is_ok(), "Alice X3DH initiation should succeed");
        let (alice_shared_secret, alice_ephemeral_key) = alice_result.unwrap();
        
        // Bob responds to X3DH
        let bob_result = time_operation!(ctx, "x3dh_respond", {
            x3dh_respond(
                &bob_identity,
                &bob_signed_prekey,
                Some(&bob_one_time_prekeys[0]),
                &alice_identity.public_key,
                &alice_ephemeral_key,
            )
        });
        
        assert!(bob_result.is_ok(), "Bob X3DH response should succeed");
        let bob_shared_secret = bob_result.unwrap();
        
        // Verify shared secrets match
        ProtocolAssertions::assert_valid_x3dh_result(
            &alice_shared_secret,
            &bob_shared_secret,
            "X3DH key agreement"
        );
        
        // Verify cryptographic properties
        CryptoAssertions::assert_sufficient_entropy(&alice_shared_secret, 7.0, "Alice shared secret");
        CryptoAssertions::assert_sufficient_entropy(&bob_shared_secret, 7.0, "Bob shared secret");
        CryptoAssertions::assert_appears_random(&alice_shared_secret, "Alice shared secret");
        CryptoAssertions::assert_appears_random(&bob_shared_secret, "Bob shared secret");
        
        println!("✓ Basic X3DH key agreement test passed");
    }

    /// Test X3DH without one-time prekey
    #[tokio::test]
    async fn test_x3dh_without_one_time_prekey() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: None, // No one-time prekey
        };
        
        let alice_result = x3dh_initiate(&alice_identity, &bob_prekey_bundle);
        assert!(alice_result.is_ok(), "X3DH should work without one-time prekey");
        
        let (alice_shared_secret, alice_ephemeral_key) = alice_result.unwrap();
        
        let bob_result = x3dh_respond(
            &bob_identity,
            &bob_signed_prekey,
            None, // No one-time prekey
            &alice_identity.public_key,
            &alice_ephemeral_key,
        );
        
        assert!(bob_result.is_ok(), "Bob should handle missing one-time prekey");
        let bob_shared_secret = bob_result.unwrap();
        
        assert_eq!(alice_shared_secret, bob_shared_secret, "Shared secrets should match");
        
        println!("✓ X3DH without one-time prekey test passed");
    }

    /// Test X3DH with invalid signature
    #[tokio::test]
    async fn test_x3dh_invalid_signature() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        
        // Create bundle with invalid signature
        let mut invalid_signature = bob_signed_prekey.signature.clone();
        invalid_signature[0] ^= 0xFF; // Corrupt the signature
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: invalid_signature,
            one_time_prekey: None,
        };
        
        let alice_result = x3dh_initiate(&alice_identity, &bob_prekey_bundle);
        assert!(alice_result.is_err(), "X3DH should fail with invalid signature");
        
        match alice_result.unwrap_err() {
            SignalProtocolError::InvalidSignature => {
                println!("✓ Correctly detected invalid signature");
            }
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
        
        println!("✓ X3DH invalid signature test passed");
    }

    /// Test X3DH key derivation consistency
    #[tokio::test]
    async fn test_x3dh_key_derivation_consistency() {
        let mut ctx = TestContext::with_default();
        
        // Test multiple rounds to ensure consistency
        for round in 0..5 {
            let alice_identity = ctx.create_test_identity(&format!("alice_{}", round));
            let bob_identity = ctx.create_test_identity(&format!("bob_{}", round));
            let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
            let bob_one_time_prekeys = generate_one_time_prekeys(1);
            
            let bob_prekey_bundle = PreKeyBundle {
                identity_key: bob_identity.public_key.clone(),
                signed_prekey: bob_signed_prekey.public_key.clone(),
                signed_prekey_signature: bob_signed_prekey.signature.clone(),
                one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
            };
            
            // Perform X3DH multiple times with same keys
            let mut shared_secrets = Vec::new();
            
            for _ in 0..3 {
                let (alice_shared_secret, alice_ephemeral_key) = 
                    x3dh_initiate(&alice_identity, &bob_prekey_bundle).unwrap();
                
                let bob_shared_secret = x3dh_respond(
                    &bob_identity,
                    &bob_signed_prekey,
                    Some(&bob_one_time_prekeys[0]),
                    &alice_identity.public_key,
                    &alice_ephemeral_key,
                ).unwrap();
                
                assert_eq!(alice_shared_secret, bob_shared_secret);
                shared_secrets.push(alice_shared_secret);
            }
            
            // Each X3DH should produce different shared secrets (due to ephemeral keys)
            for i in 0..shared_secrets.len() {
                for j in i+1..shared_secrets.len() {
                    assert_ne!(shared_secrets[i], shared_secrets[j], 
                        "Different X3DH runs should produce different secrets");
                }
            }
        }
        
        println!("✓ X3DH key derivation consistency test passed");
    }

    /// Test X3DH forward secrecy properties
    #[tokio::test]
    async fn test_x3dh_forward_secrecy() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let bob_one_time_prekeys = generate_one_time_prekeys(2);
        
        // First X3DH exchange
        let bob_prekey_bundle_1 = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
        };
        
        let (alice_shared_secret_1, alice_ephemeral_key_1) = 
            x3dh_initiate(&alice_identity, &bob_prekey_bundle_1).unwrap();
        
        // Second X3DH exchange with different one-time prekey
        let bob_prekey_bundle_2 = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: Some(bob_one_time_prekeys[1].public_key.clone()),
        };
        
        let (alice_shared_secret_2, alice_ephemeral_key_2) = 
            x3dh_initiate(&alice_identity, &bob_prekey_bundle_2).unwrap();
        
        // Verify forward secrecy: different sessions should have different secrets
        assert_ne!(alice_shared_secret_1, alice_shared_secret_2, 
            "Different X3DH sessions should produce different shared secrets");
        assert_ne!(alice_ephemeral_key_1.public_key, alice_ephemeral_key_2.public_key,
            "Different X3DH sessions should use different ephemeral keys");
        
        // Verify that compromising one session doesn't affect the other
        CryptoAssertions::assert_no_key_leakage(&alice_shared_secret_2, &alice_shared_secret_1, 
            "Second session secret should not leak first session secret");
        
        println!("✓ X3DH forward secrecy test passed");
    }

    /// Test X3DH with malformed keys
    #[tokio::test]
    async fn test_x3dh_malformed_keys() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        
        // Test with malformed identity key
        let mut malformed_identity_key = bob_identity.public_key.clone();
        malformed_identity_key[0] ^= 0xFF; // Corrupt the key
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: malformed_identity_key,
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: None,
        };
        
        let alice_result = x3dh_initiate(&alice_identity, &bob_prekey_bundle);
        assert!(alice_result.is_err(), "X3DH should fail with malformed identity key");
        
        // Test with malformed signed prekey
        let mut malformed_signed_prekey = bob_signed_prekey.public_key.clone();
        malformed_signed_prekey[0] ^= 0xFF; // Corrupt the key
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: malformed_signed_prekey,
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: None,
        };
        
        let alice_result = x3dh_initiate(&alice_identity, &bob_prekey_bundle);
        assert!(alice_result.is_err(), "X3DH should fail with malformed signed prekey");
        
        println!("✓ X3DH malformed keys test passed");
    }

    /// Test X3DH performance characteristics
    #[tokio::test]
    async fn test_x3dh_performance() {
        let mut ctx = TestContext::with_default();
        
        if !ctx.config.performance_mode {
            println!("⏭ Skipping performance test (not in performance mode)");
            return;
        }
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let bob_one_time_prekeys = generate_one_time_prekeys(1);
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
        };
        
        let benchmark = BenchmarkRunner::new()
            .with_iterations(1000)
            .with_warmup(100);
        
        // Benchmark X3DH initiation
        let initiate_result = benchmark.run("x3dh_initiate", || {
            x3dh_initiate(&alice_identity, &bob_prekey_bundle)
                .map_err(|e| format!("X3DH initiate error: {:?}", e))
        });
        
        initiate_result.print_summary();
        
        // Verify performance requirements
        assert!(initiate_result.avg_duration.as_millis() < 10, 
            "X3DH initiation should complete in under 10ms on average");
        assert!(initiate_result.ops_per_second > 100.0,
            "X3DH should support at least 100 operations per second");
        
        println!("✓ X3DH performance test passed");
    }

    /// Test X3DH security properties
    #[tokio::test]
    async fn test_x3dh_security_properties() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let bob_one_time_prekeys = generate_one_time_prekeys(1);
        
        let bob_prekey_bundle = PreKeyBundle {
            identity_key: bob_identity.public_key.clone(),
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: Some(bob_one_time_prekeys[0].public_key.clone()),
        };
        
        let (alice_shared_secret, alice_ephemeral_key) = 
            x3dh_initiate(&alice_identity, &bob_prekey_bundle).unwrap();
        
        let bob_shared_secret = x3dh_respond(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekeys[0]),
            &alice_identity.public_key,
            &alice_ephemeral_key,
        ).unwrap();
        
        // Test authentication: shared secret should be tied to identities
        crypto_assert!(alice_shared_secret == bob_shared_secret, "mutual authentication");
        
        // Test key independence: shared secret should not reveal private keys
        CryptoAssertions::assert_no_key_leakage(&alice_shared_secret, &alice_identity.private_key, 
            "Alice identity key");
        CryptoAssertions::assert_no_key_leakage(&alice_shared_secret, &bob_identity.private_key, 
            "Bob identity key");
        CryptoAssertions::assert_no_key_leakage(&alice_shared_secret, &bob_signed_prekey.private_key, 
            "Bob signed prekey");
        CryptoAssertions::assert_no_key_leakage(&alice_shared_secret, &bob_one_time_prekeys[0].private_key, 
            "Bob one-time prekey");
        
        // Test deniability: ephemeral key should not be tied to Alice's identity
        CryptoAssertions::assert_no_key_leakage(&alice_ephemeral_key.public_key, &alice_identity.private_key, 
            "Alice ephemeral key deniability");
        
        println!("✓ X3DH security properties test passed");
    }

    /// Test X3DH with concurrent operations
    #[tokio::test]
    async fn test_x3dh_concurrent_operations() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let bob_one_time_prekeys = generate_one_time_prekeys(10);
        
        let mut handles = Vec::new();
        
        // Launch concurrent X3DH operations
        for i in 0..10 {
            let alice_identity = alice_identity.clone();
            let bob_identity = bob_identity.clone();
            let bob_signed_prekey = bob_signed_prekey.clone();
            let bob_one_time_prekey = bob_one_time_prekeys[i].clone();
            
            let handle = tokio::spawn(async move {
                let bob_prekey_bundle = PreKeyBundle {
                    identity_key: bob_identity.public_key.clone(),
                    signed_prekey: bob_signed_prekey.public_key.clone(),
                    signed_prekey_signature: bob_signed_prekey.signature.clone(),
                    one_time_prekey: Some(bob_one_time_prekey.public_key.clone()),
                };
                
                let (alice_shared_secret, alice_ephemeral_key) = 
                    x3dh_initiate(&alice_identity, &bob_prekey_bundle)?;
                
                let bob_shared_secret = x3dh_respond(
                    &bob_identity,
                    &bob_signed_prekey,
                    Some(&bob_one_time_prekey),
                    &alice_identity.public_key,
                    &alice_ephemeral_key,
                )?;
                
                assert_eq!(alice_shared_secret, bob_shared_secret);
                Ok::<_, SignalProtocolError>(alice_shared_secret)
            });
            
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        let mut shared_secrets = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent X3DH operation should succeed");
            shared_secrets.push(result.unwrap());
        }
        
        // Verify all shared secrets are different (due to different one-time prekeys)
        for i in 0..shared_secrets.len() {
            for j in i+1..shared_secrets.len() {
                assert_ne!(shared_secrets[i], shared_secrets[j], 
                    "Concurrent X3DH operations should produce different secrets");
            }
        }
        
        println!("✓ X3DH concurrent operations test passed");
    }

    /// Test X3DH error handling and edge cases
    #[tokio::test]
    async fn test_x3dh_error_handling() {
        let mut ctx = TestContext::with_default();
        
        let alice_identity = ctx.create_test_identity("alice");
        let bob_identity = ctx.create_test_identity("bob");
        
        // Test with empty prekey bundle
        let empty_bundle = PreKeyBundle {
            identity_key: vec![],
            signed_prekey: vec![],
            signed_prekey_signature: vec![],
            one_time_prekey: None,
        };
        
        let result = x3dh_initiate(&alice_identity, &empty_bundle);
        assert!(result.is_err(), "X3DH should fail with empty prekey bundle");
        
        // Test with mismatched key sizes
        let bob_signed_prekey = generate_signed_prekey(&bob_identity.private_key);
        let mut oversized_key = bob_identity.public_key.clone();
        oversized_key.extend_from_slice(&[0u8; 100]); // Make it too large
        
        let oversized_bundle = PreKeyBundle {
            identity_key: oversized_key,
            signed_prekey: bob_signed_prekey.public_key.clone(),
            signed_prekey_signature: bob_signed_prekey.signature.clone(),
            one_time_prekey: None,
        };
        
        let result = x3dh_initiate(&alice_identity, &oversized_bundle);
        assert!(result.is_err(), "X3DH should fail with oversized keys");
        
        // Test error message safety (no sensitive data leakage)
        if let Err(error) = result {
            let error_message = format!("{:?}", error);
            let sensitive_data = [
                &hex::encode(&alice_identity.private_key),
                &hex::encode(&bob_identity.private_key),
            ];
            
            ErrorAssertions::assert_safe_error_messages(&error, &sensitive_data, 
                "X3DH error messages");
        }
        
        println!("✓ X3DH error handling test passed");
    }
}

/// Helper functions for X3DH testing

/// Generate a signed prekey for testing
fn generate_signed_prekey(identity_private_key: &[u8]) -> SignedPreKey {
    let keypair = generate_keypair();
    let signature = sign_prekey(identity_private_key, &keypair.public_key);
    
    SignedPreKey {
        id: 1,
        public_key: keypair.public_key,
        private_key: keypair.private_key,
        signature,
        timestamp: std::time::SystemTime::now(),
    }
}

/// Generate one-time prekeys for testing
fn generate_one_time_prekeys(count: usize) -> Vec<OneTimePreKey> {
    (0..count).map(|i| {
        let keypair = generate_keypair();
        OneTimePreKey {
            id: i as u32,
            public_key: keypair.public_key,
            private_key: keypair.private_key,
        }
    }).collect()
}

/// Generate a keypair for testing
fn generate_keypair() -> KeyPair {
    let private_key = generate_private_key();
    let public_key = derive_public_key(&private_key);
    
    KeyPair {
        public_key,
        private_key,
    }
}

/// Generate a private key for testing
fn generate_private_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Derive public key from private key
fn derive_public_key(private_key: &[u8]) -> Vec<u8> {
    // Simplified public key derivation for testing
    // In a real implementation, this would use proper curve25519 operations
    let mut public_key = vec![0u8; 32];
    public_key.copy_from_slice(&private_key[..32]);
    public_key[0] |= 0x40; // Mark as public key
    public_key
}

/// Sign a prekey with identity key
fn sign_prekey(identity_private_key: &[u8], prekey_public: &[u8]) -> Vec<u8> {
    // Simplified signature for testing
    // In a real implementation, this would use proper Ed25519 signatures
    let mut signature = vec![0u8; 64];
    signature[..32].copy_from_slice(&identity_private_key[..32]);
    signature[32..].copy_from_slice(&prekey_public[..32]);
    signature
}

/// Test data structures

#[derive(Debug, Clone)]
struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SignedPreKey {
    pub id: u32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: std::time::SystemTime,
}

#[derive(Debug, Clone)]
struct OneTimePreKey {
    pub id: u32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PreKeyBundle {
    pub identity_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
}

/// Mock X3DH functions for testing
/// These would be replaced with actual implementations

fn x3dh_initiate(
    alice_identity: &IdentityKeyPair,
    bob_prekey_bundle: &PreKeyBundle,
) -> Result<(Vec<u8>, KeyPair), SignalProtocolError> {
    // Validate inputs
    if bob_prekey_bundle.identity_key.is_empty() || 
       bob_prekey_bundle.signed_prekey.is_empty() ||
       bob_prekey_bundle.signed_prekey_signature.is_empty() {
        return Err(SignalProtocolError::InvalidKey("Empty key in prekey bundle".to_string()));
    }
    
    // Verify signature
    if !verify_signature(&bob_prekey_bundle.identity_key, 
                        &bob_prekey_bundle.signed_prekey,
                        &bob_prekey_bundle.signed_prekey_signature) {
        return Err(SignalProtocolError::InvalidSignature);
    }
    
    // Generate ephemeral key
    let ephemeral_keypair = generate_keypair();
    
    // Perform key agreement (simplified)
    let mut shared_secret = vec![0u8; 32];
    
    // DH1: alice_identity_private * bob_signed_prekey_public
    xor_keys(&mut shared_secret, &alice_identity.private_key, &bob_prekey_bundle.signed_prekey);
    
    // DH2: alice_ephemeral_private * bob_identity_public
    xor_keys(&mut shared_secret, &ephemeral_keypair.private_key, &bob_prekey_bundle.identity_key);
    
    // DH3: alice_ephemeral_private * bob_signed_prekey_public
    xor_keys(&mut shared_secret, &ephemeral_keypair.private_key, &bob_prekey_bundle.signed_prekey);
    
    // DH4: alice_ephemeral_private * bob_one_time_prekey_public (if present)
    if let Some(ref one_time_prekey) = bob_prekey_bundle.one_time_prekey {
        xor_keys(&mut shared_secret, &ephemeral_keypair.private_key, one_time_prekey);
    }
    
    Ok((shared_secret, ephemeral_keypair))
}

fn x3dh_respond(
    bob_identity: &IdentityKeyPair,
    bob_signed_prekey: &SignedPreKey,
    bob_one_time_prekey: Option<&OneTimePreKey>,
    alice_identity_public: &[u8],
    alice_ephemeral_public: &KeyPair,
) -> Result<Vec<u8>, SignalProtocolError> {
    // Perform key agreement (simplified)
    let mut shared_secret = vec![0u8; 32];
    
    // DH1: bob_signed_prekey_private * alice_identity_public
    xor_keys(&mut shared_secret, &bob_signed_prekey.private_key, alice_identity_public);
    
    // DH2: bob_identity_private * alice_ephemeral_public
    xor_keys(&mut shared_secret, &bob_identity.private_key, &alice_ephemeral_public.public_key);
    
    // DH3: bob_signed_prekey_private * alice_ephemeral_public
    xor_keys(&mut shared_secret, &bob_signed_prekey.private_key, &alice_ephemeral_public.public_key);
    
    // DH4: bob_one_time_prekey_private * alice_ephemeral_public (if present)
    if let Some(one_time_prekey) = bob_one_time_prekey {
        xor_keys(&mut shared_secret, &one_time_prekey.private_key, &alice_ephemeral_public.public_key);
    }
    
    Ok(shared_secret)
}

fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Simplified signature verification for testing
    if signature.len() != 64 || public_key.len() != 32 || message.len() != 32 {
        return false;
    }
    
    // Check if signature matches expected pattern
    signature[..32] == public_key[..32] && signature[32..] == message[..32]
}

fn xor_keys(output: &mut [u8], key1: &[u8], key2: &[u8]) {
    let len = output.len().min(key1.len()).min(key2.len());
    for i in 0..len {
        output[i] ^= key1[i] ^ key2[i];
    }
}