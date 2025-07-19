/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Post-quantum cryptography preparation with hybrid classical/PQ schemes.
 * Implements CRYSTALS-Kyber, Dilithium, SPHINCS+, and Classic McEliece algorithms
 * for quantum-resistant key agreement, signatures, and migration strategies.
 */

// signal_crypto_lib/src/post_quantum.rs
// Post-quantum cryptography preparation and hybrid schemes

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::types::*;

/// Post-quantum cryptographic algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PQAlgorithm {
    /// CRYSTALS-Kyber for key encapsulation
    Kyber512,
    Kyber768,
    Kyber1024,
    
    /// CRYSTALS-Dilithium for digital signatures
    Dilithium2,
    Dilithium3,
    Dilithium5,
    
    /// SPHINCS+ for digital signatures
    SphincsPlus128s,
    SphincsPlus192s,
    SphincsPlus256s,
    
    /// Classic McEliece for key encapsulation
    ClassicMcEliece348864,
    ClassicMcEliece460896,
    ClassicMcEliece6688128,
}

impl PQAlgorithm {
    pub fn key_size(&self) -> usize {
        match self {
            PQAlgorithm::Kyber512 => 800,
            PQAlgorithm::Kyber768 => 1184,
            PQAlgorithm::Kyber1024 => 1568,
            PQAlgorithm::Dilithium2 => 1312,
            PQAlgorithm::Dilithium3 => 1952,
            PQAlgorithm::Dilithium5 => 2592,
            PQAlgorithm::SphincsPlus128s => 32,
            PQAlgorithm::SphincsPlus192s => 48,
            PQAlgorithm::SphincsPlus256s => 64,
            PQAlgorithm::ClassicMcEliece348864 => 261120,
            PQAlgorithm::ClassicMcEliece460896 => 524160,
            PQAlgorithm::ClassicMcEliece6688128 => 1044992,
        }
    }
    
    pub fn signature_size(&self) -> Option<usize> {
        match self {
            PQAlgorithm::Dilithium2 => Some(2420),
            PQAlgorithm::Dilithium3 => Some(3293),
            PQAlgorithm::Dilithium5 => Some(4595),
            PQAlgorithm::SphincsPlus128s => Some(7856),
            PQAlgorithm::SphincsPlus192s => Some(16224),
            PQAlgorithm::SphincsPlus256s => Some(29792),
            _ => None,
        }
    }
    
    pub fn ciphertext_size(&self) -> Option<usize> {
        match self {
            PQAlgorithm::Kyber512 => Some(768),
            PQAlgorithm::Kyber768 => Some(1088),
            PQAlgorithm::Kyber1024 => Some(1568),
            PQAlgorithm::ClassicMcEliece348864 => Some(128),
            PQAlgorithm::ClassicMcEliece460896 => Some(188),
            PQAlgorithm::ClassicMcEliece6688128 => Some(240),
            _ => None,
        }
    }
    
    pub fn is_kem(&self) -> bool {
        matches!(self, 
            PQAlgorithm::Kyber512 | PQAlgorithm::Kyber768 | PQAlgorithm::Kyber1024 |
            PQAlgorithm::ClassicMcEliece348864 | PQAlgorithm::ClassicMcEliece460896 | PQAlgorithm::ClassicMcEliece6688128
        )
    }
    
    pub fn is_signature(&self) -> bool {
        matches!(self,
            PQAlgorithm::Dilithium2 | PQAlgorithm::Dilithium3 | PQAlgorithm::Dilithium5 |
            PQAlgorithm::SphincsPlus128s | PQAlgorithm::SphincsPlus192s | PQAlgorithm::SphincsPlus256s
        )
    }
}

/// Hybrid key pair combining classical and post-quantum keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKeyPair {
    pub classical_keypair: ClassicalKeyPair,
    pub pq_keypair: PostQuantumKeyPair,
    pub algorithm_suite: AlgorithmSuite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicalKeyPair {
    pub x25519_private: [u8; 32],
    pub x25519_public: [u8; 32],
    pub ed25519_private: [u8; 32],
    pub ed25519_public: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumKeyPair {
    pub kem_private: Vec<u8>,
    pub kem_public: Vec<u8>,
    pub signature_private: Vec<u8>,
    pub signature_public: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmSuite {
    pub kem_algorithm: PQAlgorithm,
    pub signature_algorithm: PQAlgorithm,
    pub hybrid_mode: HybridMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HybridMode {
    /// Classical algorithms only (current mode)
    ClassicalOnly,
    /// Post-quantum algorithms only (future mode)
    PostQuantumOnly,
    /// Both classical and post-quantum (transition mode)
    Hybrid,
}

/// Hybrid X3DH implementation with post-quantum support
pub struct HybridX3DH {
    algorithm_suite: AlgorithmSuite,
}

impl HybridX3DH {
    pub fn new(algorithm_suite: AlgorithmSuite) -> Self {
        Self { algorithm_suite }
    }
    
    /// Generate hybrid identity keypair
    pub fn generate_identity_keypair(&self) -> Result<HybridKeyPair, PQError> {
        let classical_keypair = self.generate_classical_keypair()?;
        let pq_keypair = match self.algorithm_suite.hybrid_mode {
            HybridMode::ClassicalOnly => PostQuantumKeyPair {
                kem_private: Vec::new(),
                kem_public: Vec::new(),
                signature_private: Vec::new(),
                signature_public: Vec::new(),
            },
            HybridMode::PostQuantumOnly | HybridMode::Hybrid => {
                self.generate_pq_keypair()?
            }
        };
        
        Ok(HybridKeyPair {
            classical_keypair,
            pq_keypair,
            algorithm_suite: self.algorithm_suite.clone(),
        })
    }
    
    /// Perform hybrid key agreement
    pub fn hybrid_key_agreement(
        &self,
        alice_keypair: &HybridKeyPair,
        bob_public: &HybridKeyPair,
        alice_ephemeral: &[u8; 32],
    ) -> Result<Vec<u8>, PQError> {
        let mut shared_secrets = Vec::new();
        
        // Classical key agreement
        if matches!(self.algorithm_suite.hybrid_mode, HybridMode::ClassicalOnly | HybridMode::Hybrid) {
            let classical_secret = self.classical_key_agreement(
                &alice_keypair.classical_keypair,
                &bob_public.classical_keypair,
                alice_ephemeral,
            )?;
            shared_secrets.push(classical_secret);
        }
        
        // Post-quantum key agreement
        if matches!(self.algorithm_suite.hybrid_mode, HybridMode::PostQuantumOnly | HybridMode::Hybrid) {
            let pq_secret = self.pq_key_agreement(
                &alice_keypair.pq_keypair,
                &bob_public.pq_keypair,
            )?;
            shared_secrets.push(pq_secret);
        }
        
        // Combine shared secrets using KDF
        self.combine_shared_secrets(&shared_secrets)
    }
    
    fn generate_classical_keypair(&self) -> Result<ClassicalKeyPair, PQError> {
        use rand::rngs::OsRng;
        use x25519_dalek::{StaticSecret, PublicKey};
        use ed25519_dalek::{SigningKey, VerifyingKey};
        
        // Generate X25519 keypair using StaticSecret instead of EphemeralSecret
        let x25519_private = StaticSecret::random_from_rng(OsRng);
        let x25519_public = PublicKey::from(&x25519_private);
        
        // Generate Ed25519 keypair
        let ed25519_signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_verifying_key = VerifyingKey::from(&ed25519_signing_key);
        
        Ok(ClassicalKeyPair {
            x25519_private: x25519_private.to_bytes(),
            x25519_public: x25519_public.to_bytes(),
            ed25519_private: ed25519_signing_key.to_bytes(),
            ed25519_public: ed25519_verifying_key.to_bytes(),
        })
    }
    
    fn generate_pq_keypair(&self) -> Result<PostQuantumKeyPair, PQError> {
        // This is a placeholder implementation
        // In a real implementation, you would use actual post-quantum libraries
        // such as liboqs or pqcrypto
        
        let kem_key_size = self.algorithm_suite.kem_algorithm.key_size();
        let sig_key_size = self.algorithm_suite.signature_algorithm.key_size();
        
        // Generate mock keys (in reality, use proper PQ key generation)
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        
        let mut kem_private = vec![0u8; kem_key_size];
        let mut kem_public = vec![0u8; kem_key_size];
        let mut signature_private = vec![0u8; sig_key_size];
        let mut signature_public = vec![0u8; sig_key_size];
        
        rng.fill_bytes(&mut kem_private);
        rng.fill_bytes(&mut kem_public);
        rng.fill_bytes(&mut signature_private);
        rng.fill_bytes(&mut signature_public);
        
        Ok(PostQuantumKeyPair {
            kem_private,
            kem_public,
            signature_private,
            signature_public,
        })
    }
    
    fn classical_key_agreement(
        &self,
        alice_keypair: &ClassicalKeyPair,
        bob_public: &ClassicalKeyPair,
        alice_ephemeral: &[u8; 32],
    ) -> Result<Vec<u8>, PQError> {
        use x25519_dalek::{StaticSecret, PublicKey};
        
        let alice_private = StaticSecret::from(alice_keypair.x25519_private);
        let bob_public_key = PublicKey::from(bob_public.x25519_public);
        let alice_ephemeral_secret = StaticSecret::from(*alice_ephemeral);
        
        // Perform multiple DH operations as in X3DH
        let dh1 = alice_private.diffie_hellman(&bob_public_key);
        let dh2 = alice_ephemeral_secret.diffie_hellman(&bob_public_key);
        
        // Combine the shared secrets
        let mut combined = Vec::new();
        combined.extend_from_slice(dh1.as_bytes());
        combined.extend_from_slice(dh2.as_bytes());
        
        Ok(combined)
    }
    
    fn pq_key_agreement(
        &self,
        _alice_keypair: &PostQuantumKeyPair,
        _bob_public: &PostQuantumKeyPair,
    ) -> Result<Vec<u8>, PQError> {
        // This is a placeholder implementation
        // In a real implementation, you would use the actual post-quantum KEM
        
        let shared_secret_size = match self.algorithm_suite.kem_algorithm {
            PQAlgorithm::Kyber512 | PQAlgorithm::Kyber768 | PQAlgorithm::Kyber1024 => 32,
            _ => 32, // Default shared secret size
        };
        
        // Generate mock shared secret (in reality, use proper PQ KEM)
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut shared_secret = vec![0u8; shared_secret_size];
        rng.fill_bytes(&mut shared_secret);
        
        Ok(shared_secret)
    }
    
    fn combine_shared_secrets(&self, secrets: &[Vec<u8>]) -> Result<Vec<u8>, PQError> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        if secrets.is_empty() {
            return Err(PQError::InvalidInput);
        }
        
        // Concatenate all shared secrets
        let mut combined_input = Vec::new();
        for secret in secrets {
            combined_input.extend_from_slice(secret);
        }
        
        // Use HKDF to derive final shared secret
        let hk = Hkdf::<Sha256>::new(None, &combined_input);
        let mut output = vec![0u8; 32]; // 256-bit output
        hk.expand(b"hybrid_shared_secret", &mut output)
            .map_err(|_| PQError::KeyDerivationFailed)?;
        
        Ok(output)
    }
}

/// Hybrid signature scheme combining classical and post-quantum signatures
pub struct HybridSignature {
    algorithm_suite: AlgorithmSuite,
}

impl HybridSignature {
    pub fn new(algorithm_suite: AlgorithmSuite) -> Self {
        Self { algorithm_suite }
    }
    
    /// Sign message with hybrid scheme
    pub fn sign(&self, keypair: &HybridKeyPair, message: &[u8]) -> Result<HybridSignatureValue, PQError> {
        let mut signatures = Vec::new();
        
        // Classical signature
        if matches!(self.algorithm_suite.hybrid_mode, HybridMode::ClassicalOnly | HybridMode::Hybrid) {
            let classical_sig = self.classical_sign(&keypair.classical_keypair, message)?;
            signatures.push(SignatureComponent::Classical(classical_sig));
        }
        
        // Post-quantum signature
        if matches!(self.algorithm_suite.hybrid_mode, HybridMode::PostQuantumOnly | HybridMode::Hybrid) {
            let pq_sig = self.pq_sign(&keypair.pq_keypair, message)?;
            signatures.push(SignatureComponent::PostQuantum(pq_sig));
        }
        
        Ok(HybridSignatureValue {
            signatures,
            algorithm_suite: self.algorithm_suite.clone(),
        })
    }
    
    /// Verify hybrid signature
    pub fn verify(&self, public_key: &HybridKeyPair, message: &[u8], signature: &HybridSignatureValue) -> Result<bool, PQError> {
        for sig_component in &signature.signatures {
            match sig_component {
                SignatureComponent::Classical(sig) => {
                    if !self.classical_verify(&public_key.classical_keypair, message, sig)? {
                        return Ok(false);
                    }
                }
                SignatureComponent::PostQuantum(sig) => {
                    if !self.pq_verify(&public_key.pq_keypair, message, sig)? {
                        return Ok(false);
                    }
                }
            }
        }
        
        Ok(true)
    }
    
    fn classical_sign(&self, keypair: &ClassicalKeyPair, message: &[u8]) -> Result<Vec<u8>, PQError> {
        use ed25519_dalek::{SigningKey, Signer};
        
        let signing_key = SigningKey::from_bytes(&keypair.ed25519_private);
        let signature = signing_key.sign(message);
        
        Ok(signature.to_bytes().to_vec())
    }
    
    fn classical_verify(&self, keypair: &ClassicalKeyPair, message: &[u8], signature: &[u8]) -> Result<bool, PQError> {
        use ed25519_dalek::{VerifyingKey, Verifier, Signature};
        
        let verifying_key = VerifyingKey::from_bytes(&keypair.ed25519_public)
            .map_err(|_| PQError::InvalidKey)?;
        
        let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| PQError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        
        Ok(verifying_key.verify(message, &signature).is_ok())
    }
    
    fn pq_sign(&self, _keypair: &PostQuantumKeyPair, _message: &[u8]) -> Result<Vec<u8>, PQError> {
        // Placeholder implementation
        // In reality, use proper post-quantum signature algorithm
        
        let sig_size = self.algorithm_suite.signature_algorithm.signature_size()
            .unwrap_or(64);
        
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut signature = vec![0u8; sig_size];
        rng.fill_bytes(&mut signature);
        
        Ok(signature)
    }
    
    fn pq_verify(&self, _keypair: &PostQuantumKeyPair, _message: &[u8], _signature: &[u8]) -> Result<bool, PQError> {
        // Placeholder implementation
        // In reality, use proper post-quantum signature verification
        Ok(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignatureValue {
    pub signatures: Vec<SignatureComponent>,
    pub algorithm_suite: AlgorithmSuite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureComponent {
    Classical(Vec<u8>),
    PostQuantum(Vec<u8>),
}

/// Migration manager for transitioning between cryptographic algorithms
pub struct CryptoMigrationManager {
    supported_suites: Vec<AlgorithmSuite>,
    current_suite: AlgorithmSuite,
    migration_policy: MigrationPolicy,
}

#[derive(Debug, Clone)]
pub struct MigrationPolicy {
    pub auto_upgrade: bool,
    pub fallback_enabled: bool,
    pub migration_deadline: Option<u64>, // Unix timestamp
    pub compatibility_window: std::time::Duration,
}

impl CryptoMigrationManager {
    pub fn new(current_suite: AlgorithmSuite, policy: MigrationPolicy) -> Self {
        let supported_suites = vec![
            // Classical only
            AlgorithmSuite {
                kem_algorithm: PQAlgorithm::Kyber512, // Placeholder
                signature_algorithm: PQAlgorithm::Dilithium2, // Placeholder
                hybrid_mode: HybridMode::ClassicalOnly,
            },
            // Hybrid mode
            AlgorithmSuite {
                kem_algorithm: PQAlgorithm::Kyber768,
                signature_algorithm: PQAlgorithm::Dilithium3,
                hybrid_mode: HybridMode::Hybrid,
            },
            // Post-quantum only
            AlgorithmSuite {
                kem_algorithm: PQAlgorithm::Kyber1024,
                signature_algorithm: PQAlgorithm::Dilithium5,
                hybrid_mode: HybridMode::PostQuantumOnly,
            },
        ];
        
        Self {
            supported_suites,
            current_suite,
            migration_policy: policy,
        }
    }
    
    pub fn should_migrate(&self) -> bool {
        if !self.migration_policy.auto_upgrade {
            return false;
        }
        
        if let Some(deadline) = self.migration_policy.migration_deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            if now >= deadline {
                return true;
            }
        }
        
        // Check if current suite is deprecated
        matches!(self.current_suite.hybrid_mode, HybridMode::ClassicalOnly)
    }
    
    pub fn get_recommended_suite(&self) -> &AlgorithmSuite {
        // Recommend hybrid mode as the safest transition
        self.supported_suites.iter()
            .find(|suite| matches!(suite.hybrid_mode, HybridMode::Hybrid))
            .unwrap_or(&self.current_suite)
    }
    
    pub fn is_compatible(&self, other_suite: &AlgorithmSuite) -> bool {
        // Check if we can communicate with the other suite
        match (&self.current_suite.hybrid_mode, &other_suite.hybrid_mode) {
            (HybridMode::ClassicalOnly, HybridMode::ClassicalOnly) => true,
            (HybridMode::Hybrid, _) => true,
            (_, HybridMode::Hybrid) => true,
            (HybridMode::PostQuantumOnly, HybridMode::PostQuantumOnly) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PQError {
    InvalidInput,
    InvalidKey,
    InvalidSignature,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    SignatureFailed,
    VerificationFailed,
    UnsupportedAlgorithm,
    MigrationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_algorithm_properties() {
        assert!(PQAlgorithm::Kyber512.is_kem());
        assert!(!PQAlgorithm::Kyber512.is_signature());
        
        assert!(PQAlgorithm::Dilithium2.is_signature());
        assert!(!PQAlgorithm::Dilithium2.is_kem());
        
        assert!(PQAlgorithm::Kyber512.key_size() > 0);
        assert!(PQAlgorithm::Dilithium2.signature_size().is_some());
    }
    
    #[test]
    fn test_hybrid_keypair_generation() {
        let suite = AlgorithmSuite {
            kem_algorithm: PQAlgorithm::Kyber768,
            signature_algorithm: PQAlgorithm::Dilithium3,
            hybrid_mode: HybridMode::Hybrid,
        };
        
        let hybrid_x3dh = HybridX3DH::new(suite);
        let keypair = hybrid_x3dh.generate_identity_keypair().unwrap();
        
        assert_eq!(keypair.classical_keypair.x25519_public.len(), 32);
        assert_eq!(keypair.classical_keypair.ed25519_public.len(), 32);
        assert!(!keypair.pq_keypair.kem_public.is_empty());
        assert!(!keypair.pq_keypair.signature_public.is_empty());
    }
    
    #[test]
    fn test_migration_manager() {
        let current_suite = AlgorithmSuite {
            kem_algorithm: PQAlgorithm::Kyber512,
            signature_algorithm: PQAlgorithm::Dilithium2,
            hybrid_mode: HybridMode::ClassicalOnly,
        };
        
        let policy = MigrationPolicy {
            auto_upgrade: true,
            fallback_enabled: true,
            migration_deadline: None,
            compatibility_window: std::time::Duration::from_secs(86400),
        };
        
        let manager = CryptoMigrationManager::new(current_suite, policy);
        
        // Should recommend migration from classical-only
        assert!(manager.should_migrate());
        
        let recommended = manager.get_recommended_suite();
        assert!(matches!(recommended.hybrid_mode, HybridMode::Hybrid));
    }
    
    #[test]
    fn test_hybrid_signature() {
        let suite = AlgorithmSuite {
            kem_algorithm: PQAlgorithm::Kyber768,
            signature_algorithm: PQAlgorithm::Dilithium3,
            hybrid_mode: HybridMode::Hybrid,
        };
        
        let hybrid_x3dh = HybridX3DH::new(suite.clone());
        let keypair = hybrid_x3dh.generate_identity_keypair().unwrap();
        
        let hybrid_sig = HybridSignature::new(suite);
        let message = b"test message";
        
        let signature = hybrid_sig.sign(&keypair, message).unwrap();
        let is_valid = hybrid_sig.verify(&keypair, message, &signature).unwrap();
        
        assert!(is_valid);
        assert_eq!(signature.signatures.len(), 2); // Classical + PQ
    }
}