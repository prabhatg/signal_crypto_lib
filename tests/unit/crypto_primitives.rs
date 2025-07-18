// tests/unit/crypto_primitives.rs
//! Unit tests for cryptographic primitives and utilities

use crate::common::{
    fixtures::*,
    helpers::*,
    assertions::*,
    mocks::*,
};
use std::collections::HashMap;
use rand::{Rng, RngCore};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type HmacSha256 = Hmac<Sha256>;

// Mock cryptographic key structures
#[derive(Debug, Clone, PartialEq)]
struct MockPrivateKey {
    key_data: Vec<u8>,
    key_type: KeyType,
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct MockPublicKey {
    key_data: Vec<u8>,
    key_type: KeyType,
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct MockKeyPair {
    private_key: MockPrivateKey,
    public_key: MockPublicKey,
    key_type: KeyType,
}

#[derive(Debug, Clone, PartialEq)]
enum KeyType {
    Ed25519,
    X25519,
    Secp256k1,
    RSA2048,
    RSA4096,
}

impl MockKeyPair {
    fn new(key_type: KeyType) -> Self {
        let mut rng = rand::thread_rng();
        let key_size = match key_type {
            KeyType::Ed25519 | KeyType::X25519 => 32,
            KeyType::Secp256k1 => 32,
            KeyType::RSA2048 => 256,
            KeyType::RSA4096 => 512,
        };
        
        let mut private_data = vec![0u8; key_size];
        let mut public_data = vec![0u8; key_size];
        rng.fill_bytes(&mut private_data);
        rng.fill_bytes(&mut public_data);
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            private_key: MockPrivateKey {
                key_data: private_data,
                key_type: key_type.clone(),
                created_at: timestamp,
            },
            public_key: MockPublicKey {
                key_data: public_data,
                key_type: key_type.clone(),
                created_at: timestamp,
            },
            key_type,
        }
    }
    
    fn private_key(&self) -> &MockPrivateKey {
        &self.private_key
    }
    
    fn public_key(&self) -> &MockPublicKey {
        &self.public_key
    }
    
    fn key_type(&self) -> &KeyType {
        &self.key_type
    }
}

// Mock cryptographic operations
struct MockCryptoProvider {
    supported_algorithms: Vec<CryptoAlgorithm>,
    key_cache: HashMap<String, MockKeyPair>,
}

#[derive(Debug, Clone, PartialEq)]
enum CryptoAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    Ed25519,
    X25519,
    HMACSHA256,
    SHA256,
    SHA512,
    HKDF,
    PBKDF2,
    Scrypt,
}

impl MockCryptoProvider {
    fn new() -> Self {
        Self {
            supported_algorithms: vec![
                CryptoAlgorithm::AES256GCM,
                CryptoAlgorithm::ChaCha20Poly1305,
                CryptoAlgorithm::Ed25519,
                CryptoAlgorithm::X25519,
                CryptoAlgorithm::HMACSHA256,
                CryptoAlgorithm::SHA256,
                CryptoAlgorithm::SHA512,
                CryptoAlgorithm::HKDF,
                CryptoAlgorithm::PBKDF2,
                CryptoAlgorithm::Scrypt,
            ],
            key_cache: HashMap::new(),
        }
    }
    
    fn supports_algorithm(&self, algorithm: &CryptoAlgorithm) -> bool {
        self.supported_algorithms.contains(algorithm)
    }
    
    fn generate_keypair(&mut self, key_type: KeyType) -> Result<String> {
        let keypair = MockKeyPair::new(key_type);
        let key_id = format!("key_{}", rand::thread_rng().gen::<u32>());
        self.key_cache.insert(key_id.clone(), keypair);
        Ok(key_id)
    }
    
    fn get_keypair(&self, key_id: &str) -> Option<&MockKeyPair> {
        self.key_cache.get(key_id)
    }
    
    fn hash_sha256(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn hash_sha512(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Sha512;
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| format!("HMAC key error: {}", e))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    
    fn hkdf_expand(&self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let hk = Hkdf::<Sha256>::from_prk(prk)
            .map_err(|e| format!("HKDF PRK error: {}", e))?;
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm)
            .map_err(|e| format!("HKDF expand error: {}", e))?;
        Ok(okm)
    }
    
    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        prk.to_vec()
    }
    
    fn pbkdf2_derive(&self, password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
        use pbkdf2::pbkdf2;
        use sha2::Sha256;
        
        let mut output = vec![0u8; length];
        pbkdf2::<HmacSha256>(password, salt, iterations, &mut output);
        output
    }
    
    fn encrypt_aes256gcm(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err("AES-256-GCM requires 32-byte key".into());
        }
        if nonce.len() != 12 {
            return Err("AES-256-GCM requires 12-byte nonce".into());
        }
        
        let cipher_key = Key::from_slice(key);
        let cipher_nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(cipher_key);
        
        cipher.encrypt(cipher_nonce, [plaintext, aad].concat().as_slice())
            .map_err(|e| format!("AES-256-GCM encryption error: {}", e).into())
    }
    
    fn decrypt_aes256gcm(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err("AES-256-GCM requires 32-byte key".into());
        }
        if nonce.len() != 12 {
            return Err("AES-256-GCM requires 12-byte nonce".into());
        }
        
        let cipher_key = Key::from_slice(key);
        let cipher_nonce = Nonce::from_slice(nonce);
        let cipher = Aes256Gcm::new(cipher_key);
        
        cipher.decrypt(cipher_nonce, ciphertext)
            .map_err(|e| format!("AES-256-GCM decryption error: {}", e).into())
    }
    
    fn generate_random_bytes(&self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
    
    fn constant_time_compare(&self, a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
    
    fn secure_zero(&self, data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
    }
}

// Mock signature operations
struct MockSignatureProvider {
    crypto_provider: MockCryptoProvider,
}

impl MockSignatureProvider {
    fn new() -> Self {
        Self {
            crypto_provider: MockCryptoProvider::new(),
        }
    }
    
    fn sign_ed25519(&self, private_key: &MockPrivateKey, message: &[u8]) -> Result<Vec<u8>> {
        if private_key.key_type != KeyType::Ed25519 {
            return Err("Invalid key type for Ed25519 signing".into());
        }
        
        // Mock signature - in real implementation would use ed25519-dalek
        let mut signature = Vec::new();
        signature.extend_from_slice(&private_key.key_data[..16]); // Mock R component
        signature.extend_from_slice(&self.crypto_provider.hash_sha256(message)[..16]); // Mock S component
        Ok(signature)
    }
    
    fn verify_ed25519(&self, public_key: &MockPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        if public_key.key_type != KeyType::Ed25519 {
            return Err("Invalid key type for Ed25519 verification".into());
        }
        
        if signature.len() != 32 {
            return Ok(false);
        }
        
        // Mock verification - check if signature contains expected components
        let expected_hash = &self.crypto_provider.hash_sha256(message)[..16];
        Ok(signature[16..32] == *expected_hash)
    }
    
    fn ecdh_x25519(&self, private_key: &MockPrivateKey, public_key: &MockPublicKey) -> Result<Vec<u8>> {
        if private_key.key_type != KeyType::X25519 || public_key.key_type != KeyType::X25519 {
            return Err("Invalid key types for X25519 ECDH".into());
        }
        
        // Mock ECDH - XOR the keys for deterministic result
        let mut shared_secret = vec![0u8; 32];
        for i in 0..32 {
            shared_secret[i] = private_key.key_data[i] ^ public_key.key_data[i];
        }
        Ok(shared_secret)
    }
}

// Tests for basic cryptographic operations
#[test]
fn test_keypair_generation() -> Result<()> {
    let mut crypto = MockCryptoProvider::new();
    
    // Test Ed25519 keypair generation
    let ed25519_id = crypto.generate_keypair(KeyType::Ed25519)?;
    let ed25519_keypair = crypto.get_keypair(&ed25519_id).unwrap();
    assert_eq!(ed25519_keypair.key_type(), &KeyType::Ed25519);
    assert_eq!(ed25519_keypair.private_key().key_data.len(), 32);
    assert_eq!(ed25519_keypair.public_key().key_data.len(), 32);
    
    // Test X25519 keypair generation
    let x25519_id = crypto.generate_keypair(KeyType::X25519)?;
    let x25519_keypair = crypto.get_keypair(&x25519_id).unwrap();
    assert_eq!(x25519_keypair.key_type(), &KeyType::X25519);
    assert_eq!(x25519_keypair.private_key().key_data.len(), 32);
    assert_eq!(x25519_keypair.public_key().key_data.len(), 32);
    
    // Test RSA keypair generation
    let rsa_id = crypto.generate_keypair(KeyType::RSA2048)?;
    let rsa_keypair = crypto.get_keypair(&rsa_id).unwrap();
    assert_eq!(rsa_keypair.key_type(), &KeyType::RSA2048);
    assert_eq!(rsa_keypair.private_key().key_data.len(), 256);
    assert_eq!(rsa_keypair.public_key().key_data.len(), 256);
    
    Ok(())
}

#[test]
fn test_hash_functions() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    let test_data = b"Hello, World!";
    
    // Test SHA-256
    let sha256_hash = crypto.hash_sha256(test_data);
    assert_eq!(sha256_hash.len(), 32);
    
    // Test deterministic hashing
    let sha256_hash2 = crypto.hash_sha256(test_data);
    assert_eq!(sha256_hash, sha256_hash2);
    
    // Test different input produces different hash
    let different_hash = crypto.hash_sha256(b"Different data");
    assert_ne!(sha256_hash, different_hash);
    
    // Test SHA-512
    let sha512_hash = crypto.hash_sha512(test_data);
    assert_eq!(sha512_hash.len(), 64);
    
    Ok(())
}

#[test]
fn test_hmac_operations() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    let key = b"secret_key_for_hmac_testing_12345678";
    let message = b"Message to authenticate";
    
    // Test HMAC-SHA256
    let hmac1 = crypto.hmac_sha256(key, message)?;
    assert_eq!(hmac1.len(), 32);
    
    // Test deterministic HMAC
    let hmac2 = crypto.hmac_sha256(key, message)?;
    assert_eq!(hmac1, hmac2);
    
    // Test different key produces different HMAC
    let different_key = b"different_key_for_hmac_testing_123";
    let hmac3 = crypto.hmac_sha256(different_key, message)?;
    assert_ne!(hmac1, hmac3);
    
    // Test different message produces different HMAC
    let hmac4 = crypto.hmac_sha256(key, b"Different message")?;
    assert_ne!(hmac1, hmac4);
    
    Ok(())
}

#[test]
fn test_hkdf_operations() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    let ikm = b"input_keying_material_for_testing";
    let salt = b"salt_for_hkdf_testing";
    let info = b"application_specific_info";
    
    // Test HKDF extract
    let prk = crypto.hkdf_extract(salt, ikm);
    assert_eq!(prk.len(), 32); // SHA-256 output size
    
    // Test HKDF expand
    let okm1 = crypto.hkdf_expand(&prk, info, 32)?;
    assert_eq!(okm1.len(), 32);
    
    let okm2 = crypto.hkdf_expand(&prk, info, 64)?;
    assert_eq!(okm2.len(), 64);
    
    // Test deterministic output
    let okm3 = crypto.hkdf_expand(&prk, info, 32)?;
    assert_eq!(okm1, okm3);
    
    // Test different info produces different output
    let okm4 = crypto.hkdf_expand(&prk, b"different_info", 32)?;
    assert_ne!(okm1, okm4);
    
    Ok(())
}

#[test]
fn test_pbkdf2_operations() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    let password = b"user_password_for_testing";
    let salt = b"random_salt_for_pbkdf2_testing_123";
    let iterations = 10000;
    
    // Test PBKDF2 key derivation
    let key1 = crypto.pbkdf2_derive(password, salt, iterations, 32);
    assert_eq!(key1.len(), 32);
    
    // Test deterministic output
    let key2 = crypto.pbkdf2_derive(password, salt, iterations, 32);
    assert_eq!(key1, key2);
    
    // Test different password produces different key
    let key3 = crypto.pbkdf2_derive(b"different_password", salt, iterations, 32);
    assert_ne!(key1, key3);
    
    // Test different salt produces different key
    let key4 = crypto.pbkdf2_derive(password, b"different_salt", iterations, 32);
    assert_ne!(key1, key4);
    
    // Test different iterations produces different key
    let key5 = crypto.pbkdf2_derive(password, salt, iterations * 2, 32);
    assert_ne!(key1, key5);
    
    Ok(())
}

#[test]
fn test_aes256gcm_encryption() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    let key = crypto.generate_random_bytes(32);
    let nonce = crypto.generate_random_bytes(12);
    let plaintext = b"Secret message to encrypt";
    let aad = b"additional_authenticated_data";
    
    // Test encryption
    let ciphertext = crypto.encrypt_aes256gcm(&key, &nonce, plaintext, aad)?;
    assert!(ciphertext.len() > plaintext.len()); // Should include authentication tag
    
    // Test decryption
    let decrypted = crypto.decrypt_aes256gcm(&key, &nonce, &ciphertext, aad)?;
    assert_eq!(decrypted, [plaintext, aad].concat());
    
    // Test wrong key fails decryption
    let wrong_key = crypto.generate_random_bytes(32);
    let result = crypto.decrypt_aes256gcm(&wrong_key, &nonce, &ciphertext, aad);
    assert!(result.is_err());
    
    // Test wrong nonce fails decryption
    let wrong_nonce = crypto.generate_random_bytes(12);
    let result = crypto.decrypt_aes256gcm(&key, &wrong_nonce, &ciphertext, aad);
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_signature_operations() -> Result<()> {
    let mut crypto = MockCryptoProvider::new();
    let signer = MockSignatureProvider::new();
    
    // Generate Ed25519 keypair
    let key_id = crypto.generate_keypair(KeyType::Ed25519)?;
    let keypair = crypto.get_keypair(&key_id).unwrap();
    let message = b"Message to sign and verify";
    
    // Test signing
    let signature = signer.sign_ed25519(keypair.private_key(), message)?;
    assert_eq!(signature.len(), 32);
    
    // Test verification with correct key
    let is_valid = signer.verify_ed25519(keypair.public_key(), message, &signature)?;
    assert!(is_valid);
    
    // Test verification with wrong message
    let is_valid = signer.verify_ed25519(keypair.public_key(), b"Wrong message", &signature)?;
    assert!(!is_valid);
    
    // Test verification with wrong key
    let other_key_id = crypto.generate_keypair(KeyType::Ed25519)?;
    let other_keypair = crypto.get_keypair(&other_key_id).unwrap();
    let is_valid = signer.verify_ed25519(other_keypair.public_key(), message, &signature)?;
    assert!(!is_valid);
    
    Ok(())
}

#[test]
fn test_ecdh_operations() -> Result<()> {
    let mut crypto = MockCryptoProvider::new();
    let signer = MockSignatureProvider::new();
    
    // Generate X25519 keypairs for Alice and Bob
    let alice_key_id = crypto.generate_keypair(KeyType::X25519)?;
    let bob_key_id = crypto.generate_keypair(KeyType::X25519)?;
    
    let alice_keypair = crypto.get_keypair(&alice_key_id).unwrap();
    let bob_keypair = crypto.get_keypair(&bob_key_id).unwrap();
    
    // Test ECDH from Alice's perspective
    let alice_shared = signer.ecdh_x25519(
        alice_keypair.private_key(),
        bob_keypair.public_key()
    )?;
    assert_eq!(alice_shared.len(), 32);
    
    // Test ECDH from Bob's perspective
    let bob_shared = signer.ecdh_x25519(
        bob_keypair.private_key(),
        alice_keypair.public_key()
    )?;
    assert_eq!(bob_shared.len(), 32);
    
    // Shared secrets should be equal
    assert_eq!(alice_shared, bob_shared);
    
    // Test with different keypair produces different shared secret
    let charlie_key_id = crypto.generate_keypair(KeyType::X25519)?;
    let charlie_keypair = crypto.get_keypair(&charlie_key_id).unwrap();
    
    let charlie_shared = signer.ecdh_x25519(
        alice_keypair.private_key(),
        charlie_keypair.public_key()
    )?;
    assert_ne!(alice_shared, charlie_shared);
    
    Ok(())
}

#[test]
fn test_random_generation() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    
    // Test different sizes
    let bytes_16 = crypto.generate_random_bytes(16);
    assert_eq!(bytes_16.len(), 16);
    
    let bytes_32 = crypto.generate_random_bytes(32);
    assert_eq!(bytes_32.len(), 32);
    
    let bytes_64 = crypto.generate_random_bytes(64);
    assert_eq!(bytes_64.len(), 64);
    
    // Test randomness (should be different)
    let random1 = crypto.generate_random_bytes(32);
    let random2 = crypto.generate_random_bytes(32);
    assert_ne!(random1, random2);
    
    // Test zero-length
    let empty = crypto.generate_random_bytes(0);
    assert_eq!(empty.len(), 0);
    
    Ok(())
}

#[test]
fn test_constant_time_compare() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    
    // Test equal arrays
    let data1 = b"test_data_for_comparison";
    let data2 = b"test_data_for_comparison";
    assert!(crypto.constant_time_compare(data1, data2));
    
    // Test different arrays of same length
    let data3 = b"different_data_same_len";
    assert!(!crypto.constant_time_compare(data1, data3));
    
    // Test different lengths
    let data4 = b"short";
    assert!(!crypto.constant_time_compare(data1, data4));
    
    // Test empty arrays
    let empty1 = b"";
    let empty2 = b"";
    assert!(crypto.constant_time_compare(empty1, empty2));
    
    Ok(())
}

#[test]
fn test_secure_zero() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    
    // Test zeroing sensitive data
    let mut sensitive_data = vec![0x42u8; 32];
    assert_eq!(sensitive_data[0], 0x42);
    assert_eq!(sensitive_data[31], 0x42);
    
    crypto.secure_zero(&mut sensitive_data);
    assert_eq!(sensitive_data[0], 0x00);
    assert_eq!(sensitive_data[31], 0x00);
    
    // Verify all bytes are zero
    for byte in &sensitive_data {
        assert_eq!(*byte, 0x00);
    }
    
    Ok(())
}

#[test]
fn test_algorithm_support() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    
    // Test supported algorithms
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::AES256GCM));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::ChaCha20Poly1305));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::Ed25519));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::X25519));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::HMACSHA256));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::SHA256));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::SHA512));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::HKDF));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::PBKDF2));
    assert!(crypto.supports_algorithm(&CryptoAlgorithm::Scrypt));
    
    Ok(())
}

#[test]
fn test_key_validation() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    
    // Test invalid key sizes for AES-256-GCM
    let short_key = vec![0u8; 16]; // Too short
    let long_key = vec![0u8; 64];  // Too long
    let valid_key = vec![0u8; 32]; // Correct size
    let nonce = vec![0u8; 12];
    let plaintext = b"test";
    let aad = b"";
    
    let result = crypto.encrypt_aes256gcm(&short_key, &nonce, plaintext, aad);
    assert!(result.is_err());
    
    let result = crypto.encrypt_aes256gcm(&long_key, &nonce, plaintext, aad);
    assert!(result.is_err());
    
    let result = crypto.encrypt_aes256gcm(&valid_key, &nonce, plaintext, aad);
    assert!(result.is_ok());
    
    // Test invalid nonce sizes
    let short_nonce = vec![0u8; 8];  // Too short
    let long_nonce = vec![0u8; 16];  // Too long
    
    let result = crypto.encrypt_aes256gcm(&valid_key, &short_nonce, plaintext, aad);
    assert!(result.is_err());
    
    let result = crypto.encrypt_aes256gcm(&valid_key, &long_nonce, plaintext, aad);
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_cryptographic_edge_cases() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    
    // Test empty data hashing
    let empty_hash = crypto.hash_sha256(b"");
    assert_eq!(empty_hash.len(), 32);
    
    // Test large data hashing
    let large_data = vec![0x42u8; 1_000_000];
    let large_hash = crypto.hash_sha256(&large_data);
    assert_eq!(large_hash.len(), 32);
    
    // Test HMAC with empty message
    let key = b"test_key_for_empty_message_hmac_test";
    let empty_hmac = crypto.hmac_sha256(key, b"")?;
    assert_eq!(empty_hmac.len(), 32);
    
    // Test HKDF with zero-length output
    let prk = crypto.hkdf_extract(b"salt", b"ikm");
    let zero_okm = crypto.hkdf_expand(&prk, b"info", 0)?;
    assert_eq!(zero_okm.len(), 0);
    
    // Test PBKDF2 with minimum iterations
    let min_key = crypto.pbkdf2_derive(b"password", b"salt", 1, 32);
    assert_eq!(min_key.len(), 32);
    
    Ok(())
}

#[test]
fn test_concurrent_crypto_operations() -> Result<()> {
    use std::sync::Arc;
    use std::thread;
    
    let crypto = Arc::new(MockCryptoProvider::new());
    let mut handles = Vec::new();
    
    // Spawn multiple threads performing crypto operations
    for i in 0..10 {
        let crypto_clone = crypto.clone();
        let handle = thread::spawn(move || {
            let data = format!("test_data_{}", i);
            let hash = crypto_clone.hash_sha256(data.as_bytes());
            assert_eq!(hash.len(), 32);
            
            let key = crypto_clone.generate_random_bytes(32);
            let hmac = crypto_clone.hmac_sha256(&key, data.as_bytes()).unwrap();
            assert_eq!(hmac.len(), 32);
            
            hash
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.join().unwrap();
        results.push(result);
    }
    
    // Verify all operations completed successfully
    assert_eq!(results.len(), 10);
    
    // All hashes should be different since input data was different
    for i in 0..results.len() {
        for j in i+1..results.len() {
            assert_ne!(results[i], results[j]);
        }
    }
    
    Ok(())
}

#[test]
fn test_performance_benchmarks() -> Result<()> {
    let crypto = MockCryptoProvider::new();
    let iterations = 1000;
    
    // Benchmark SHA-256 hashing
    let start = std::time::Instant::now();
    for i in 0..iterations {
        let data = format!("benchmark_data_{}", i);
        let _hash = crypto.hash_sha256(data.as_bytes());
    }
    let hash_duration = start.elapsed();
    println!("SHA-256 hashing: {} ops in {:?}", iterations, hash_duration);
    
    // Benchmark HMAC operations
    let key = b"benchmark_key_for_hmac_testing_123";
    let start = std::time::Instant::now();
    for i in 0..iterations {
        let data = format!("benchmark_data_{}", i);
        let _hmac = crypto.hmac_sha256(key, data.as_bytes()).unwrap();
    }
    let hmac_duration = start.elapsed();
    println!("HMAC-SHA256: {} ops in {:?}", iterations, hmac_duration);
    
    // Benchmark random generation
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _random = crypto.generate_random_bytes(32);
    }
    let random_duration = start.elapsed();
    println!("Random generation: {} ops in {:?}", iterations, random_duration);
    
    Ok(())
}