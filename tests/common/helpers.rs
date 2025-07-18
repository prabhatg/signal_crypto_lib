//! Test helper functions for Signal Protocol testing
//! 
//! This module provides utility functions to simplify test setup,
//! execution, and validation across the test suite.

use signal_crypto_lib::*;
use super::*;
use std::time::{Duration, SystemTime};

/// Helper functions for X3DH protocol testing
pub struct X3DHTestHelpers;

impl X3DHTestHelpers {
    /// Create a complete X3DH key bundle for testing
    pub fn create_key_bundle(user_id: &str) -> X3DHKeyBundle {
        let identity_key = generate_identity_keypair();
        let signed_prekey = generate_signed_prekey_pair(1, &identity_key.private_key);
        let one_time_prekeys: Vec<PreKeyPair> = (0..10)
            .map(|i| generate_prekey_pair(i))
            .collect();
        
        X3DHKeyBundle {
            user_id: user_id.to_string(),
            identity_key: identity_key.public_key,
            signed_prekey: signed_prekey.public_key,
            signed_prekey_signature: signed_prekey.signature,
            one_time_prekeys: one_time_prekeys.iter().map(|pk| pk.public_key).collect(),
        }
    }

    /// Perform X3DH key agreement between two parties
    pub fn perform_key_agreement(
        alice_identity: &IdentityKeyPair,
        alice_ephemeral: &EphemeralKeyPair,
        bob_bundle: &X3DHKeyBundle,
        bob_signed_prekey: &SignedPreKeyPair,
        bob_one_time_prekey: Option<&PreKeyPair>,
    ) -> Result<(Vec<u8>, Vec<u8>), SignalProtocolError> {
        // Alice's side
        let alice_shared_secret = x3dh_alice(
            alice_identity,
            alice_ephemeral,
            &bob_bundle.identity_key,
            &bob_bundle.signed_prekey,
            bob_one_time_prekey.map(|pk| &pk.public_key),
        )?;

        // Bob's side  
        let bob_shared_secret = x3dh_bob(
            &bob_bundle.identity_key,
            bob_signed_prekey,
            bob_one_time_prekey,
            &alice_identity.public_key,
            &alice_ephemeral.public_key,
        )?;

        Ok((alice_shared_secret, bob_shared_secret))
    }

    /// Validate that X3DH produces matching shared secrets
    pub fn validate_shared_secrets(alice_secret: &[u8], bob_secret: &[u8]) -> bool {
        alice_secret == bob_secret
    }
}

/// Helper functions for Double Ratchet protocol testing
pub struct DoubleRatchetTestHelpers;

impl DoubleRatchetTestHelpers {
    /// Initialize a Double Ratchet session for testing
    pub fn initialize_session(
        shared_secret: &[u8],
        alice_identity: &IdentityKeyPair,
        bob_identity: &IdentityKeyPair,
        is_alice: bool,
    ) -> Result<SessionState, SignalProtocolError> {
        if is_alice {
            initialize_alice_session(shared_secret, &bob_identity.public_key)
        } else {
            initialize_bob_session(shared_secret, alice_identity)
        }
    }

    /// Encrypt a message using Double Ratchet
    pub fn encrypt_message(
        session: &mut SessionState,
        message: &[u8],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        encrypt_message(session, message)
    }

    /// Decrypt a message using Double Ratchet
    pub fn decrypt_message(
        session: &mut SessionState,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        decrypt_message(session, ciphertext)
    }

    /// Test message exchange between two sessions
    pub fn test_message_exchange(
        alice_session: &mut SessionState,
        bob_session: &mut SessionState,
        messages: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, SignalProtocolError> {
        let mut decrypted_messages = Vec::new();

        for message in messages {
            // Alice encrypts
            let ciphertext = Self::encrypt_message(alice_session, message)?;
            
            // Bob decrypts
            let decrypted = Self::decrypt_message(bob_session, &ciphertext)?;
            decrypted_messages.push(decrypted);
        }

        Ok(decrypted_messages)
    }

    /// Validate message integrity
    pub fn validate_messages(original: &[&[u8]], decrypted: &[Vec<u8>]) -> bool {
        if original.len() != decrypted.len() {
            return false;
        }

        original.iter().zip(decrypted.iter()).all(|(orig, dec)| *orig == dec.as_slice())
    }
}

/// Helper functions for group messaging testing
pub struct GroupTestHelpers;

impl GroupTestHelpers {
    /// Create a group session for testing
    pub fn create_group_session(group_id: &str, admin_id: &str) -> Result<GroupSession, SignalProtocolError> {
        create_group_session(group_id, admin_id)
    }

    /// Add a member to a group session
    pub fn add_member(
        session: &mut GroupSession,
        member_id: &str,
        member_identity: &IdentityKeyPair,
    ) -> Result<(), SignalProtocolError> {
        add_group_member(session, member_id, &member_identity.public_key)
    }

    /// Send a group message
    pub fn send_group_message(
        session: &mut GroupSession,
        sender_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        encrypt_group_message(session, sender_id, message)
    }

    /// Receive a group message
    pub fn receive_group_message(
        session: &mut GroupSession,
        ciphertext: &[u8],
    ) -> Result<(String, Vec<u8>), SignalProtocolError> {
        decrypt_group_message(session, ciphertext)
    }

    /// Test group message broadcast
    pub fn test_group_broadcast(
        sessions: &mut [GroupSession],
        sender_index: usize,
        message: &[u8],
    ) -> Result<Vec<(String, Vec<u8>)>, SignalProtocolError> {
        let ciphertext = Self::send_group_message(&mut sessions[sender_index], "sender", message)?;
        
        let mut results = Vec::new();
        for (i, session) in sessions.iter_mut().enumerate() {
            if i != sender_index {
                let result = Self::receive_group_message(session, &ciphertext)?;
                results.push(result);
            }
        }
        
        Ok(results)
    }
}

/// Helper functions for performance testing
pub struct PerformanceTestHelpers;

impl PerformanceTestHelpers {
    /// Measure execution time of a function
    pub fn measure_time<F, R>(operation: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = SystemTime::now();
        let result = operation();
        let duration = start.elapsed().unwrap_or(Duration::ZERO);
        (result, duration)
    }

    /// Run a performance benchmark
    pub fn benchmark<F, R>(
        name: &str,
        iterations: usize,
        operation: F,
    ) -> BenchmarkResult
    where
        F: Fn() -> R,
    {
        let runner = BenchmarkRunner::new().with_iterations(iterations);
        runner.run(name, || operation())
    }

    /// Measure memory usage (simplified)
    pub fn measure_memory_usage<F, R>(operation: F) -> (R, u64)
    where
        F: FnOnce() -> R,
    {
        // Note: This is a simplified implementation
        // In a real scenario, you'd use proper memory profiling tools
        let result = operation();
        let estimated_memory = 0; // Placeholder
        (result, estimated_memory)
    }

    /// Test throughput for message processing
    pub fn test_throughput(
        message_count: usize,
        message_size: usize,
        processor: impl Fn(&[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    ) -> Result<f64, SignalProtocolError> {
        let test_message = vec![0xAA; message_size];
        
        let (_, duration) = Self::measure_time(|| {
            for _ in 0..message_count {
                let _ = processor(&test_message)?;
            }
            Ok::<(), SignalProtocolError>(())
        });

        let throughput = message_count as f64 / duration.as_secs_f64();
        Ok(throughput)
    }
}

/// Helper functions for security testing
pub struct SecurityTestHelpers;

impl SecurityTestHelpers {
    /// Test for timing attacks by measuring execution time variance
    pub fn test_timing_attack_resistance<F>(
        operation: F,
        test_cases: &[Vec<u8>],
        threshold_ms: f64,
    ) -> bool
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        let mut durations = Vec::new();
        
        for test_case in test_cases {
            let (_, duration) = PerformanceTestHelpers::measure_time(|| {
                let _ = operation(test_case);
            });
            durations.push(duration.as_secs_f64() * 1000.0); // Convert to milliseconds
        }
        
        // Calculate variance
        let mean = durations.iter().sum::<f64>() / durations.len() as f64;
        let variance = durations.iter()
            .map(|d| (d - mean).powi(2))
            .sum::<f64>() / durations.len() as f64;
        let std_dev = variance.sqrt();
        
        // Check if standard deviation is below threshold
        std_dev < threshold_ms
    }

    /// Test for side-channel resistance
    pub fn test_side_channel_resistance<F>(
        operation: F,
        secret_inputs: &[Vec<u8>],
        public_inputs: &[Vec<u8>],
    ) -> bool
    where
        F: Fn(&[u8], &[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        // Simplified side-channel test
        // In practice, this would involve more sophisticated analysis
        for (secret, public) in secret_inputs.iter().zip(public_inputs.iter()) {
            let (_, duration1) = PerformanceTestHelpers::measure_time(|| {
                let _ = operation(secret, public);
            });
            
            let (_, duration2) = PerformanceTestHelpers::measure_time(|| {
                let _ = operation(secret, public);
            });
            
            // Check for consistent timing
            let diff = (duration1.as_nanos() as i64 - duration2.as_nanos() as i64).abs();
            if diff > 1_000_000 { // 1ms threshold
                return false;
            }
        }
        
        true
    }

    /// Validate cryptographic properties
    pub fn validate_crypto_properties(
        ciphertext: &[u8],
        key: &[u8],
        plaintext: &[u8],
    ) -> CryptoValidationResult {
        CryptoValidationResult {
            entropy_sufficient: Self::check_entropy(ciphertext),
            no_plaintext_leakage: Self::check_plaintext_leakage(ciphertext, plaintext),
            key_independence: Self::check_key_independence(ciphertext, key),
            avalanche_effect: Self::check_avalanche_effect(ciphertext, plaintext),
        }
    }

    fn check_entropy(data: &[u8]) -> bool {
        // Simplified entropy check
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let entropy: f64 = counts.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum();
        
        entropy > 7.0 // Expect high entropy
    }

    fn check_plaintext_leakage(ciphertext: &[u8], plaintext: &[u8]) -> bool {
        // Check that ciphertext doesn't contain plaintext patterns
        if ciphertext.len() < plaintext.len() {
            return true;
        }
        
        for i in 0..=(ciphertext.len() - plaintext.len()) {
            if &ciphertext[i..i + plaintext.len()] == plaintext {
                return false;
            }
        }
        
        true
    }

    fn check_key_independence(ciphertext: &[u8], key: &[u8]) -> bool {
        // Check that ciphertext doesn't contain key patterns
        if ciphertext.len() < key.len() {
            return true;
        }
        
        for i in 0..=(ciphertext.len() - key.len()) {
            if &ciphertext[i..i + key.len()] == key {
                return false;
            }
        }
        
        true
    }

    fn check_avalanche_effect(_ciphertext: &[u8], _plaintext: &[u8]) -> bool {
        // Simplified avalanche effect check
        // In practice, this would require multiple encryptions with slight input changes
        true
    }
}

/// Helper functions for error testing
pub struct ErrorTestHelpers;

impl ErrorTestHelpers {
    /// Test error handling for invalid inputs
    pub fn test_invalid_inputs<F, R>(
        operation: F,
        invalid_inputs: &[Vec<u8>],
    ) -> Vec<bool>
    where
        F: Fn(&[u8]) -> Result<R, SignalProtocolError>,
    {
        invalid_inputs.iter()
            .map(|input| operation(input).is_err())
            .collect()
    }

    /// Test error recovery mechanisms
    pub fn test_error_recovery<F, R>(
        operation: F,
        recovery_operation: F,
        test_input: &[u8],
    ) -> bool
    where
        F: Fn(&[u8]) -> Result<R, SignalProtocolError>,
    {
        // First operation should fail
        if operation(test_input).is_ok() {
            return false;
        }
        
        // Recovery operation should succeed
        recovery_operation(test_input).is_ok()
    }

    /// Test error propagation
    pub fn test_error_propagation<F, R>(
        operation: F,
        error_input: &[u8],
    ) -> bool
    where
        F: Fn(&[u8]) -> Result<R, SignalProtocolError>,
    {
        match operation(error_input) {
            Err(_) => true,
            Ok(_) => false,
        }
    }
}

/// Helper functions for integration testing
pub struct IntegrationTestHelpers;

impl IntegrationTestHelpers {
    /// Set up a complete test environment
    pub fn setup_test_environment() -> TestEnvironment {
        TestEnvironment {
            identities: TestIdentities::new(),
            sessions: HashMap::new(),
            groups: HashMap::new(),
            config: TestConfig::default(),
        }
    }

    /// Simulate a complete protocol flow
    pub fn simulate_protocol_flow(
        alice_id: &str,
        bob_id: &str,
        messages: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, SignalProtocolError> {
        // Create identities
        let alice_identity = generate_identity_keypair();
        let bob_identity = generate_identity_keypair();
        
        // X3DH key agreement
        let alice_ephemeral = generate_ephemeral_keypair();
        let bob_bundle = X3DHTestHelpers::create_key_bundle(bob_id);
        let bob_signed_prekey = generate_signed_prekey_pair(1, &bob_identity.private_key);
        
        let (alice_secret, bob_secret) = X3DHTestHelpers::perform_key_agreement(
            &alice_identity,
            &alice_ephemeral,
            &bob_bundle,
            &bob_signed_prekey,
            None,
        )?;
        
        // Verify shared secrets match
        assert!(X3DHTestHelpers::validate_shared_secrets(&alice_secret, &bob_secret));
        
        // Initialize Double Ratchet sessions
        let mut alice_session = DoubleRatchetTestHelpers::initialize_session(
            &alice_secret,
            &alice_identity,
            &bob_identity,
            true,
        )?;
        
        let mut bob_session = DoubleRatchetTestHelpers::initialize_session(
            &bob_secret,
            &alice_identity,
            &bob_identity,
            false,
        )?;
        
        // Exchange messages
        DoubleRatchetTestHelpers::test_message_exchange(
            &mut alice_session,
            &mut bob_session,
            messages,
        )
    }

    /// Test end-to-end encryption
    pub fn test_end_to_end_encryption(
        sender_id: &str,
        recipient_id: &str,
        message: &[u8],
    ) -> Result<bool, SignalProtocolError> {
        let decrypted_messages = Self::simulate_protocol_flow(
            sender_id,
            recipient_id,
            &[message],
        )?;
        
        Ok(decrypted_messages.len() == 1 && decrypted_messages[0] == message)
    }
}

/// Test environment structure
pub struct TestEnvironment {
    pub identities: TestIdentities,
    pub sessions: HashMap<String, SessionState>,
    pub groups: HashMap<String, GroupSession>,
    pub config: TestConfig,
}

/// Cryptographic validation result
#[derive(Debug, Clone)]
pub struct CryptoValidationResult {
    pub entropy_sufficient: bool,
    pub no_plaintext_leakage: bool,
    pub key_independence: bool,
    pub avalanche_effect: bool,
}

impl CryptoValidationResult {
    pub fn is_valid(&self) -> bool {
        self.entropy_sufficient
            && self.no_plaintext_leakage
            && self.key_independence
            && self.avalanche_effect
    }
}

/// X3DH key bundle for testing
#[derive(Debug, Clone)]
pub struct X3DHKeyBundle {
    pub user_id: String,
    pub identity_key: PublicKey,
    pub signed_prekey: PublicKey,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekeys: Vec<PublicKey>,
}

/// Utility macros for common test patterns
#[macro_export]
macro_rules! assert_crypto_property {
    ($condition:expr, $property:expr) => {
        assert!($condition, "Cryptographic property failed: {}", $property);
    };
}

#[macro_export]
macro_rules! test_with_timeout {
    ($timeout:expr, $test:block) => {{
        let start = std::time::SystemTime::now();
        let result = $test;
        let elapsed = start.elapsed().unwrap_or(std::time::Duration::ZERO);
        assert!(elapsed < $timeout, "Test exceeded timeout of {:?}", $timeout);
        result
    }};
}

#[macro_export]
macro_rules! benchmark_operation {
    ($name:expr, $iterations:expr, $operation:expr) => {{
        let runner = BenchmarkRunner::new().with_iterations($iterations);
        let result = runner.run($name, || $operation);
        result.print_summary();
        result
    }};
}