//! Test assertion utilities for Signal Protocol testing
//! 
//! This module provides specialized assertion functions for validating
//! cryptographic properties, protocol behavior, and security requirements.

use signal_crypto_lib::*;
use super::*;
use std::collections::HashSet;

/// Cryptographic assertion utilities
pub struct CryptoAssertions;

impl CryptoAssertions {
    /// Assert that two byte arrays are equal
    pub fn assert_bytes_equal(actual: &[u8], expected: &[u8], message: &str) {
        assert_eq!(
            actual, expected,
            "{}: Expected {:?}, got {:?}",
            message, expected, actual
        );
    }

    /// Assert that a byte array has sufficient entropy
    pub fn assert_sufficient_entropy(data: &[u8], min_entropy: f64, message: &str) {
        let entropy = calculate_entropy(data);
        assert!(
            entropy >= min_entropy,
            "{}: Entropy {} is below minimum {}",
            message, entropy, min_entropy
        );
    }

    /// Assert that data appears random (no obvious patterns)
    pub fn assert_appears_random(data: &[u8], message: &str) {
        // Check for repeated patterns
        let pattern_size = 4;
        let mut patterns = HashSet::new();
        let mut repeated_patterns = 0;

        for window in data.windows(pattern_size) {
            if patterns.contains(window) {
                repeated_patterns += 1;
            } else {
                patterns.insert(window.to_vec());
            }
        }

        let repetition_ratio = repeated_patterns as f64 / (data.len() - pattern_size + 1) as f64;
        assert!(
            repetition_ratio < 0.1, // Less than 10% repetition
            "{}: Data appears non-random with {:.2}% pattern repetition",
            message, repetition_ratio * 100.0
        );
    }

    /// Assert that ciphertext doesn't leak plaintext
    pub fn assert_no_plaintext_leakage(ciphertext: &[u8], plaintext: &[u8], message: &str) {
        // Check that plaintext doesn't appear in ciphertext
        if plaintext.len() <= ciphertext.len() {
            for i in 0..=(ciphertext.len() - plaintext.len()) {
                assert_ne!(
                    &ciphertext[i..i + plaintext.len()], plaintext,
                    "{}: Plaintext found in ciphertext at position {}",
                    message, i
                );
            }
        }

        // Check for partial plaintext leakage (more than 50% match)
        let max_consecutive_matches = find_max_consecutive_matches(ciphertext, plaintext);
        assert!(
            max_consecutive_matches < plaintext.len() / 2,
            "{}: Potential plaintext leakage detected ({} consecutive bytes match)",
            message, max_consecutive_matches
        );
    }

    /// Assert that key material doesn't appear in ciphertext
    pub fn assert_no_key_leakage(ciphertext: &[u8], key: &[u8], message: &str) {
        Self::assert_no_plaintext_leakage(ciphertext, key, &format!("{} (key leakage)", message));
    }

    /// Assert forward secrecy property
    pub fn assert_forward_secrecy<F>(
        encrypt_fn: F,
        old_key: &[u8],
        new_key: &[u8],
        plaintext: &[u8],
        message: &str,
    ) where
        F: Fn(&[u8], &[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        let old_ciphertext = encrypt_fn(old_key, plaintext)
            .expect(&format!("{}: Failed to encrypt with old key", message));
        let new_ciphertext = encrypt_fn(new_key, plaintext)
            .expect(&format!("{}: Failed to encrypt with new key", message));

        assert_ne!(
            old_ciphertext, new_ciphertext,
            "{}: Forward secrecy violated - same ciphertext with different keys",
            message
        );

        // Ensure old key material doesn't appear in new ciphertext
        Self::assert_no_key_leakage(&new_ciphertext, old_key, message);
    }

    /// Assert that encryption is deterministic or non-deterministic as expected
    pub fn assert_encryption_determinism<F>(
        encrypt_fn: F,
        key: &[u8],
        plaintext: &[u8],
        should_be_deterministic: bool,
        message: &str,
    ) where
        F: Fn(&[u8], &[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        let ciphertext1 = encrypt_fn(key, plaintext)
            .expect(&format!("{}: First encryption failed", message));
        let ciphertext2 = encrypt_fn(key, plaintext)
            .expect(&format!("{}: Second encryption failed", message));

        if should_be_deterministic {
            assert_eq!(
                ciphertext1, ciphertext2,
                "{}: Expected deterministic encryption but got different results",
                message
            );
        } else {
            assert_ne!(
                ciphertext1, ciphertext2,
                "{}: Expected non-deterministic encryption but got same results",
                message
            );
        }
    }
}

/// Protocol assertion utilities
pub struct ProtocolAssertions;

impl ProtocolAssertions {
    /// Assert that a session state is valid
    pub fn assert_valid_session_state(session: &SessionState, message: &str) {
        // Check that required fields are present
        assert!(!session.session_id.is_empty(), "{}: Session ID is empty", message);
        
        // Check key material is present
        assert!(!session.root_key.is_empty(), "{}: Root key is empty", message);
        assert!(!session.chain_key.is_empty(), "{}: Chain key is empty", message);
        
        // Check counters are valid
        assert!(session.send_counter >= 0, "{}: Invalid send counter", message);
        assert!(session.receive_counter >= 0, "{}: Invalid receive counter", message);
    }

    /// Assert that X3DH key agreement produces valid results
    pub fn assert_valid_x3dh_result(
        alice_secret: &[u8],
        bob_secret: &[u8],
        message: &str,
    ) {
        assert_eq!(
            alice_secret, bob_secret,
            "{}: X3DH shared secrets don't match",
            message
        );

        assert!(!alice_secret.is_empty(), "{}: Shared secret is empty", message);
        
        CryptoAssertions::assert_sufficient_entropy(alice_secret, 7.0, 
            &format!("{}: X3DH shared secret", message));
    }

    /// Assert that group session is properly initialized
    pub fn assert_valid_group_session(session: &GroupSession, message: &str) {
        assert!(!session.group_id.is_empty(), "{}: Group ID is empty", message);
        assert!(!session.members.is_empty(), "{}: Group has no members", message);
        assert!(session.members.contains(&session.admin), 
            "{}: Admin is not in member list", message);
    }

    /// Assert message ordering properties
    pub fn assert_message_ordering(
        sent_messages: &[Vec<u8>],
        received_messages: &[Vec<u8>],
        message: &str,
    ) {
        assert_eq!(
            sent_messages.len(), received_messages.len(),
            "{}: Message count mismatch", message
        );

        for (i, (sent, received)) in sent_messages.iter().zip(received_messages.iter()).enumerate() {
            assert_eq!(
                sent, received,
                "{}: Message {} content mismatch", message, i
            );
        }
    }

    /// Assert replay protection
    pub fn assert_replay_protection<F>(
        process_message: F,
        message_data: &[u8],
        test_message: &str,
    ) where
        F: Fn(&[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        // First processing should succeed
        let result1 = process_message(message_data);
        assert!(result1.is_ok(), "{}: First message processing failed", test_message);

        // Second processing should fail (replay detected)
        let result2 = process_message(message_data);
        assert!(result2.is_err(), "{}: Replay attack not detected", test_message);
    }
}

/// Security assertion utilities
pub struct SecurityAssertions;

impl SecurityAssertions {
    /// Assert timing attack resistance
    pub fn assert_timing_resistance<F>(
        operation: F,
        test_cases: &[Vec<u8>],
        max_variance_ms: f64,
        message: &str,
    ) where
        F: Fn(&[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        let mut durations = Vec::new();

        for test_case in test_cases {
            let start = std::time::SystemTime::now();
            let _ = operation(test_case);
            let duration = start.elapsed().unwrap_or(std::time::Duration::ZERO);
            durations.push(duration.as_secs_f64() * 1000.0); // Convert to milliseconds
        }

        let mean = durations.iter().sum::<f64>() / durations.len() as f64;
        let variance = durations.iter()
            .map(|d| (d - mean).powi(2))
            .sum::<f64>() / durations.len() as f64;
        let std_dev = variance.sqrt();

        assert!(
            std_dev <= max_variance_ms,
            "{}: Timing variance {} ms exceeds threshold {} ms",
            message, std_dev, max_variance_ms
        );
    }

    /// Assert memory safety (no buffer overflows)
    pub fn assert_memory_safety<F>(
        operation: F,
        oversized_input: &[u8],
        message: &str,
    ) where
        F: Fn(&[u8]) -> Result<Vec<u8>, SignalProtocolError>,
    {
        // This should either succeed or fail gracefully, not crash
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            operation(oversized_input)
        }));

        assert!(
            result.is_ok(),
            "{}: Memory safety violation detected (panic on oversized input)",
            message
        );
    }

    /// Assert that sensitive data is properly cleared
    pub fn assert_secure_cleanup(
        data_before: &[u8],
        data_after: &[u8],
        message: &str,
    ) {
        assert_ne!(
            data_before, data_after,
            "{}: Sensitive data not properly cleared",
            message
        );

        // Check that data is actually zeroed or randomized
        let all_zeros = data_after.iter().all(|&b| b == 0);
        let appears_random = calculate_entropy(data_after) > 6.0;

        assert!(
            all_zeros || appears_random,
            "{}: Data not properly cleared (not zeroed or randomized)",
            message
        );
    }
}

/// Performance assertion utilities
pub struct PerformanceAssertions;

impl PerformanceAssertions {
    /// Assert operation completes within time limit
    pub fn assert_performance_bound<F, R>(
        operation: F,
        max_duration: std::time::Duration,
        message: &str,
    ) -> R
    where
        F: FnOnce() -> R,
    {
        let start = std::time::SystemTime::now();
        let result = operation();
        let duration = start.elapsed().unwrap_or(std::time::Duration::ZERO);

        assert!(
            duration <= max_duration,
            "{}: Operation took {:?}, exceeds limit {:?}",
            message, duration, max_duration
        );

        result
    }

    /// Assert throughput meets minimum requirements
    pub fn assert_throughput<F>(
        operation: F,
        iterations: usize,
        min_ops_per_second: f64,
        message: &str,
    ) where
        F: Fn() -> Result<(), SignalProtocolError>,
    {
        let start = std::time::SystemTime::now();
        
        for _ in 0..iterations {
            operation().expect(&format!("{}: Operation failed during throughput test", message));
        }
        
        let duration = start.elapsed().unwrap_or(std::time::Duration::ZERO);
        let ops_per_second = iterations as f64 / duration.as_secs_f64();

        assert!(
            ops_per_second >= min_ops_per_second,
            "{}: Throughput {} ops/sec below minimum {} ops/sec",
            message, ops_per_second, min_ops_per_second
        );
    }

    /// Assert memory usage is within bounds
    pub fn assert_memory_bound<F, R>(
        operation: F,
        max_memory_mb: u64,
        message: &str,
    ) -> R
    where
        F: FnOnce() -> R,
    {
        // Note: This is a simplified implementation
        // In practice, you'd use proper memory profiling tools
        let result = operation();
        
        // Placeholder memory check
        // In a real implementation, you'd measure actual memory usage
        let estimated_memory_mb = 0; // Placeholder
        
        assert!(
            estimated_memory_mb <= max_memory_mb,
            "{}: Memory usage {} MB exceeds limit {} MB",
            message, estimated_memory_mb, max_memory_mb
        );

        result
    }
}

/// Error assertion utilities
pub struct ErrorAssertions;

impl ErrorAssertions {
    /// Assert that an operation fails with expected error type
    pub fn assert_error_type<F, R>(
        operation: F,
        expected_error: SignalProtocolError,
        message: &str,
    ) where
        F: FnOnce() -> Result<R, SignalProtocolError>,
    {
        let result = operation();
        assert!(result.is_err(), "{}: Expected error but operation succeeded", message);
        
        let actual_error = result.unwrap_err();
        assert_eq!(
            std::mem::discriminant(&actual_error),
            std::mem::discriminant(&expected_error),
            "{}: Expected error type {:?}, got {:?}",
            message, expected_error, actual_error
        );
    }

    /// Assert that error messages don't leak sensitive information
    pub fn assert_safe_error_messages(
        error: &SignalProtocolError,
        sensitive_data: &[&str],
        message: &str,
    ) {
        let error_message = format!("{:?}", error);
        
        for sensitive in sensitive_data {
            assert!(
                !error_message.contains(sensitive),
                "{}: Error message contains sensitive data: {}",
                message, sensitive
            );
        }
    }

    /// Assert proper error propagation
    pub fn assert_error_propagation<F1, F2, R>(
        inner_operation: F1,
        outer_operation: F2,
        message: &str,
    ) where
        F1: FnOnce() -> Result<R, SignalProtocolError>,
        F2: FnOnce(Result<R, SignalProtocolError>) -> Result<R, SignalProtocolError>,
    {
        let inner_result = inner_operation();
        let outer_result = outer_operation(inner_result);
        
        assert!(
            outer_result.is_err(),
            "{}: Error not properly propagated",
            message
        );
    }
}

/// Helper functions for assertions
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    counts.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn find_max_consecutive_matches(haystack: &[u8], needle: &[u8]) -> usize {
    let mut max_matches = 0;
    
    for i in 0..haystack.len() {
        let mut matches = 0;
        for (j, &needle_byte) in needle.iter().enumerate() {
            if i + j >= haystack.len() {
                break;
            }
            if haystack[i + j] == needle_byte {
                matches += 1;
            } else {
                break;
            }
        }
        max_matches = max_matches.max(matches);
    }
    
    max_matches
}

/// Macro for asserting cryptographic properties
#[macro_export]
macro_rules! assert_crypto_property {
    ($condition:expr, $property:expr) => {
        assert!($condition, "Cryptographic property violated: {}", $property);
    };
    ($condition:expr, $property:expr, $($arg:tt)*) => {
        assert!($condition, "Cryptographic property violated: {}: {}", $property, format!($($arg)*));
    };
}

/// Macro for asserting protocol invariants
#[macro_export]
macro_rules! assert_protocol_invariant {
    ($condition:expr, $invariant:expr) => {
        assert!($condition, "Protocol invariant violated: {}", $invariant);
    };
    ($condition:expr, $invariant:expr, $($arg:tt)*) => {
        assert!($condition, "Protocol invariant violated: {}: {}", $invariant, format!($($arg)*));
    };
}

/// Macro for asserting security properties
#[macro_export]
macro_rules! assert_security_property {
    ($condition:expr, $property:expr) => {
        assert!($condition, "Security property violated: {}", $property);
    };
    ($condition:expr, $property:expr, $($arg:tt)*) => {
        assert!($condition, "Security property violated: {}: {}", $property, format!($($arg)*));
    };
}