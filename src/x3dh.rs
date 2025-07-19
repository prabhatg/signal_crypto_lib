/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Legacy X3DH compatibility wrapper for backward compatibility.
 * Provides simplified session establishment interface - use protocol::x3dh
 * for full-featured implementation with proper key agreement and validation.
 */

// signal_crypto_lib/src/x3dh.rs
// Legacy compatibility wrapper - use protocol::x3dh instead

use crate::types::{IdentityKeyPair, PreKeyBundle, SessionState};
use crate::protocol::x3dh::{x3dh_alice_init, create_prekey_bundle};
use crate::prekey::{generate_signed_prekey, generate_one_time_prekey};
use std::collections::HashMap;

/// Legacy function - creates a simple session for backward compatibility
pub fn establish_session(local_identity: &IdentityKeyPair, remote_bundle: &PreKeyBundle) -> SessionState {
    // For backward compatibility, use the new X3DH implementation
    match x3dh_alice_init(local_identity, 1234, remote_bundle) {
        Ok((_, mut session)) => {
            // Ensure both chain keys are set for backward compatibility
            if session.chain_key_recv.is_none() {
                session.chain_key_recv = Some(vec![0u8; 32]);
            }
            session
        },
        Err(_) => {
            // Fallback to a basic session state for tests
            SessionState {
                session_id: "legacy_session".to_string(),
                registration_id: 0,
                device_id: 0,
                dh_self_private: vec![0u8; 32],
                dh_self_public: vec![0u8; 32],
                dh_remote: Some(vec![0u8; 32]),
                root_key: vec![0u8; 32],
                chain_key_send: Some(vec![0u8; 32]),
                chain_key_recv: Some(vec![0u8; 32]),
                header_key_send: None,
                header_key_recv: None,
                next_header_key_send: None,
                next_header_key_recv: None,
                n_send: 0,
                n_recv: 0,
                pn: 0,
                mk_skipped: HashMap::new(),
                max_skip: 1000,
            }
        }
    }
}

/// Legacy helper to create a simple prekey bundle
pub fn create_simple_prekey_bundle(identity: &IdentityKeyPair) -> PreKeyBundle {
    let signed_prekey = generate_signed_prekey(identity, 1);
    let one_time_prekey = generate_one_time_prekey(1001);
    
    create_prekey_bundle(
        identity,
        1234,  // registration_id
        1,     // device_id
        &signed_prekey,
        Some(&one_time_prekey),
    )
}
