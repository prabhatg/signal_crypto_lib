// signal_crypto_lib/src/lib.rs

mod identity;
mod prekey;
mod types;
mod group;
mod integration_tests;
mod session_manager;
mod group_sender_key;
mod skipped_keys;
mod x3dh_keys;
mod protocol;
mod security;
mod advanced;
mod performance;
mod post_quantum;
mod recovery;
mod enterprise;
mod audit;
mod deployment;
mod ai_ml;
mod quantum;
mod next_gen;
mod group_ffi;
mod session_ffi;

// Legacy modules (to be replaced)
mod x3dh;
mod double_ratchet;

pub use types::*;
pub use protocol::*;

// Re-export the actual implementations from their modules
pub use identity::generate_identity_keypair;
pub use prekey::{generate_signed_prekey, generate_one_time_prekey};
pub use protocol::x3dh::{x3dh_alice_init, x3dh_bob_init, create_prekey_bundle};
pub use session_manager::{SessionManager, SessionManagerError};
pub use security::{ReplayProtection, SecurityError, MessageMetadata, SecureMemory, SecureKeyDerivation, MessageAuthenticator};
pub use advanced::{
    ProtocolVersion, MessageBatch, MessageBatcher, MessageCompressor, CompressionType,
    AdvancedGroupSession, GroupMember, GroupRole, Permission as AdvancedPermission, DeliveryReceipt, DeliveryStatus,
    ProtocolMetrics, BatchedMessage, MessageType, MessagePriority
};
pub use performance::{
    LruCache, SessionCache, ObjectPool, MemoryPool, PerformanceMonitor, KeyDerivationCache
};
pub use post_quantum::{
    PQAlgorithm, HybridKeyPair, HybridX3DH, HybridSignature, AlgorithmSuite, HybridMode,
    CryptoMigrationManager, PQError
};
pub use recovery::{
    ErrorRecoveryManager, RecoveryStrategy, RecoveryConfig, RecoveryResult, CircuitBreaker,
    ProtocolError, RecoveryError
};
pub use enterprise::{
    EnterpriseAuthManager, EnterpriseUser, AuthProvider, SecurityClearance, Role, Permission,
    Tenant, TenantSettings, AuthSession, AuthMethod, EnterpriseAuthConfig
};

// Temporary compatibility layer
pub use x3dh::establish_session;
pub use double_ratchet::{encrypt, decrypt};
pub use group::{generate_sender_key, encrypt_group_message, decrypt_group_message};

#[cfg(feature = "ffi")]
mod api;
#[cfg(feature = "ffi")]
pub use api::*;
#[cfg(feature = "ffi")]
pub use group_ffi::*;
#[cfg(feature = "ffi")]
pub use session_ffi::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::create_simple_prekey_bundle;

    #[test]
    fn test_identity_key_generation() {
        let identity = generate_identity_keypair();
        assert_eq!(identity.dh_public.len(), 32);
        assert_eq!(identity.dh_private.len(), 32);
        assert_eq!(identity.ed_public.len(), 32);
        assert_eq!(identity.ed_private.len(), 32);
    }

    #[test]
    fn test_prekey_bundle_creation() {
        let identity = generate_identity_keypair();
        let bundle = create_simple_prekey_bundle(&identity);
        assert_eq!(bundle.identity_key.len(), 32);
        assert_eq!(bundle.signed_prekey_public.len(), 32);
        assert_eq!(bundle.signed_prekey_signature.len(), 64);
    }

    #[test]
    fn test_x3dh_session_establishment() {
        let alice = generate_identity_keypair();
        let bob = generate_identity_keypair();
        let bob_bundle = create_simple_prekey_bundle(&bob);

        let session = establish_session(&alice, &bob_bundle);
        assert!(!session.session_id.is_empty());
        assert_eq!(session.root_key.len(), 32);
        assert!(session.chain_key_send.is_some());
        assert!(session.chain_key_recv.is_some());
    }

    #[test]
    fn test_double_ratchet_encryption_decryption() {
        let alice = generate_identity_keypair();
        let bob = generate_identity_keypair();
        let bob_bundle = create_simple_prekey_bundle(&bob);

        let mut alice_session = establish_session(&alice, &bob_bundle);
        let alice_bundle = create_simple_prekey_bundle(&alice);
        let mut bob_session = establish_session(&bob, &alice_bundle);

        // Initialize Bob's receive chain with Alice's send chain
        bob_session.chain_key_recv = alice_session.chain_key_send.clone();
        alice_session.chain_key_recv = bob_session.chain_key_send.clone();

        let plaintext = "Hello, Bob!";
        let encrypted = encrypt(&mut alice_session, plaintext);
        let decrypted = decrypt(&mut bob_session, &encrypted);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_group_sender_key_generation_and_encryption() {
        let group_sender = generate_sender_key();
        let plaintext = "Hello Group!";
        let encrypted = encrypt_group_message(&group_sender, plaintext);
        let decrypted = decrypt_group_message(&group_sender, &encrypted);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_group_member_encryption_decryption() {
        let group_sender = generate_sender_key();
        let member1_key = group_sender.clone();
        let member2_key = group_sender.clone();

        let plaintext = "Group message";
        let encrypted = encrypt_group_message(&group_sender, plaintext);

        let decrypted1 = decrypt_group_message(&member1_key, &encrypted);
        let decrypted2 = decrypt_group_message(&member2_key, &encrypted);

        assert_eq!(plaintext, decrypted1);
        assert_eq!(plaintext, decrypted2);
    }
}
