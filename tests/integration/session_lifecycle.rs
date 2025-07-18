//! Integration tests for session lifecycle management
//! 
//! This module tests the complete lifecycle of cryptographic sessions including:
//! - Session creation and initialization
//! - Session persistence and recovery
//! - Session expiration and cleanup
//! - Session migration and upgrades

use crate::common::*;
use signal_crypto_lib::*;
use tokio::time::{sleep, Duration};
use std::collections::HashMap;

/// Test complete session lifecycle from creation to cleanup
#[tokio::test]
async fn test_complete_session_lifecycle() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut session_manager = MockSessionManager::new().await?;
    
    // Phase 1: Session Creation
    let alice_id = "alice@example.com";
    let bob_id = "bob@example.com";
    
    let session_id = session_manager.create_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Verify session was created with correct metadata
    assert!(session_manager.has_session(&session_id).await?);
    let session_info = session_manager.get_session_info(&session_id).await?;
    assert_eq!(session_info.alice_id, alice_id);
    assert_eq!(session_info.bob_id, bob_id);
    assert!(session_info.created_at <= chrono::Utc::now());
    assert!(session_info.last_used <= chrono::Utc::now());
    
    // Phase 2: Session Usage
    let messages = vec![
        "Initial message",
        "Second message",
        "Third message",
    ];
    
    for message in &messages {
        let encrypted = session_manager.encrypt_message(
            &session_id,
            message.as_bytes()
        ).await?;
        
        let decrypted = session_manager.decrypt_message(
            &session_id,
            &encrypted
        ).await?;
        
        assert_eq!(decrypted, message.as_bytes());
    }
    
    // Verify session usage updates metadata
    let updated_info = session_manager.get_session_info(&session_id).await?;
    assert!(updated_info.last_used > session_info.last_used);
    assert_eq!(updated_info.message_count, messages.len() as u64);
    
    // Phase 3: Session Persistence
    session_manager.save_session(&session_id).await?;
    
    // Simulate application restart
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
    
    // Phase 4: Session Expiration
    // Simulate time passing beyond session TTL
    new_session_manager.advance_time(Duration::from_secs(86400 * 30)).await?; // 30 days
    
    // Session should be marked as expired but still functional
    let expired_info = new_session_manager.get_session_info(&session_id).await?;
    assert!(expired_info.is_expired());
    
    // Phase 5: Session Cleanup
    new_session_manager.cleanup_expired_sessions().await?;
    
    // Session should be removed after cleanup
    assert!(!new_session_manager.has_session(&session_id).await?);
    
    test_ctx.metrics.record_test_completion("session_lifecycle", true);
    Ok(())
}

/// Test session persistence across different storage backends
#[tokio::test]
async fn test_session_persistence_backends() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Test with different storage backends
    let backends = vec![
        MockStorageBackend::Memory,
        MockStorageBackend::File,
        MockStorageBackend::Database,
    ];
    
    for backend in backends {
        let mut session_manager = MockSessionManager::with_backend(backend.clone()).await?;
        
        // Create session
        let session_id = session_manager.create_session(
            "alice@example.com",
            "bob@example.com",
            &test_ctx.fixtures.bob_prekey_bundle
        ).await?;
        
        // Use session
        let message = format!("Test message for {:?} backend", backend);
        let encrypted = session_manager.encrypt_message(
            &session_id,
            message.as_bytes()
        ).await?;
        
        // Save session
        session_manager.save_session(&session_id).await?;
        
        // Create new session manager with same backend
        let mut new_session_manager = MockSessionManager::with_backend(backend.clone()).await?;
        new_session_manager.load_session(&session_id).await?;
        
        // Verify session works
        let decrypted = new_session_manager.decrypt_message(
            &session_id,
            &encrypted
        ).await?;
        
        assert_eq!(decrypted, message.as_bytes());
        
        // Cleanup
        new_session_manager.delete_session(&session_id).await?;
    }
    
    test_ctx.metrics.record_test_completion("session_persistence_backends", true);
    Ok(())
}

/// Test session recovery after corruption
#[tokio::test]
async fn test_session_recovery_after_corruption() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut session_manager = MockSessionManager::new().await?;
    
    // Create session
    let session_id = session_manager.create_session(
        "alice@example.com",
        "bob@example.com",
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Use session normally
    let original_message = "Original message";
    let encrypted = session_manager.encrypt_message(
        &session_id,
        original_message.as_bytes()
    ).await?;
    
    // Save session state
    session_manager.save_session(&session_id).await?;
    
    // Simulate corruption by partially corrupting session data
    session_manager.corrupt_session_data(&session_id, 0.1).await?; // 10% corruption
    
    // Attempt to use corrupted session
    let recovery_result = session_manager.encrypt_message(
        &session_id,
        b"Message after corruption"
    ).await;
    
    match recovery_result {
        Ok(_) => {
            // Session recovered successfully
            test_ctx.metrics.record_test_completion("session_recovery_success", true);
        },
        Err(_) => {
            // Session recovery failed, should trigger session reset
            let reset_result = session_manager.reset_session(&session_id).await;
            assert!(reset_result.is_ok());
            
            // Verify session works after reset
            let new_encrypted = session_manager.encrypt_message(
                &session_id,
                b"Message after reset"
            ).await?;
            
            let decrypted = session_manager.decrypt_message(
                &session_id,
                &new_encrypted
            ).await?;
            
            assert_eq!(decrypted, b"Message after reset");
            test_ctx.metrics.record_test_completion("session_recovery_reset", true);
        }
    }
    
    Ok(())
}

/// Test concurrent session operations
#[tokio::test]
async fn test_concurrent_session_operations() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let session_manager = MockSessionManager::new().await?;
    
    // Create multiple sessions concurrently
    let session_count = 20;
    let mut handles = Vec::new();
    
    for i in 0..session_count {
        let session_manager = session_manager.clone();
        let bob_prekey_bundle = test_ctx.fixtures.bob_prekey_bundle.clone();
        
        let handle = tokio::spawn(async move {
            let alice_id = format!("alice{}@example.com", i);
            let bob_id = format!("bob{}@example.com", i);
            
            // Create session
            let session_id = session_manager.create_session(
                &alice_id,
                &bob_id,
                &bob_prekey_bundle
            ).await?;
            
            // Use session
            let message = format!("Concurrent message {}", i);
            let encrypted = session_manager.encrypt_message(
                &session_id,
                message.as_bytes()
            ).await?;
            
            let decrypted = session_manager.decrypt_message(
                &session_id,
                &encrypted
            ).await?;
            
            assert_eq!(decrypted, message.as_bytes());
            
            // Save session
            session_manager.save_session(&session_id).await?;
            
            Ok::<String, Box<dyn std::error::Error + Send + Sync>>(session_id)
        });
        
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    let mut session_ids = Vec::new();
    for handle in handles {
        let session_id = handle.await??;
        session_ids.push(session_id);
    }
    
    // Verify all sessions were created
    assert_eq!(session_ids.len(), session_count);
    
    // Verify all sessions are functional
    for session_id in &session_ids {
        assert!(session_manager.has_session(session_id).await?);
        
        let test_message = "Verification message";
        let encrypted = session_manager.encrypt_message(
            session_id,
            test_message.as_bytes()
        ).await?;
        
        let decrypted = session_manager.decrypt_message(
            session_id,
            &encrypted
        ).await?;
        
        assert_eq!(decrypted, test_message.as_bytes());
    }
    
    test_ctx.metrics.record_test_completion("concurrent_session_operations", true);
    Ok(())
}

/// Test session migration between protocol versions
#[tokio::test]
async fn test_session_migration() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    
    // Create session with old protocol version
    let mut old_session_manager = MockSessionManager::with_protocol_version(1).await?;
    
    let session_id = old_session_manager.create_session(
        "alice@example.com",
        "bob@example.com",
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Use session with old version
    let old_message = "Message with old protocol";
    let old_encrypted = old_session_manager.encrypt_message(
        &session_id,
        old_message.as_bytes()
    ).await?;
    
    // Save session
    old_session_manager.save_session(&session_id).await?;
    
    // Create new session manager with updated protocol version
    let mut new_session_manager = MockSessionManager::with_protocol_version(2).await?;
    
    // Load session (should trigger migration)
    new_session_manager.load_session(&session_id).await?;
    
    // Verify session was migrated
    let session_info = new_session_manager.get_session_info(&session_id).await?;
    assert_eq!(session_info.protocol_version, 2);
    
    // Verify old messages can still be decrypted
    let decrypted_old = new_session_manager.decrypt_message(
        &session_id,
        &old_encrypted
    ).await?;
    assert_eq!(decrypted_old, old_message.as_bytes());
    
    // Verify new messages use new protocol
    let new_message = "Message with new protocol";
    let new_encrypted = new_session_manager.encrypt_message(
        &session_id,
        new_message.as_bytes()
    ).await?;
    
    let decrypted_new = new_session_manager.decrypt_message(
        &session_id,
        &new_encrypted
    ).await?;
    assert_eq!(decrypted_new, new_message.as_bytes());
    
    test_ctx.metrics.record_test_completion("session_migration", true);
    Ok(())
}

/// Test session cleanup and garbage collection
#[tokio::test]
async fn test_session_cleanup_and_gc() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut session_manager = MockSessionManager::new().await?;
    
    // Create multiple sessions with different ages
    let mut session_ids = Vec::new();
    
    for i in 0..10 {
        let session_id = session_manager.create_session(
            &format!("alice{}@example.com", i),
            &format!("bob{}@example.com", i),
            &test_ctx.fixtures.bob_prekey_bundle
        ).await?;
        
        session_ids.push(session_id);
        
        // Simulate different creation times
        session_manager.set_session_age(&session_ids[i], Duration::from_secs(i * 86400)).await?;
    }
    
    // Mark some sessions as inactive
    for i in 0..5 {
        session_manager.mark_session_inactive(&session_ids[i]).await?;
    }
    
    // Run cleanup with different policies
    let cleanup_policies = vec![
        MockCleanupPolicy::RemoveInactive,
        MockCleanupPolicy::RemoveOlderThan(Duration::from_secs(86400 * 5)), // 5 days
        MockCleanupPolicy::KeepMostRecent(3),
    ];
    
    for policy in cleanup_policies {
        let initial_count = session_manager.get_session_count().await?;
        session_manager.cleanup_sessions_with_policy(policy.clone()).await?;
        let final_count = session_manager.get_session_count().await?;
        
        match policy {
            MockCleanupPolicy::RemoveInactive => {
                assert!(final_count <= initial_count);
            },
            MockCleanupPolicy::RemoveOlderThan(_) => {
                assert!(final_count <= initial_count);
            },
            MockCleanupPolicy::KeepMostRecent(n) => {
                assert!(final_count <= n);
            },
        }
    }
    
    test_ctx.metrics.record_test_completion("session_cleanup_gc", true);
    Ok(())
}

/// Test session backup and restore
#[tokio::test]
async fn test_session_backup_and_restore() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut session_manager = MockSessionManager::new().await?;
    
    // Create multiple sessions
    let mut session_ids = Vec::new();
    let mut messages = HashMap::new();
    
    for i in 0..5 {
        let session_id = session_manager.create_session(
            &format!("alice{}@example.com", i),
            &format!("bob{}@example.com", i),
            &test_ctx.fixtures.bob_prekey_bundle
        ).await?;
        
        // Use each session
        let message = format!("Test message {}", i);
        let encrypted = session_manager.encrypt_message(
            &session_id,
            message.as_bytes()
        ).await?;
        
        session_ids.push(session_id.clone());
        messages.insert(session_id, (message, encrypted));
    }
    
    // Create backup
    let backup_data = session_manager.create_backup().await?;
    assert!(!backup_data.is_empty());
    
    // Simulate data loss
    session_manager.clear_all_sessions().await?;
    assert_eq!(session_manager.get_session_count().await?, 0);
    
    // Restore from backup
    session_manager.restore_from_backup(&backup_data).await?;
    
    // Verify all sessions were restored
    assert_eq!(session_manager.get_session_count().await?, session_ids.len());
    
    // Verify sessions are functional
    for session_id in &session_ids {
        assert!(session_manager.has_session(session_id).await?);
        
        if let Some((original_message, encrypted)) = messages.get(session_id) {
            let decrypted = session_manager.decrypt_message(
                session_id,
                encrypted
            ).await?;
            
            assert_eq!(decrypted, original_message.as_bytes());
        }
    }
    
    test_ctx.metrics.record_test_completion("session_backup_restore", true);
    Ok(())
}

/// Test session monitoring and health checks
#[tokio::test]
async fn test_session_monitoring_and_health() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut session_manager = MockSessionManager::new().await?;
    
    // Create sessions with different health states
    let healthy_session = session_manager.create_session(
        "alice1@example.com",
        "bob1@example.com",
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    let degraded_session = session_manager.create_session(
        "alice2@example.com",
        "bob2@example.com",
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    let failing_session = session_manager.create_session(
        "alice3@example.com",
        "bob3@example.com",
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Simulate different health conditions
    session_manager.simulate_session_degradation(&degraded_session, 0.3).await?; // 30% degradation
    session_manager.simulate_session_failure(&failing_session).await?;
    
    // Run health checks
    let health_report = session_manager.run_health_check().await?;
    
    assert_eq!(health_report.total_sessions, 3);
    assert_eq!(health_report.healthy_sessions, 1);
    assert_eq!(health_report.degraded_sessions, 1);
    assert_eq!(health_report.failing_sessions, 1);
    
    // Test individual session health
    let healthy_status = session_manager.check_session_health(&healthy_session).await?;
    assert_eq!(healthy_status, MockSessionHealth::Healthy);
    
    let degraded_status = session_manager.check_session_health(&degraded_session).await?;
    assert_eq!(degraded_status, MockSessionHealth::Degraded);
    
    let failing_status = session_manager.check_session_health(&failing_session).await?;
    assert_eq!(failing_status, MockSessionHealth::Failing);
    
    // Test automatic remediation
    session_manager.enable_auto_remediation(true).await?;
    session_manager.run_remediation().await?;
    
    // Verify remediation results
    let post_remediation_report = session_manager.run_health_check().await?;
    assert!(post_remediation_report.healthy_sessions >= health_report.healthy_sessions);
    
    test_ctx.metrics.record_test_completion("session_monitoring_health", true);
    Ok(())
}

/// Mock session manager implementation for testing
#[derive(Clone)]
struct MockSessionManager {
    sessions: std::sync::Arc<tokio::sync::RwLock<HashMap<String, MockSessionData>>>,
    backend: MockStorageBackend,
    protocol_version: u32,
    auto_remediation: bool,
}

#[derive(Debug, Clone)]
struct MockSessionData {
    alice_id: String,
    bob_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: chrono::DateTime<chrono::Utc>,
    message_count: u64,
    protocol_version: u32,
    health: MockSessionHealth,
    is_active: bool,
    ratchet_state: Vec<u8>,
}

#[derive(Debug, Clone)]
struct MockSessionInfo {
    alice_id: String,
    bob_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: chrono::DateTime<chrono::Utc>,
    message_count: u64,
    protocol_version: u32,
}

impl MockSessionInfo {
    fn is_expired(&self) -> bool {
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(self.created_at);
        age.num_days() > 30 // 30 day TTL
    }
}

#[derive(Debug, Clone, PartialEq)]
enum MockStorageBackend {
    Memory,
    File,
    Database,
}

#[derive(Debug, Clone, PartialEq)]
enum MockSessionHealth {
    Healthy,
    Degraded,
    Failing,
}

#[derive(Debug, Clone)]
enum MockCleanupPolicy {
    RemoveInactive,
    RemoveOlderThan(Duration),
    KeepMostRecent(usize),
}

#[derive(Debug)]
struct MockHealthReport {
    total_sessions: usize,
    healthy_sessions: usize,
    degraded_sessions: usize,
    failing_sessions: usize,
}

impl MockSessionManager {
    async fn new() -> Result<Self> {
        Ok(Self {
            sessions: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            backend: MockStorageBackend::Memory,
            protocol_version: 1,
            auto_remediation: false,
        })
    }
    
    async fn with_backend(backend: MockStorageBackend) -> Result<Self> {
        Ok(Self {
            sessions: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            backend,
            protocol_version: 1,
            auto_remediation: false,
        })
    }
    
    async fn with_protocol_version(version: u32) -> Result<Self> {
        Ok(Self {
            sessions: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            backend: MockStorageBackend::Memory,
            protocol_version: version,
            auto_remediation: false,
        })
    }
    
    async fn create_session(
        &self,
        alice_id: &str,
        bob_id: &str,
        _prekey_bundle: &TestPreKeyBundle,
    ) -> Result<String> {
        let session_id = format!("session_{}_{}", alice_id, bob_id);
        let now = chrono::Utc::now();
        
        let session_data = MockSessionData {
            alice_id: alice_id.to_string(),
            bob_id: bob_id.to_string(),
            created_at: now,
            last_used: now,
            message_count: 0,
            protocol_version: self.protocol_version,
            health: MockSessionHealth::Healthy,
            is_active: true,
            ratchet_state: generate_test_key(64),
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session_data);
        
        Ok(session_id)
    }
    
    async fn has_session(&self, session_id: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        Ok(sessions.contains_key(session_id))
    }
    
    async fn get_session_info(&self, session_id: &str) -> Result<MockSessionInfo> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("Session not found: {}", session_id))?;
        
        Ok(MockSessionInfo {
            alice_id: session.alice_id.clone(),
            bob_id: session.bob_id.clone(),
            created_at: session.created_at,
            last_used: session.last_used,
            message_count: session.message_count,
            protocol_version: session.protocol_version,
        })
    }
    
    async fn encrypt_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| format!("Session not found: {}", session_id))?;
        
        // Update session metadata
        session.last_used = chrono::Utc::now();
        session.message_count += 1;
        
        // Simulate encryption
        let mut encrypted = message.to_vec();
        encrypted.extend_from_slice(b"_encrypted");
        Ok(encrypted)
    }
    
    async fn decrypt_message(&self, session_id: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let _session = sessions.get(session_id)
            .ok_or_else(|| format!("Session not found: {}", session_id))?;
        
        // Simulate decryption
        if encrypted.ends_with(b"_encrypted") {
            let decrypted = &encrypted[..encrypted.len() - 10];
            Ok(decrypted.to_vec())
        } else {
            Err("Invalid encrypted message".into())
        }
    }
    
    async fn save_session(&self, _session_id: &str) -> Result<()> {
        // Simulate saving to storage backend
        match self.backend {
            MockStorageBackend::Memory => Ok(()),
            MockStorageBackend::File => {
                sleep(Duration::from_millis(10)).await; // Simulate file I/O
                Ok(())
            },
            MockStorageBackend::Database => {
                sleep(Duration::from_millis(20)).await; // Simulate database I/O
                Ok(())
            },
        }
    }
    
    async fn load_session(&self, session_id: &str) -> Result<()> {
        // Simulate loading from storage backend
        match self.backend {
            MockStorageBackend::Memory => Ok(()),
            MockStorageBackend::File => {
                sleep(Duration::from_millis(10)).await; // Simulate file I/O
                Ok(())
            },
            MockStorageBackend::Database => {
                sleep(Duration::from_millis(20)).await; // Simulate database I/O
                
                // Simulate protocol migration if needed
                let mut sessions = self.sessions.write().await;
                if let Some(session) = sessions.get_mut(session_id) {
                    if session.protocol_version < self.protocol_version {
                        session.protocol_version = self.protocol_version;
                    }
                }
                Ok(())
            },
        }
    }
    
    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        Ok(())
    }
    
    async fn advance_time(&self, duration: Duration) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        for session in sessions.values_mut() {
            session.created_at = session.created_at - chrono::Duration::from_std(duration)?;
        }
        Ok(())
    }
    
    async fn cleanup_expired_sessions(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        
        sessions.retain(|_, session| {
            let age = now.signed_duration_since(session.created_at);
            age.num_days() <= 30 // Keep sessions younger than 30 days
        });
        
        Ok(())
    }
    
    async fn corrupt_session_data(&self, session_id: &str, corruption_rate: f32) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            let corrupt_bytes = (session.ratchet_state.len() as f32 * corruption_rate) as usize;
            for i in 0..corrupt_bytes {
                session.ratchet_state[i] = 0xFF; // Corrupt data
            }
        }
        Ok(())
    }
    
    async fn reset_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.ratchet_state = generate_test_key(64); // Reset with new state
            session.health = MockSessionHealth::Healthy;
        }
        Ok(())
    }
    
    async fn get_session_count(&self) -> Result<usize> {
        let sessions = self.sessions.read().await;
        Ok(sessions.len())
    }
    
    async fn mark_session_inactive(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.is_active = false;
        }
        Ok(())
    }
    
    async fn set_session_age(&self, session_id: &str, age: Duration) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            let now = chrono::Utc::now();
            session.created_at = now - chrono::Duration::from_std(age)?;
        }
        Ok(())
    }
    
    async fn cleanup_sessions_with_policy(&self, policy: MockCleanupPolicy) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        match policy {
            MockCleanupPolicy::RemoveInactive => {
                sessions.retain(|_, session| session.is_active);
            },
            MockCleanupPolicy::RemoveOlderThan(max_age) => {
                let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age)?;
                sessions.retain(|_, session| session.created_at > cutoff);
            },
            MockCleanupPolicy::KeepMostRecent(keep_count) => {
                if sessions.len() > keep_count {
                    let mut session_vec: Vec<_> = sessions.iter().collect();
                    session_vec.sort_by_key(|(_, session)| session.last_used);
                    session_vec.reverse(); // Most recent first
                    
                    let to_remove: Vec<_> = session_vec.iter()
                        .skip(keep_count)
                        .map(|(id, _)| (*id).clone())
                        .collect();
                    
                    for id in to_remove {
                        sessions.remove(&id);
                    }
                }
            },
        }
        Ok(())
    }
    
    async fn clear_all_sessions(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.clear();
        Ok(())
    }
    
    async fn restore_from_backup(&self, backup_data: &[u8]) -> Result<()> {
        // Simulate restoring from backup
        let _backup_str = String::from_utf8_lossy(backup_data);
        // In a real implementation, this would deserialize the backup data
        // and restore all sessions
        Ok(())
    }
    
    async fn create_backup(&self) -> Result<Vec<u8>> {
        // Simulate creating backup
        let sessions = self.sessions.read().await;
        let backup_data = format!("backup_of_{}_sessions", sessions.len());
        Ok(backup_data.into_bytes())
    }
    
    async fn run_health_check(&self) -> Result<MockHealthReport> {
        let sessions = self.sessions.read().await;
        let mut healthy = 0;
        let mut degraded = 0;
        let mut failing = 0;
        
        for session in sessions.values() {
            match session.health {
                MockSessionHealth::Healthy => healthy += 1,
                MockSessionHealth::Degraded => degraded += 1,
                MockSessionHealth::Failing => failing += 1,
            }
        }
        
        Ok(MockHealthReport {
            total_sessions: sessions.len(),
            healthy_sessions: healthy,
            degraded_sessions: degraded,
            failing_sessions: failing,
        })
    }
    
    async fn check_session_health(&self, session_id: &str) -> Result<MockSessionHealth> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            Ok(session.health.clone())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn simulate_session_degradation(&self, session_id: &str, _degradation_rate: f32) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.health = MockSessionHealth::Degraded;
        }
        Ok(())
    }
    
    async fn simulate_session_failure(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.health = MockSessionHealth::Failing;
        }
        Ok(())
    }
    
    async fn enable_auto_remediation(&self, _enabled: bool) -> Result<()> {
        // Simulate enabling auto-remediation
        Ok(())
    }
    
    async fn run_remediation(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        for session in sessions.values_mut() {
            if session.health == MockSessionHealth::Degraded {
                // Attempt to fix degraded sessions
                session.health = MockSessionHealth::Healthy;
            }
        }
        Ok(())
    }
}