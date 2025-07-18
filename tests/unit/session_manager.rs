// tests/unit/session_manager.rs
//! Unit tests for session manager functionality

use crate::common::{
    fixtures::*,
    helpers::*,
    assertions::*,
    mocks::*,
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Mock session structures
#[derive(Debug, Clone, PartialEq)]
enum MockSessionState {
    Pending,
    Active,
    Suspended,
    Terminated,
    Error,
}

#[derive(Debug, Clone)]
struct MockSession {
    id: String,
    alice_id: String,
    bob_id: String,
    state: MockSessionState,
    created_at: u64,
    last_activity: u64,
    message_count: u64,
    root_key: Vec<u8>,
    chain_key: Vec<u8>,
    metadata: HashMap<String, String>,
}

impl MockSession {
    fn new(id: String, alice_id: String, bob_id: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id,
            alice_id,
            bob_id,
            state: MockSessionState::Pending,
            created_at: timestamp,
            last_activity: timestamp,
            message_count: 0,
            root_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            chain_key: vec![8, 7, 6, 5, 4, 3, 2, 1],
            metadata: HashMap::new(),
        }
    }
    
    fn id(&self) -> &str {
        &self.id
    }
    
    fn alice_id(&self) -> &str {
        &self.alice_id
    }
    
    fn bob_id(&self) -> &str {
        &self.bob_id
    }
    
    fn state(&self) -> &MockSessionState {
        &self.state
    }
    
    fn set_state(&mut self, state: MockSessionState) {
        self.state = state;
        self.update_activity();
    }
    
    fn created_at(&self) -> u64 {
        self.created_at
    }
    
    fn last_activity(&self) -> u64 {
        self.last_activity
    }
    
    fn message_count(&self) -> u64 {
        self.message_count
    }
    
    fn increment_message_count(&mut self) {
        self.message_count += 1;
        self.update_activity();
    }
    
    fn update_activity(&mut self) {
        self.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    fn root_key(&self) -> &[u8] {
        &self.root_key
    }
    
    fn chain_key(&self) -> &[u8] {
        &self.chain_key
    }
    
    fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.push(0); // separator
        data.extend_from_slice(self.alice_id.as_bytes());
        data.push(0); // separator
        data.extend_from_slice(self.bob_id.as_bytes());
        data.push(0); // separator
        data.extend_from_slice(&self.created_at.to_be_bytes());
        data.extend_from_slice(&self.message_count.to_be_bytes());
        data.extend_from_slice(&self.root_key);
        data.extend_from_slice(&self.chain_key);
        data
    }
}

// Mock session manager
struct MockSessionManager {
    sessions: RwLock<HashMap<String, MockSession>>,
    user_sessions: RwLock<HashMap<String, Vec<String>>>, // user_id -> session_ids
    session_counter: RwLock<u64>,
    max_sessions_per_user: usize,
    session_timeout: Duration,
}

impl MockSessionManager {
    fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            user_sessions: RwLock::new(HashMap::new()),
            session_counter: RwLock::new(0),
            max_sessions_per_user: 10,
            session_timeout: Duration::from_secs(3600), // 1 hour
        }
    }
    
    fn with_config(max_sessions_per_user: usize, session_timeout: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            user_sessions: RwLock::new(HashMap::new()),
            session_counter: RwLock::new(0),
            max_sessions_per_user,
            session_timeout,
        }
    }
    
    async fn create_session(&self, alice_id: String, bob_id: String) -> Result<String> {
        // Check session limits
        let user_sessions = self.user_sessions.read().await;
        if let Some(sessions) = user_sessions.get(&alice_id) {
            if sessions.len() >= self.max_sessions_per_user {
                return Err("Maximum sessions per user exceeded".into());
            }
        }
        if let Some(sessions) = user_sessions.get(&bob_id) {
            if sessions.len() >= self.max_sessions_per_user {
                return Err("Maximum sessions per user exceeded".into());
            }
        }
        drop(user_sessions);
        
        // Generate session ID
        let mut counter = self.session_counter.write().await;
        *counter += 1;
        let session_id = format!("session_{}", *counter);
        drop(counter);
        
        // Create session
        let session = MockSession::new(session_id.clone(), alice_id.clone(), bob_id.clone());
        
        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);
        drop(sessions);
        
        // Update user sessions
        let mut user_sessions = self.user_sessions.write().await;
        user_sessions.entry(alice_id).or_insert_with(Vec::new).push(session_id.clone());
        user_sessions.entry(bob_id).or_insert_with(Vec::new).push(session_id.clone());
        
        Ok(session_id)
    }
    
    async fn get_session(&self, session_id: &str) -> Result<Option<MockSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }
    
    async fn update_session_state(&self, session_id: &str, state: MockSessionState) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.set_state(state);
            Ok(())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn activate_session(&self, session_id: &str) -> Result<()> {
        self.update_session_state(session_id, MockSessionState::Active).await
    }
    
    async fn suspend_session(&self, session_id: &str) -> Result<()> {
        self.update_session_state(session_id, MockSessionState::Suspended).await
    }
    
    async fn terminate_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(mut session) = sessions.remove(session_id) {
            session.set_state(MockSessionState::Terminated);
            
            // Remove from user sessions
            let mut user_sessions = self.user_sessions.write().await;
            if let Some(alice_sessions) = user_sessions.get_mut(&session.alice_id) {
                alice_sessions.retain(|id| id != session_id);
            }
            if let Some(bob_sessions) = user_sessions.get_mut(&session.bob_id) {
                bob_sessions.retain(|id| id != session_id);
            }
            
            Ok(())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn increment_message_count(&self, session_id: &str) -> Result<u64> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.increment_message_count();
            Ok(session.message_count())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<String>> {
        let user_sessions = self.user_sessions.read().await;
        Ok(user_sessions.get(user_id).cloned().unwrap_or_default())
    }
    
    async fn list_active_sessions(&self) -> Result<Vec<String>> {
        let sessions = self.sessions.read().await;
        let active_sessions: Vec<String> = sessions
            .values()
            .filter(|session| session.state() == &MockSessionState::Active)
            .map(|session| session.id().to_string())
            .collect();
        Ok(active_sessions)
    }
    
    async fn count_sessions(&self) -> Result<usize> {
        let sessions = self.sessions.read().await;
        Ok(sessions.len())
    }
    
    async fn count_sessions_by_state(&self, state: MockSessionState) -> Result<usize> {
        let sessions = self.sessions.read().await;
        let count = sessions
            .values()
            .filter(|session| session.state() == &state)
            .count();
        Ok(count)
    }
    
    async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let timeout_seconds = self.session_timeout.as_secs();
        let mut expired_sessions = Vec::new();
        
        {
            let sessions = self.sessions.read().await;
            for (session_id, session) in sessions.iter() {
                let age = current_time.saturating_sub(session.last_activity());
                if age > timeout_seconds {
                    expired_sessions.push(session_id.clone());
                }
            }
        }
        
        let count = expired_sessions.len();
        for session_id in expired_sessions {
            let _ = self.terminate_session(&session_id).await;
        }
        
        Ok(count)
    }
    
    async fn set_session_metadata(&self, session_id: &str, key: String, value: String) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.set_metadata(key, value);
            Ok(())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn get_session_metadata(&self, session_id: &str, key: &str) -> Result<Option<String>> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            Ok(session.get_metadata(key).cloned())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn export_session(&self, session_id: &str) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            Ok(session.serialize())
        } else {
            Err("Session not found".into())
        }
    }
    
    async fn get_session_statistics(&self) -> Result<SessionStatistics> {
        let sessions = self.sessions.read().await;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let total_sessions = sessions.len();
        let mut active_sessions = 0;
        let mut suspended_sessions = 0;
        let mut total_messages = 0;
        let mut oldest_session_age = 0u64;
        let mut newest_session_age = u64::MAX;
        
        for session in sessions.values() {
            match session.state() {
                MockSessionState::Active => active_sessions += 1,
                MockSessionState::Suspended => suspended_sessions += 1,
                _ => {}
            }
            
            total_messages += session.message_count();
            
            let age = current_time.saturating_sub(session.created_at());
            oldest_session_age = oldest_session_age.max(age);
            newest_session_age = newest_session_age.min(age);
        }
        
        if newest_session_age == u64::MAX {
            newest_session_age = 0;
        }
        
        Ok(SessionStatistics {
            total_sessions,
            active_sessions,
            suspended_sessions,
            total_messages,
            oldest_session_age,
            newest_session_age,
        })
    }
    
    async fn find_session_by_participants(&self, alice_id: &str, bob_id: &str) -> Result<Option<String>> {
        let sessions = self.sessions.read().await;
        for (session_id, session) in sessions.iter() {
            if (session.alice_id() == alice_id && session.bob_id() == bob_id) ||
               (session.alice_id() == bob_id && session.bob_id() == alice_id) {
                return Ok(Some(session_id.clone()));
            }
        }
        Ok(None)
    }
    
    async fn bulk_terminate_user_sessions(&self, user_id: &str) -> Result<usize> {
        let session_ids = self.get_user_sessions(user_id).await?;
        let count = session_ids.len();
        
        for session_id in session_ids {
            let _ = self.terminate_session(&session_id).await;
        }
        
        Ok(count)
    }
}

#[derive(Debug)]
struct SessionStatistics {
    total_sessions: usize,
    active_sessions: usize,
    suspended_sessions: usize,
    total_messages: u64,
    oldest_session_age: u64,
    newest_session_age: u64,
}

#[tokio::test]
async fn test_session_creation() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Create session
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    assert!(!session_id.is_empty());
    assert!(session_id.starts_with("session_"));
    
    // Verify session exists
    let session = manager.get_session(&session_id).await?;
    assert!(session.is_some());
    
    let session = session.unwrap();
    assert_eq!(session.alice_id(), "alice");
    assert_eq!(session.bob_id(), "bob");
    assert_eq!(session.state(), &MockSessionState::Pending);
    assert_eq!(session.message_count(), 0);
    
    Ok(())
}

#[tokio::test]
async fn test_session_state_management() -> Result<()> {
    let manager = MockSessionManager::new();
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    
    // Activate session
    manager.activate_session(&session_id).await?;
    let session = manager.get_session(&session_id).await?.unwrap();
    assert_eq!(session.state(), &MockSessionState::Active);
    
    // Suspend session
    manager.suspend_session(&session_id).await?;
    let session = manager.get_session(&session_id).await?.unwrap();
    assert_eq!(session.state(), &MockSessionState::Suspended);
    
    // Terminate session
    manager.terminate_session(&session_id).await?;
    let session = manager.get_session(&session_id).await?;
    assert!(session.is_none());
    
    Ok(())
}

#[tokio::test]
async fn test_message_count_tracking() -> Result<()> {
    let manager = MockSessionManager::new();
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    
    // Increment message count
    let count1 = manager.increment_message_count(&session_id).await?;
    assert_eq!(count1, 1);
    
    let count2 = manager.increment_message_count(&session_id).await?;
    assert_eq!(count2, 2);
    
    let count3 = manager.increment_message_count(&session_id).await?;
    assert_eq!(count3, 3);
    
    // Verify count in session
    let session = manager.get_session(&session_id).await?.unwrap();
    assert_eq!(session.message_count(), 3);
    
    Ok(())
}

#[tokio::test]
async fn test_user_session_management() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Create multiple sessions for alice
    let session1 = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    let session2 = manager.create_session("alice".to_string(), "charlie".to_string()).await?;
    let session3 = manager.create_session("dave".to_string(), "alice".to_string()).await?;
    
    // Get alice's sessions
    let alice_sessions = manager.get_user_sessions("alice").await?;
    assert_eq!(alice_sessions.len(), 3);
    assert!(alice_sessions.contains(&session1));
    assert!(alice_sessions.contains(&session2));
    assert!(alice_sessions.contains(&session3));
    
    // Get bob's sessions
    let bob_sessions = manager.get_user_sessions("bob").await?;
    assert_eq!(bob_sessions.len(), 1);
    assert!(bob_sessions.contains(&session1));
    
    Ok(())
}

#[tokio::test]
async fn test_session_limits() -> Result<()> {
    let manager = MockSessionManager::with_config(2, Duration::from_secs(3600));
    
    // Create sessions up to limit
    let session1 = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    let session2 = manager.create_session("alice".to_string(), "charlie".to_string()).await?;
    
    // Try to exceed limit
    let result = manager.create_session("alice".to_string(), "dave".to_string()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Maximum sessions"));
    
    // Terminate a session and try again
    manager.terminate_session(&session1).await?;
    let session3 = manager.create_session("alice".to_string(), "dave".to_string()).await?;
    assert!(!session3.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_session_listing() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Create and activate sessions
    let session1 = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    let session2 = manager.create_session("charlie".to_string(), "dave".to_string()).await?;
    let session3 = manager.create_session("eve".to_string(), "frank".to_string()).await?;
    
    manager.activate_session(&session1).await?;
    manager.activate_session(&session2).await?;
    manager.suspend_session(&session3).await?;
    
    // List active sessions
    let active_sessions = manager.list_active_sessions().await?;
    assert_eq!(active_sessions.len(), 2);
    assert!(active_sessions.contains(&session1));
    assert!(active_sessions.contains(&session2));
    assert!(!active_sessions.contains(&session3));
    
    // Count sessions by state
    let active_count = manager.count_sessions_by_state(MockSessionState::Active).await?;
    assert_eq!(active_count, 2);
    
    let suspended_count = manager.count_sessions_by_state(MockSessionState::Suspended).await?;
    assert_eq!(suspended_count, 1);
    
    Ok(())
}

#[tokio::test]
async fn test_session_metadata() -> Result<()> {
    let manager = MockSessionManager::new();
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    
    // Set metadata
    manager.set_session_metadata(&session_id, "protocol_version".to_string(), "1.0".to_string()).await?;
    manager.set_session_metadata(&session_id, "encryption_type".to_string(), "AES256".to_string()).await?;
    
    // Get metadata
    let version = manager.get_session_metadata(&session_id, "protocol_version").await?;
    assert_eq!(version, Some("1.0".to_string()));
    
    let encryption = manager.get_session_metadata(&session_id, "encryption_type").await?;
    assert_eq!(encryption, Some("AES256".to_string()));
    
    let nonexistent = manager.get_session_metadata(&session_id, "nonexistent").await?;
    assert_eq!(nonexistent, None);
    
    Ok(())
}

#[tokio::test]
async fn test_session_cleanup() -> Result<()> {
    let manager = MockSessionManager::with_config(10, Duration::from_millis(100));
    
    // Create sessions
    let session1 = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    let session2 = manager.create_session("charlie".to_string(), "dave".to_string()).await?;
    
    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // Create a new session (should not be expired)
    let session3 = manager.create_session("eve".to_string(), "frank".to_string()).await?;
    
    // Cleanup expired sessions
    let cleaned_up = manager.cleanup_expired_sessions().await?;
    assert_eq!(cleaned_up, 2); // session1 and session2 should be expired
    
    // Verify remaining sessions
    let total_sessions = manager.count_sessions().await?;
    assert_eq!(total_sessions, 1); // only session3 should remain
    
    let remaining_session = manager.get_session(&session3).await?;
    assert!(remaining_session.is_some());
    
    Ok(())
}

#[tokio::test]
async fn test_session_export() -> Result<()> {
    let manager = MockSessionManager::new();
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    
    // Export session
    let exported_data = manager.export_session(&session_id).await?;
    assert!(!exported_data.is_empty());
    
    // Verify exported data contains session information
    let exported_string = String::from_utf8_lossy(&exported_data);
    assert!(exported_string.contains("alice"));
    assert!(exported_string.contains("bob"));
    
    Ok(())
}

#[tokio::test]
async fn test_session_statistics() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Create sessions with different states
    let session1 = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    let session2 = manager.create_session("charlie".to_string(), "dave".to_string()).await?;
    let session3 = manager.create_session("eve".to_string(), "frank".to_string()).await?;
    
    manager.activate_session(&session1).await?;
    manager.activate_session(&session2).await?;
    manager.suspend_session(&session3).await?;
    
    // Add some messages
    manager.increment_message_count(&session1).await?;
    manager.increment_message_count(&session1).await?;
    manager.increment_message_count(&session2).await?;
    
    // Get statistics
    let stats = manager.get_session_statistics().await?;
    assert_eq!(stats.total_sessions, 3);
    assert_eq!(stats.active_sessions, 2);
    assert_eq!(stats.suspended_sessions, 1);
    assert_eq!(stats.total_messages, 3);
    assert!(stats.oldest_session_age >= 0);
    assert!(stats.newest_session_age >= 0);
    
    Ok(())
}

#[tokio::test]
async fn test_find_session_by_participants() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Create session
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    
    // Find session by participants (both directions)
    let found1 = manager.find_session_by_participants("alice", "bob").await?;
    assert_eq!(found1, Some(session_id.clone()));
    
    let found2 = manager.find_session_by_participants("bob", "alice").await?;
    assert_eq!(found2, Some(session_id));
    
    // Try to find non-existent session
    let not_found = manager.find_session_by_participants("alice", "charlie").await?;
    assert_eq!(not_found, None);
    
    Ok(())
}

#[tokio::test]
async fn test_bulk_terminate_user_sessions() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Create multiple sessions for alice
    let _session1 = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    let _session2 = manager.create_session("alice".to_string(), "charlie".to_string()).await?;
    let _session3 = manager.create_session("dave".to_string(), "alice".to_string()).await?;
    let session4 = manager.create_session("eve".to_string(), "frank".to_string()).await?;
    
    // Terminate all alice's sessions
    let terminated_count = manager.bulk_terminate_user_sessions("alice").await?;
    assert_eq!(terminated_count, 3);
    
    // Verify alice has no sessions
    let alice_sessions = manager.get_user_sessions("alice").await?;
    assert!(alice_sessions.is_empty());
    
    // Verify other sessions still exist
    let remaining_session = manager.get_session(&session4).await?;
    assert!(remaining_session.is_some());
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_session_operations() -> Result<()> {
    let manager = std::sync::Arc::new(MockSessionManager::new());
    let mut handles = Vec::new();
    
    // Spawn multiple concurrent operations
    for i in 0..10 {
        let manager_clone = manager.clone();
        let alice_id = format!("alice_{}", i);
        let bob_id = format!("bob_{}", i);
        
        let handle = tokio::spawn(async move {
            // Create session
            let session_id = manager_clone.create_session(alice_id, bob_id).await?;
            
            // Activate session
            manager_clone.activate_session(&session_id).await?;
            
            // Increment message count
            manager_clone.increment_message_count(&session_id).await?;
            manager_clone.increment_message_count(&session_id).await?;
            
            // Set metadata
            manager_clone.set_session_metadata(&session_id, "test".to_string(), "value".to_string()).await?;
            
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
    assert_eq!(session_ids.len(), 10);
    
    let total_sessions = manager.count_sessions().await?;
    assert_eq!(total_sessions, 10);
    
    let active_sessions = manager.count_sessions_by_state(MockSessionState::Active).await?;
    assert_eq!(active_sessions, 10);
    
    Ok(())
}

#[tokio::test]
async fn test_session_error_handling() -> Result<()> {
    let manager = MockSessionManager::new();
    
    // Test operations on non-existent session
    let result = manager.get_session("nonexistent").await?;
    assert!(result.is_none());
    
    let result = manager.activate_session("nonexistent").await;
    assert!(result.is_err());
    
    let result = manager.increment_message_count("nonexistent").await;
    assert!(result.is_err());
    
    let result = manager.set_session_metadata("nonexistent", "key".to_string(), "value".to_string()).await;
    assert!(result.is_err());
    
    let result = manager.export_session("nonexistent").await;
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_session_activity_tracking() -> Result<()> {
    let manager = MockSessionManager::new();
    let session_id = manager.create_session("alice".to_string(), "bob".to_string()).await?;
    
    let session1 = manager.get_session(&session_id).await?.unwrap();
    let initial_activity = session1.last_activity();
    
    // Wait a bit and update activity
    tokio::time::sleep(Duration::from_millis(10)).await;
    manager.increment_message_count(&session_id).await?;
    
    let session2 = manager.get_session(&session_id).await?.unwrap();
    let updated_activity = session2.last_activity();
    
    assert!(updated_activity > initial_activity);
    
    Ok(())
}