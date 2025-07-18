//! Session Management and Storage
//! 
//! This module provides persistent session storage, lifecycle management,
//! and enhanced security features for Signal Protocol sessions.

use crate::types::*;
use crate::protocol::sesame::GroupSessionState;
use rusqlite::{Connection, Result as SqlResult, params};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug)]
pub enum SessionManagerError {
    DatabaseError(String),
    SerializationError(String),
    SessionNotFound,
    InvalidSession,
    StorageError(String),
    SecurityViolation(String),
}

impl Clone for SessionManagerError {
    fn clone(&self) -> Self {
        match self {
            SessionManagerError::DatabaseError(msg) => SessionManagerError::DatabaseError(msg.clone()),
            SessionManagerError::SerializationError(msg) => SessionManagerError::SerializationError(msg.clone()),
            SessionManagerError::SessionNotFound => SessionManagerError::SessionNotFound,
            SessionManagerError::InvalidSession => SessionManagerError::InvalidSession,
            SessionManagerError::StorageError(msg) => SessionManagerError::StorageError(msg.clone()),
            SessionManagerError::SecurityViolation(msg) => SessionManagerError::SecurityViolation(msg.clone()),
        }
    }
}

impl std::fmt::Display for SessionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionManagerError::DatabaseError(e) => write!(f, "Database error: {}", e),
            SessionManagerError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            SessionManagerError::SessionNotFound => write!(f, "Session not found"),
            SessionManagerError::InvalidSession => write!(f, "Invalid session"),
            SessionManagerError::StorageError(e) => write!(f, "Storage error: {}", e),
            SessionManagerError::SecurityViolation(e) => write!(f, "Security violation: {}", e),
        }
    }
}

impl std::error::Error for SessionManagerError {}

impl From<rusqlite::Error> for SessionManagerError {
    fn from(error: rusqlite::Error) -> Self {
        SessionManagerError::DatabaseError(error.to_string())
    }
}

impl From<serde_json::Error> for SessionManagerError {
    fn from(error: serde_json::Error) -> Self {
        SessionManagerError::SerializationError(error.to_string())
    }
}

/// Metadata for stored sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: String,
    pub remote_identity: String,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub message_count: u64,
    pub session_type: SessionType,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    DoubleRatchet,
    GroupSession,
}

/// Encrypted session data for storage
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedSessionData {
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
}

/// Session backup data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBackup {
    pub backup_id: String,
    pub created_at: DateTime<Utc>,
    pub sessions: Vec<(SessionMetadata, EncryptedSessionData)>,
    pub checksum: Vec<u8>,
}

/// Main session manager
pub struct SessionManager {
    db: Connection,
    storage_key: [u8; 32],
    max_sessions: usize,
    session_ttl: Duration,
    cleanup_interval: Duration,
    last_cleanup: DateTime<Utc>,
}

impl SessionManager {
    /// Create a new session manager with the specified database path
    pub fn new(db_path: Option<PathBuf>, storage_key: [u8; 32]) -> Result<Self, SessionManagerError> {
        let db_path = db_path.unwrap_or_else(|| {
            let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push("signal_sessions");
            std::fs::create_dir_all(&path).ok();
            path.push("sessions.db");
            path
        });

        let db = Connection::open(db_path)?;
        
        let mut manager = SessionManager {
            db,
            storage_key,
            max_sessions: 1000,
            session_ttl: Duration::days(30),
            cleanup_interval: Duration::hours(24),
            last_cleanup: Utc::now(),
        };

        manager.initialize_database()?;
        Ok(manager)
    }

    /// Initialize the database schema
    fn initialize_database(&mut self) -> Result<(), SessionManagerError> {
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                remote_identity TEXT NOT NULL,
                session_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used TEXT NOT NULL,
                message_count INTEGER NOT NULL DEFAULT 0,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                encrypted_data BLOB NOT NULL,
                nonce BLOB NOT NULL,
                salt BLOB NOT NULL
            )",
            [],
        )?;

        self.db.execute(
            "CREATE TABLE IF NOT EXISTS group_sessions (
                group_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                nonce BLOB NOT NULL,
                salt BLOB NOT NULL,
                PRIMARY KEY (group_id, sender_id)
            )",
            [],
        )?;

        self.db.execute(
            "CREATE TABLE IF NOT EXISTS session_backups (
                backup_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                backup_data BLOB NOT NULL,
                checksum BLOB NOT NULL
            )",
            [],
        )?;

        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_last_used ON sessions(last_used)",
            [],
        )?;

        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_group_sessions_last_used ON group_sessions(last_used)",
            [],
        )?;

        Ok(())
    }

    /// Store a Double Ratchet session
    pub fn store_session(
        &mut self,
        session: &SessionState,
        remote_identity: &str,
    ) -> Result<(), SessionManagerError> {
        self.cleanup_if_needed()?;

        let metadata = SessionMetadata {
            session_id: session.session_id.clone(),
            remote_identity: remote_identity.to_string(),
            created_at: Utc::now(),
            last_used: Utc::now(),
            message_count: (session.n_send + session.n_recv) as u64,
            session_type: SessionType::DoubleRatchet,
            is_active: true,
        };

        let encrypted_data = self.encrypt_session_data(session)?;

        self.db.execute(
            "INSERT OR REPLACE INTO sessions 
             (session_id, remote_identity, session_type, created_at, last_used, 
              message_count, is_active, encrypted_data, nonce, salt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                metadata.session_id,
                metadata.remote_identity,
                serde_json::to_string(&metadata.session_type)?,
                metadata.created_at.to_rfc3339(),
                metadata.last_used.to_rfc3339(),
                metadata.message_count as i64,
                metadata.is_active,
                encrypted_data.encrypted_data,
                encrypted_data.nonce,
                encrypted_data.salt,
            ],
        )?;

        Ok(())
    }

    /// Load a Double Ratchet session
    pub fn load_session(&mut self, session_id: &str) -> Result<SessionState, SessionManagerError> {
        let mut stmt = self.db.prepare(
            "SELECT encrypted_data, nonce, salt FROM sessions WHERE session_id = ?1 AND is_active = 1"
        )?;

        let encrypted_data: EncryptedSessionData = stmt.query_row(params![session_id], |row| {
            Ok(EncryptedSessionData {
                encrypted_data: row.get(0)?,
                nonce: row.get(1)?,
                salt: row.get(2)?,
            })
        }).map_err(|_| SessionManagerError::SessionNotFound)?;

        let session: SessionState = self.decrypt_session_data(&encrypted_data)?;

        // Update last_used timestamp
        self.db.execute(
            "UPDATE sessions SET last_used = ?1, message_count = ?2 WHERE session_id = ?3",
            params![
                Utc::now().to_rfc3339(),
                (session.n_send + session.n_recv) as i64,
                session_id
            ],
        )?;

        Ok(session)
    }

    /// Store a group session
    pub fn store_group_session(
        &mut self,
        group_session: &GroupSessionState,
    ) -> Result<(), SessionManagerError> {
        self.cleanup_if_needed()?;

        let encrypted_data = self.encrypt_group_session_data(group_session)?;

        self.db.execute(
            "INSERT OR REPLACE INTO group_sessions 
             (group_id, session_id, sender_id, created_at, last_used, encrypted_data, nonce, salt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                group_session.group_id,
                format!("{}_{}", group_session.group_id, group_session.own_sender_id),
                group_session.own_sender_id,
                Utc::now().to_rfc3339(),
                Utc::now().to_rfc3339(),
                encrypted_data.encrypted_data,
                encrypted_data.nonce,
                encrypted_data.salt,
            ],
        )?;

        Ok(())
    }

    /// Load a group session
    pub fn load_group_session(
        &mut self,
        group_id: &str,
        sender_id: &str,
    ) -> Result<GroupSessionState, SessionManagerError> {
        let mut stmt = self.db.prepare(
            "SELECT encrypted_data, nonce, salt FROM group_sessions 
             WHERE group_id = ?1 AND sender_id = ?2"
        )?;

        let encrypted_data: EncryptedSessionData = stmt.query_row(params![group_id, sender_id], |row| {
            Ok(EncryptedSessionData {
                encrypted_data: row.get(0)?,
                nonce: row.get(1)?,
                salt: row.get(2)?,
            })
        }).map_err(|_| SessionManagerError::SessionNotFound)?;

        let group_session: GroupSessionState = self.decrypt_group_session_data(&encrypted_data)?;

        // Update last_used timestamp
        self.db.execute(
            "UPDATE group_sessions SET last_used = ?1 WHERE group_id = ?2 AND sender_id = ?3",
            params![Utc::now().to_rfc3339(), group_id, sender_id],
        )?;

        Ok(group_session)
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Result<Vec<SessionMetadata>, SessionManagerError> {
        let mut stmt = self.db.prepare(
            "SELECT session_id, remote_identity, session_type, created_at, last_used, 
                    message_count, is_active 
             FROM sessions WHERE is_active = 1 ORDER BY last_used DESC"
        )?;

        let sessions = stmt.query_map([], |row| {
            Ok(SessionMetadata {
                session_id: row.get(0)?,
                remote_identity: row.get(1)?,
                session_type: serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or(SessionType::DoubleRatchet),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .unwrap_or_else(|_| Utc::now().into()).with_timezone(&Utc),
                last_used: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                    .unwrap_or_else(|_| Utc::now().into()).with_timezone(&Utc),
                message_count: row.get::<_, i64>(5)? as u64,
                is_active: row.get(6)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
    }

    /// Delete a session
    pub fn delete_session(&mut self, session_id: &str) -> Result<(), SessionManagerError> {
        self.db.execute(
            "UPDATE sessions SET is_active = 0 WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(())
    }

    /// Delete a group session
    pub fn delete_group_session(
        &mut self,
        group_id: &str,
        sender_id: &str,
    ) -> Result<(), SessionManagerError> {
        self.db.execute(
            "DELETE FROM group_sessions WHERE group_id = ?1 AND sender_id = ?2",
            params![group_id, sender_id],
        )?;
        Ok(())
    }

    /// Create a backup of all sessions
    pub fn create_backup(&self) -> Result<SessionBackup, SessionManagerError> {
        let sessions = self.list_sessions()?;
        let mut backup_sessions = Vec::new();

        for metadata in sessions {
            if let Ok(encrypted_data) = self.get_encrypted_session_data(&metadata.session_id) {
                backup_sessions.push((metadata, encrypted_data));
            }
        }

        let checksum = self.calculate_backup_checksum(&backup_sessions)?;
        let backup = SessionBackup {
            backup_id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            sessions: backup_sessions,
            checksum,
        };

        // Store backup in database
        let backup_data = serde_json::to_vec(&backup)?;
        self.db.execute(
            "INSERT INTO session_backups (backup_id, created_at, backup_data, checksum)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                backup.backup_id,
                backup.created_at.to_rfc3339(),
                backup_data,
                backup.checksum,
            ],
        )?;

        Ok(backup)
    }

    /// Restore sessions from backup
    pub fn restore_backup(&mut self, backup: &SessionBackup) -> Result<(), SessionManagerError> {
        // Verify backup integrity
        let calculated_checksum = self.calculate_backup_checksum(&backup.sessions)?;
        if calculated_checksum != backup.checksum {
            return Err(SessionManagerError::SecurityViolation(
                "Backup checksum verification failed".to_string()
            ));
        }

        // Restore sessions
        for (metadata, encrypted_data) in &backup.sessions {
            self.db.execute(
                "INSERT OR REPLACE INTO sessions 
                 (session_id, remote_identity, session_type, created_at, last_used, 
                  message_count, is_active, encrypted_data, nonce, salt)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    metadata.session_id,
                    metadata.remote_identity,
                    serde_json::to_string(&metadata.session_type)?,
                    metadata.created_at.to_rfc3339(),
                    metadata.last_used.to_rfc3339(),
                    metadata.message_count as i64,
                    metadata.is_active,
                    encrypted_data.encrypted_data,
                    encrypted_data.nonce,
                    encrypted_data.salt,
                ],
            )?;
        }

        Ok(())
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&mut self) -> Result<usize, SessionManagerError> {
        let cutoff_time = Utc::now() - self.session_ttl;
        
        let deleted = self.db.execute(
            "UPDATE sessions SET is_active = 0 
             WHERE last_used < ?1 AND is_active = 1",
            params![cutoff_time.to_rfc3339()],
        )?;

        let group_deleted = self.db.execute(
            "DELETE FROM group_sessions WHERE last_used < ?1",
            params![cutoff_time.to_rfc3339()],
        )?;

        self.last_cleanup = Utc::now();
        Ok(deleted + group_deleted)
    }

    /// Check if cleanup is needed and perform it
    fn cleanup_if_needed(&mut self) -> Result<(), SessionManagerError> {
        if Utc::now() - self.last_cleanup > self.cleanup_interval {
            self.cleanup_expired_sessions()?;
        }
        Ok(())
    }

    /// Encrypt session data for storage
    fn encrypt_session_data(&self, session: &SessionState) -> Result<EncryptedSessionData, SessionManagerError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};
        use rand::RngCore;

        let data = serde_json::to_vec(session)?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        // Derive encryption key from storage key and salt
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &self.storage_key);
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"SessionEncryption", &mut derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let payload = Payload {
            msg: &data,
            aad: b"SignalSession",
        };

        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| SessionManagerError::StorageError("Encryption failed".to_string()))?;

        Ok(EncryptedSessionData {
            encrypted_data: encrypted,
            nonce: nonce.to_vec(),
            salt: salt.to_vec(),
        })
    }

    /// Decrypt session data from storage
    fn decrypt_session_data(&self, encrypted: &EncryptedSessionData) -> Result<SessionState, SessionManagerError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};

        // Derive decryption key from storage key and salt
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&encrypted.salt), &self.storage_key);
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"SessionEncryption", &mut derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let payload = Payload {
            msg: &encrypted.encrypted_data,
            aad: b"SignalSession",
        };

        let decrypted = cipher.decrypt(Nonce::from_slice(&encrypted.nonce), payload)
            .map_err(|_| SessionManagerError::StorageError("Decryption failed".to_string()))?;

        let session: SessionState = serde_json::from_slice(&decrypted)?;
        Ok(session)
    }

    /// Encrypt group session data for storage
    fn encrypt_group_session_data(&self, session: &GroupSessionState) -> Result<EncryptedSessionData, SessionManagerError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};
        use rand::RngCore;

        let data = serde_json::to_vec(session)?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        // Derive encryption key from storage key and salt
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &self.storage_key);
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"GroupSessionEncryption", &mut derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let payload = Payload {
            msg: &data,
            aad: b"SignalGroupSession",
        };

        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| SessionManagerError::StorageError("Encryption failed".to_string()))?;

        Ok(EncryptedSessionData {
            encrypted_data: encrypted,
            nonce: nonce.to_vec(),
            salt: salt.to_vec(),
        })
    }

    /// Decrypt group session data from storage
    fn decrypt_group_session_data(&self, encrypted: &EncryptedSessionData) -> Result<GroupSessionState, SessionManagerError> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};

        // Derive decryption key from storage key and salt
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&encrypted.salt), &self.storage_key);
        let mut derived_key = [0u8; 32];
        hkdf.expand(b"GroupSessionEncryption", &mut derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| SessionManagerError::StorageError(e.to_string()))?;

        let payload = Payload {
            msg: &encrypted.encrypted_data,
            aad: b"SignalGroupSession",
        };

        let decrypted = cipher.decrypt(Nonce::from_slice(&encrypted.nonce), payload)
            .map_err(|_| SessionManagerError::StorageError("Decryption failed".to_string()))?;

        let session: GroupSessionState = serde_json::from_slice(&decrypted)?;
        Ok(session)
    }

    /// Get encrypted session data for backup
    fn get_encrypted_session_data(&self, session_id: &str) -> Result<EncryptedSessionData, SessionManagerError> {
        let mut stmt = self.db.prepare(
            "SELECT encrypted_data, nonce, salt FROM sessions WHERE session_id = ?1"
        )?;

        let encrypted_data = stmt.query_row(params![session_id], |row| {
            Ok(EncryptedSessionData {
                encrypted_data: row.get(0)?,
                nonce: row.get(1)?,
                salt: row.get(2)?,
            })
        })?;

        Ok(encrypted_data)
    }

    /// Calculate backup checksum
    fn calculate_backup_checksum(&self, sessions: &[(SessionMetadata, EncryptedSessionData)]) -> Result<Vec<u8>, SessionManagerError> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        for (metadata, encrypted_data) in sessions {
            hasher.update(metadata.session_id.as_bytes());
            hasher.update(&encrypted_data.encrypted_data);
            hasher.update(&encrypted_data.nonce);
            hasher.update(&encrypted_data.salt);
        }
        Ok(hasher.finalize().to_vec())
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        let _ = self.cleanup_expired_sessions();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity_keypair;
    use crate::prekey::generate_signed_prekey;
    use crate::protocol::x3dh::{x3dh_alice_init, create_prekey_bundle};
    use std::collections::HashMap;

    #[test]
    fn test_session_manager_creation() {
        let storage_key = [1u8; 32];
        let manager = SessionManager::new(None, storage_key).unwrap();
        assert!(manager.list_sessions().unwrap().is_empty());
    }

    #[test]
    fn test_session_storage_and_retrieval() {
        let storage_key = [2u8; 32];
        let mut manager = SessionManager::new(None, storage_key).unwrap();

        // Create a test session
        let alice_identity = generate_identity_keypair();
        let bob_identity = generate_identity_keypair();
        let bob_signed_prekey = generate_signed_prekey(&bob_identity, 1);
        let bob_bundle = create_prekey_bundle(&bob_identity, 1234, 1, &bob_signed_prekey, None);

        let (_, session) = x3dh_alice_init(&alice_identity, 5678, &bob_bundle).unwrap();

        // Store the session
        manager.store_session(&session, "bob@example.com").unwrap();

        // Retrieve the session
        let loaded_session = manager.load_session(&session.session_id).unwrap();
        assert_eq!(session.session_id, loaded_session.session_id);
        assert_eq!(session.root_key, loaded_session.root_key);
    }

    #[test]
    fn test_group_session_storage() {
        let storage_key = [3u8; 32];
        let mut manager = SessionManager::new(None, storage_key).unwrap();

        // Create a test group session
        let mut group_session = GroupSessionState::new("test-group", "alice");
        group_session.initialize_own_chain().unwrap();

        // Store the group session
        manager.store_group_session(&group_session).unwrap();

        // Retrieve the group session
        let loaded_session = manager.load_group_session("test-group", "alice").unwrap();
        assert_eq!(group_session.group_id, loaded_session.group_id);
        assert_eq!(group_session.own_sender_id, loaded_session.own_sender_id);
    }

    #[test]
    fn test_session_cleanup() {
        let storage_key = [4u8; 32];
        let mut manager = SessionManager::new(None, storage_key).unwrap();
        manager.session_ttl = Duration::seconds(1); // Very short TTL for testing

        // Create and store a session
        let alice_identity = generate_identity_keypair();
        let bob_identity = generate_identity_keypair();
        let bob_signed_prekey = generate_signed_prekey(&bob_identity, 1);
        let bob_bundle = create_prekey_bundle(&bob_identity, 1234, 1, &bob_signed_prekey, None);

        let (_, session) = x3dh_alice_init(&alice_identity, 5678, &bob_bundle).unwrap();
        manager.store_session(&session, "bob@example.com").unwrap();

        // Wait for TTL to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Cleanup should remove the expired session
        let cleaned = manager.cleanup_expired_sessions().unwrap();
        assert!(cleaned > 0);
    }

    #[test]
    fn test_backup_and_restore() {
        use std::fs;
        use std::path::PathBuf;
        
        // Create a temporary database file for this test
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("test_backup_{}.db", uuid::Uuid::new_v4()));
        
        let storage_key = [42u8; 32];
        let mut manager = SessionManager::new(Some(db_path.clone()), storage_key).unwrap();

        // Create and store multiple sessions
        let mut session_ids = Vec::new();
        for i in 0..3 {
            let alice_identity = generate_identity_keypair();
            let bob_identity = generate_identity_keypair();
            let bob_signed_prekey = generate_signed_prekey(&bob_identity, 1);
            let bob_bundle = create_prekey_bundle(&bob_identity, 1234, 1, &bob_signed_prekey, None);

            let (_, session) = x3dh_alice_init(&alice_identity, 5678, &bob_bundle).unwrap();
            session_ids.push(session.session_id.clone());
            manager.store_session(&session, &format!("user{}@example.com", i)).unwrap();
        }

        // Verify we have 3 sessions
        let initial_sessions = manager.list_sessions().unwrap();
        assert_eq!(initial_sessions.len(), 3);

        // Create backup
        let backup = manager.create_backup().unwrap();
        assert_eq!(backup.sessions.len(), 3);

        // Clear sessions by marking them inactive
        for session_id in &session_ids {
            manager.delete_session(session_id).unwrap();
        }

        // Verify sessions are marked as inactive
        let active_sessions = manager.list_sessions().unwrap();
        assert_eq!(active_sessions.len(), 0);

        // Restore backup (this will reactivate the sessions)
        manager.restore_backup(&backup).unwrap();
        let restored_sessions = manager.list_sessions().unwrap();
        assert_eq!(restored_sessions.len(), 3);
        
        // Cleanup
        drop(manager);
        let _ = fs::remove_file(db_path);
    }
}