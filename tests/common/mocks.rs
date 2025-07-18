//! Mock implementations for testing Signal Protocol components
//! 
//! This module provides mock implementations of various traits and components
//! to enable isolated unit testing without external dependencies.

use signal_crypto_lib::*;
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;

/// Mock implementation of a key store for testing
#[derive(Debug, Clone)]
pub struct MockKeyStore {
    keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    fail_operations: Arc<Mutex<bool>>,
}

impl MockKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            fail_operations: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_keys(keys: HashMap<String, Vec<u8>>) -> Self {
        Self {
            keys: Arc::new(Mutex::new(keys)),
            fail_operations: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidKey("Mock failure".to_string()));
        }
        
        self.keys.lock().unwrap().insert(key_id.to_string(), key_data.to_vec());
        Ok(())
    }

    pub fn get_key(&self, key_id: &str) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidKey("Mock failure".to_string()));
        }
        
        Ok(self.keys.lock().unwrap().get(key_id).cloned())
    }

    pub fn delete_key(&self, key_id: &str) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidKey("Mock failure".to_string()));
        }
        
        self.keys.lock().unwrap().remove(key_id);
        Ok(())
    }

    pub fn list_keys(&self) -> Result<Vec<String>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidKey("Mock failure".to_string()));
        }
        
        Ok(self.keys.lock().unwrap().keys().cloned().collect())
    }

    pub fn clear(&self) {
        self.keys.lock().unwrap().clear();
    }

    pub fn key_count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

/// Mock implementation of a session store for testing
#[derive(Debug, Clone)]
pub struct MockSessionStore {
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    fail_operations: Arc<Mutex<bool>>,
}

impl MockSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            fail_operations: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn store_session(&self, session_id: &str, session: SessionState) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::SessionNotFound);
        }
        
        self.sessions.lock().unwrap().insert(session_id.to_string(), session);
        Ok(())
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionState>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::SessionNotFound);
        }
        
        Ok(self.sessions.lock().unwrap().get(session_id).cloned())
    }

    pub fn delete_session(&self, session_id: &str) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::SessionNotFound);
        }
        
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }

    pub fn list_sessions(&self) -> Result<Vec<String>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::SessionNotFound);
        }
        
        Ok(self.sessions.lock().unwrap().keys().cloned().collect())
    }

    pub fn clear(&self) {
        self.sessions.lock().unwrap().clear();
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

/// Mock implementation of a message store for testing
#[derive(Debug, Clone)]
pub struct MockMessageStore {
    messages: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
    fail_operations: Arc<Mutex<bool>>,
}

impl MockMessageStore {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(HashMap::new())),
            fail_operations: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn store_message(&self, session_id: &str, message: &[u8]) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidMessage("Mock failure".to_string()));
        }
        
        self.messages.lock().unwrap()
            .entry(session_id.to_string())
            .or_insert_with(Vec::new)
            .push(message.to_vec());
        Ok(())
    }

    pub fn get_messages(&self, session_id: &str) -> Result<Vec<Vec<u8>>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidMessage("Mock failure".to_string()));
        }
        
        Ok(self.messages.lock().unwrap()
            .get(session_id)
            .cloned()
            .unwrap_or_default())
    }

    pub fn clear_messages(&self, session_id: &str) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::InvalidMessage("Mock failure".to_string()));
        }
        
        self.messages.lock().unwrap().remove(session_id);
        Ok(())
    }

    pub fn message_count(&self, session_id: &str) -> usize {
        self.messages.lock().unwrap()
            .get(session_id)
            .map(|msgs| msgs.len())
            .unwrap_or(0)
    }

    pub fn total_message_count(&self) -> usize {
        self.messages.lock().unwrap()
            .values()
            .map(|msgs| msgs.len())
            .sum()
    }
}

/// Mock implementation of a network transport for testing
#[derive(Debug, Clone)]
pub struct MockNetworkTransport {
    sent_messages: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    received_messages: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
    fail_operations: Arc<Mutex<bool>>,
    latency_ms: Arc<Mutex<u64>>,
}

impl MockNetworkTransport {
    pub fn new() -> Self {
        Self {
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            received_messages: Arc::new(Mutex::new(HashMap::new())),
            fail_operations: Arc::new(Mutex::new(false)),
            latency_ms: Arc::Mutex::new(0),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn set_latency(&self, latency_ms: u64) {
        *self.latency_ms.lock().unwrap() = latency_ms;
    }

    pub async fn send_message(&self, destination: &str, message: &[u8]) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::NetworkError("Mock network failure".to_string()));
        }

        // Simulate latency
        let latency = *self.latency_ms.lock().unwrap();
        if latency > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(latency)).await;
        }

        self.sent_messages.lock().unwrap().push((destination.to_string(), message.to_vec()));
        
        // Simulate message delivery to destination
        self.received_messages.lock().unwrap()
            .entry(destination.to_string())
            .or_insert_with(Vec::new)
            .push(message.to_vec());

        Ok(())
    }

    pub fn get_sent_messages(&self) -> Vec<(String, Vec<u8>)> {
        self.sent_messages.lock().unwrap().clone()
    }

    pub fn get_received_messages(&self, destination: &str) -> Vec<Vec<u8>> {
        self.received_messages.lock().unwrap()
            .get(destination)
            .cloned()
            .unwrap_or_default()
    }

    pub fn clear_messages(&self) {
        self.sent_messages.lock().unwrap().clear();
        self.received_messages.lock().unwrap().clear();
    }

    pub fn sent_message_count(&self) -> usize {
        self.sent_messages.lock().unwrap().len()
    }
}

/// Mock implementation of a random number generator for testing
#[derive(Debug, Clone)]
pub struct MockRng {
    values: Arc<Mutex<Vec<u8>>>,
    index: Arc<Mutex<usize>>,
}

impl MockRng {
    pub fn new(values: Vec<u8>) -> Self {
        Self {
            values: Arc::new(Mutex::new(values)),
            index: Arc::new(Mutex::new(0)),
        }
    }

    pub fn with_repeating_pattern(pattern: &[u8]) -> Self {
        let mut values = Vec::new();
        for _ in 0..1000 {  // Repeat pattern 1000 times
            values.extend_from_slice(pattern);
        }
        Self::new(values)
    }

    pub fn with_zeros(count: usize) -> Self {
        Self::new(vec![0; count])
    }

    pub fn with_ones(count: usize) -> Self {
        Self::new(vec![1; count])
    }

    pub fn fill_bytes(&self, dest: &mut [u8]) {
        let mut values = self.values.lock().unwrap();
        let mut index = self.index.lock().unwrap();
        
        for byte in dest.iter_mut() {
            if *index < values.len() {
                *byte = values[*index];
                *index += 1;
            } else {
                *byte = 0; // Default to zero if we run out of values
            }
        }
    }

    pub fn reset(&self) {
        *self.index.lock().unwrap() = 0;
    }

    pub fn set_values(&self, values: Vec<u8>) {
        *self.values.lock().unwrap() = values;
        *self.index.lock().unwrap() = 0;
    }
}

/// Mock implementation of a time provider for testing
#[derive(Debug, Clone)]
pub struct MockTimeProvider {
    current_time: Arc<Mutex<std::time::SystemTime>>,
    auto_advance: Arc<Mutex<bool>>,
    advance_amount: Arc<Mutex<std::time::Duration>>,
}

impl MockTimeProvider {
    pub fn new(initial_time: std::time::SystemTime) -> Self {
        Self {
            current_time: Arc::new(Mutex::new(initial_time)),
            auto_advance: Arc::new(Mutex::new(false)),
            advance_amount: Arc::new(Mutex::new(std::time::Duration::from_secs(1))),
        }
    }

    pub fn now() -> Self {
        Self::new(std::time::SystemTime::now())
    }

    pub fn unix_epoch() -> Self {
        Self::new(std::time::UNIX_EPOCH)
    }

    pub fn set_time(&self, time: std::time::SystemTime) {
        *self.current_time.lock().unwrap() = time;
    }

    pub fn advance_time(&self, duration: std::time::Duration) {
        let mut current = self.current_time.lock().unwrap();
        *current = *current + duration;
    }

    pub fn set_auto_advance(&self, enabled: bool, amount: std::time::Duration) {
        *self.auto_advance.lock().unwrap() = enabled;
        *self.advance_amount.lock().unwrap() = amount;
    }

    pub fn get_time(&self) -> std::time::SystemTime {
        let time = *self.current_time.lock().unwrap();
        
        // Auto-advance if enabled
        if *self.auto_advance.lock().unwrap() {
            let advance = *self.advance_amount.lock().unwrap();
            *self.current_time.lock().unwrap() = time + advance;
        }
        
        time
    }

    pub fn elapsed_since(&self, earlier: std::time::SystemTime) -> std::time::Duration {
        self.get_time().duration_since(earlier).unwrap_or(std::time::Duration::ZERO)
    }
}

/// Mock implementation of a database for testing
#[derive(Debug, Clone)]
pub struct MockDatabase {
    data: Arc<Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
    fail_operations: Arc<Mutex<bool>>,
    transaction_count: Arc<Mutex<usize>>,
}

impl MockDatabase {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            fail_operations: Arc::new(Mutex::new(false)),
            transaction_count: Arc::new(Mutex::new(0)),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn store(&self, table: &str, key: &str, value: &[u8]) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::DatabaseError("Mock database failure".to_string()));
        }

        self.data.lock().unwrap()
            .entry(table.to_string())
            .or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_vec());
        
        Ok(())
    }

    pub fn get(&self, table: &str, key: &str) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::DatabaseError("Mock database failure".to_string()));
        }

        Ok(self.data.lock().unwrap()
            .get(table)
            .and_then(|t| t.get(key))
            .cloned())
    }

    pub fn delete(&self, table: &str, key: &str) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::DatabaseError("Mock database failure".to_string()));
        }

        if let Some(table_data) = self.data.lock().unwrap().get_mut(table) {
            table_data.remove(key);
        }
        
        Ok(())
    }

    pub fn list_keys(&self, table: &str) -> Result<Vec<String>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::DatabaseError("Mock database failure".to_string()));
        }

        Ok(self.data.lock().unwrap()
            .get(table)
            .map(|t| t.keys().cloned().collect())
            .unwrap_or_default())
    }

    pub fn begin_transaction(&self) -> Result<MockTransaction, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::DatabaseError("Mock transaction failure".to_string()));
        }

        *self.transaction_count.lock().unwrap() += 1;
        Ok(MockTransaction::new(self.clone()))
    }

    pub fn clear(&self) {
        self.data.lock().unwrap().clear();
    }

    pub fn table_count(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn key_count(&self, table: &str) -> usize {
        self.data.lock().unwrap()
            .get(table)
            .map(|t| t.len())
            .unwrap_or(0)
    }

    pub fn transaction_count(&self) -> usize {
        *self.transaction_count.lock().unwrap()
    }
}

/// Mock database transaction
#[derive(Debug)]
pub struct MockTransaction {
    database: MockDatabase,
    committed: bool,
    operations: Vec<TransactionOperation>,
}

#[derive(Debug, Clone)]
enum TransactionOperation {
    Store { table: String, key: String, value: Vec<u8> },
    Delete { table: String, key: String },
}

impl MockTransaction {
    fn new(database: MockDatabase) -> Self {
        Self {
            database,
            committed: false,
            operations: Vec::new(),
        }
    }

    pub fn store(&mut self, table: &str, key: &str, value: &[u8]) -> Result<(), SignalProtocolError> {
        self.operations.push(TransactionOperation::Store {
            table: table.to_string(),
            key: key.to_string(),
            value: value.to_vec(),
        });
        Ok(())
    }

    pub fn delete(&mut self, table: &str, key: &str) -> Result<(), SignalProtocolError> {
        self.operations.push(TransactionOperation::Delete {
            table: table.to_string(),
            key: key.to_string(),
        });
        Ok(())
    }

    pub fn commit(mut self) -> Result<(), SignalProtocolError> {
        if *self.database.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::DatabaseError("Mock commit failure".to_string()));
        }

        for operation in &self.operations {
            match operation {
                TransactionOperation::Store { table, key, value } => {
                    self.database.store(table, key, value)?;
                }
                TransactionOperation::Delete { table, key } => {
                    self.database.delete(table, key)?;
                }
            }
        }

        self.committed = true;
        Ok(())
    }

    pub fn rollback(self) -> Result<(), SignalProtocolError> {
        // In a mock, rollback just discards the operations
        Ok(())
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

/// Mock implementation of a cryptographic provider for testing
#[derive(Debug, Clone)]
pub struct MockCryptoProvider {
    fail_operations: Arc<Mutex<bool>>,
    weak_keys: Arc<Mutex<bool>>,
    deterministic: Arc<Mutex<bool>>,
}

impl MockCryptoProvider {
    pub fn new() -> Self {
        Self {
            fail_operations: Arc::new(Mutex::new(false)),
            weak_keys: Arc::new(Mutex::new(false)),
            deterministic: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn set_weak_keys(&self, use_weak_keys: bool) {
        *self.weak_keys.lock().unwrap() = use_weak_keys;
    }

    pub fn set_deterministic(&self, deterministic: bool) {
        *self.deterministic.lock().unwrap() = deterministic;
    }

    pub fn generate_key_pair(&self) -> Result<(Vec<u8>, Vec<u8>), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::CryptographicError("Mock crypto failure".to_string()));
        }

        if *self.weak_keys.lock().unwrap() {
            // Return weak/predictable keys for testing
            return Ok((vec![1; 32], vec![2; 32]));
        }

        if *self.deterministic.lock().unwrap() {
            // Return deterministic keys for reproducible tests
            return Ok((vec![0xAA; 32], vec![0xBB; 32]));
        }

        // Return "random" keys (actually deterministic for testing)
        let private_key = (0..32).map(|i| (i * 7) as u8).collect();
        let public_key = (0..32).map(|i| (i * 11) as u8).collect();
        
        Ok((private_key, public_key))
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::CryptographicError("Mock encryption failure".to_string()));
        }

        // Simple XOR encryption for testing
        let mut ciphertext = Vec::new();
        for (i, &byte) in plaintext.iter().enumerate() {
            let key_byte = key[i % key.len()];
            ciphertext.push(byte ^ key_byte);
        }

        Ok(ciphertext)
    }

    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::CryptographicError("Mock decryption failure".to_string()));
        }

        // XOR decryption (same as encryption for XOR)
        self.encrypt(key, ciphertext)
    }

    pub fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::CryptographicError("Mock signing failure".to_string()));
        }

        // Simple mock signature
        let mut signature = Vec::new();
        signature.extend_from_slice(&private_key[..16]); // First 16 bytes of private key
        signature.extend_from_slice(&message[..std::cmp::min(16, message.len())]); // First 16 bytes of message
        
        Ok(signature)
    }

    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::CryptographicError("Mock verification failure".to_string()));
        }

        if signature.len() < 32 {
            return Ok(false);
        }

        // Mock verification logic
        let expected_key_part = &signature[..16];
        let expected_msg_part = &signature[16..32];
        let actual_msg_part = &message[..std::cmp::min(16, message.len())];

        // This is a very simplified mock verification
        Ok(expected_key_part == &public_key[..16] && expected_msg_part == actual_msg_part)
    }

    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::CryptographicError("Mock hashing failure".to_string()));
        }

        // Simple mock hash (sum of bytes)
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        Ok(sum.to_be_bytes().to_vec())
    }
}

/// Mock implementation of an audit logger for testing
#[derive(Debug, Clone)]
pub struct MockAuditLogger {
    logs: Arc<Mutex<Vec<AuditLogEntry>>>,
    fail_operations: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub timestamp: std::time::SystemTime,
    pub level: String,
    pub event: String,
    pub details: HashMap<String, String>,
}

impl MockAuditLogger {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
            fail_operations: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_fail_operations(&self, should_fail: bool) {
        *self.fail_operations.lock().unwrap() = should_fail;
    }

    pub fn log(&self, level: &str, event: &str, details: HashMap<String, String>) -> Result<(), SignalProtocolError> {
        if *self.fail_operations.lock().unwrap() {
            return Err(SignalProtocolError::AuditError("Mock audit failure".to_string()));
        }

        let entry = AuditLogEntry {
            timestamp: std::time::SystemTime::now(),
            level: level.to_string(),
            event: event.to_string(),
            details,
        };

        self.logs.lock().unwrap().push(entry);
        Ok(())
    }

    pub fn get_logs(&self) -> Vec<AuditLogEntry> {
        self.logs.lock().unwrap().clone()
    }

    pub fn get_logs_by_level(&self, level: &str) -> Vec<AuditLogEntry> {
        self.logs.lock().unwrap()
            .iter()
            .filter(|entry| entry.level == level)
            .cloned()
            .collect()
    }

    pub fn get_logs_by_event(&self, event: &str) -> Vec<AuditLogEntry> {
        self.logs.lock().unwrap()
            .iter()
            .filter(|entry| entry.event == event)
            .cloned()
            .collect()
    }

    pub fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
    }

    pub fn log_count(&self) -> usize {
        self.logs.lock().unwrap().len()
    }

    pub fn has_log_with_event(&self, event: &str) -> bool {
        self.logs.lock().unwrap()
            .iter()
            .any(|entry| entry.event == event)
    }

    pub fn has_log_with_detail(&self, key: &str, value: &str) -> bool {
        self.logs.lock().unwrap()
            .iter()
            .any(|entry| entry.details.get(key) == Some(&value.to_string()))
    }
}

/// Utility functions for creating mock objects
pub struct MockFactory;

impl MockFactory {
    /// Create a complete mock test environment
    pub fn create_test_environment() -> MockTestEnvironment {
        MockTestEnvironment {
            key_store: MockKeyStore::new(),
            session_store: MockSessionStore::new(),
            message_store: MockMessageStore::new(),
            network_transport: MockNetworkTransport::new(),
            database: MockDatabase::new(),
            crypto_provider: MockCryptoProvider::new(),
            audit_logger: MockAuditLogger::new(),
            time_provider: MockTimeProvider::now(),
            rng: MockRng::new(vec![]),
        }
    }

    /// Create a mock environment with pre-configured failure modes
    pub fn create_failing_environment() -> MockTestEnvironment {
        let env = Self::create_test_environment();
        env.set_all_fail_operations(true);
        env
    }

    /// Create a mock environment with deterministic behavior
    pub fn create_deterministic_environment() -> MockTestEnvironment {
        let env = Self::create_test_environment();
        env.crypto_provider.set_deterministic(true);
        env.time_provider.set_time(std::time::UNIX_EPOCH);
        env.rng.set_values((0..255).cycle().take(1000).collect());
        env
    }
}

/// Complete mock test environment
#[derive(Debug, Clone)]
pub struct MockTestEnvironment {
    pub key_store: MockKeyStore,
    pub session_store: MockSessionStore,
    pub message_store: MockMessageStore,
    pub network_transport: MockNetworkTransport,
    pub database: MockDatabase,
    pub crypto_provider: MockCryptoProvider,
    pub audit_logger: MockAuditLogger,
    pub time_provider: MockTimeProvider,
    pub rng: MockRng,
}

impl MockTestEnvironment {
    pub fn set_all_fail_operations(&self, should_fail: bool) {
        self.key_store.set_fail_operations(should_fail);
        self.session_store.set_fail_operations(should_fail);
        self.message_store.set_fail_operations(should_fail);
        self.network_transport.set_fail_operations(should_fail);
        self.database.set_fail_operations(should_fail);
        self.crypto_provider.set_fail_operations(should_fail);
        self.audit_logger.set_fail_operations(should_fail);
    }

    pub fn clear_all_data(&self) {
        self.key_store.clear();
        self.session_store.clear();
        self.network_transport.clear_messages();
        self.database.clear();
        self.audit_logger.clear_logs();
        self.rng.reset();
    }

    pub fn get_total_operation_count(&self) -> usize {
        self.key_store.key_count() +
        self.session_store.session_count() +
        self.message_store.total_message_count() +
        self.network_transport.sent_message_count() +
        self.database.table_count() +
        self.audit_logger.log_count()
    }
}

/// Macro for creating mock objects