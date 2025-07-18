// tests/unit/types_and_errors.rs
//! Unit tests for types and error handling

use crate::common::{
    fixtures::*,
    helpers::*,
    assertions::*,
    mocks::*,
};
use std::collections::HashMap;
use std::fmt;
use std::error::Error as StdError;
use serde::{Serialize, Deserialize};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Mock error types for testing
#[derive(Debug, Clone, PartialEq)]
enum MockProtocolError {
    InvalidMessage(String),
    CryptographicError(String),
    NetworkError(String),
    SessionNotFound(String),
    KeyExchangeFailure(String),
    AuthenticationFailure(String),
    SerializationError(String),
    DeserializationError(String),
    InvalidState(String),
    TimeoutError(String),
}

impl fmt::Display for MockProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MockProtocolError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            MockProtocolError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            MockProtocolError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            MockProtocolError::SessionNotFound(msg) => write!(f, "Session not found: {}", msg),
            MockProtocolError::KeyExchangeFailure(msg) => write!(f, "Key exchange failure: {}", msg),
            MockProtocolError::AuthenticationFailure(msg) => write!(f, "Authentication failure: {}", msg),
            MockProtocolError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            MockProtocolError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            MockProtocolError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            MockProtocolError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
        }
    }
}

impl StdError for MockProtocolError {}

// Mock message types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MockMessage {
    id: String,
    sender: String,
    recipient: String,
    content: Vec<u8>,
    timestamp: u64,
    message_type: MockMessageType,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum MockMessageType {
    Text,
    Image,
    Video,
    Audio,
    File,
    System,
    KeyExchange,
    GroupUpdate,
}

impl MockMessage {
    fn new(sender: String, recipient: String, content: Vec<u8>, message_type: MockMessageType) -> Self {
        Self {
            id: format!("msg_{}", rand::random::<u32>()),
            sender,
            recipient,
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            message_type,
            metadata: HashMap::new(),
        }
    }
    
    fn id(&self) -> &str {
        &self.id
    }
    
    fn sender(&self) -> &str {
        &self.sender
    }
    
    fn recipient(&self) -> &str {
        &self.recipient
    }
    
    fn content(&self) -> &[u8] {
        &self.content
    }
    
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
    
    fn message_type(&self) -> &MockMessageType {
        &self.message_type
    }
    
    fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| MockProtocolError::SerializationError(e.to_string()).into())
    }
    
    fn deserialize(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| MockProtocolError::DeserializationError(e.to_string()).into())
    }
    
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(MockProtocolError::InvalidMessage("Empty message ID".to_string()).into());
        }
        
        if self.sender.is_empty() {
            return Err(MockProtocolError::InvalidMessage("Empty sender".to_string()).into());
        }
        
        if self.recipient.is_empty() {
            return Err(MockProtocolError::InvalidMessage("Empty recipient".to_string()).into());
        }
        
        if self.content.is_empty() {
            return Err(MockProtocolError::InvalidMessage("Empty content".to_string()).into());
        }
        
        if self.timestamp == 0 {
            return Err(MockProtocolError::InvalidMessage("Invalid timestamp".to_string()).into());
        }
        
        Ok(())
    }
}

// Mock session state types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum MockSessionState {
    Pending,
    Establishing,
    Active,
    Suspended,
    Terminated,
    Error(String),
}

impl MockSessionState {
    fn is_active(&self) -> bool {
        matches!(self, MockSessionState::Active)
    }
    
    fn is_terminated(&self) -> bool {
        matches!(self, MockSessionState::Terminated)
    }
    
    fn is_error(&self) -> bool {
        matches!(self, MockSessionState::Error(_))
    }
    
    fn can_transition_to(&self, new_state: &MockSessionState) -> bool {
        match (self, new_state) {
            (MockSessionState::Pending, MockSessionState::Establishing) => true,
            (MockSessionState::Establishing, MockSessionState::Active) => true,
            (MockSessionState::Establishing, MockSessionState::Error(_)) => true,
            (MockSessionState::Active, MockSessionState::Suspended) => true,
            (MockSessionState::Active, MockSessionState::Terminated) => true,
            (MockSessionState::Active, MockSessionState::Error(_)) => true,
            (MockSessionState::Suspended, MockSessionState::Active) => true,
            (MockSessionState::Suspended, MockSessionState::Terminated) => true,
            (_, MockSessionState::Error(_)) => true, // Can always transition to error
            _ => false,
        }
    }
}

// Mock key types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MockKey {
    id: String,
    key_data: Vec<u8>,
    key_type: MockKeyType,
    created_at: u64,
    expires_at: Option<u64>,
    usage_count: u64,
    max_usage: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum MockKeyType {
    Identity,
    Prekey,
    SignedPrekey,
    Ephemeral,
    SenderKey,
    ChainKey,
    MessageKey,
}

impl MockKey {
    fn new(key_type: MockKeyType, key_data: Vec<u8>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: format!("key_{}", rand::random::<u32>()),
            key_data,
            key_type,
            created_at: timestamp,
            expires_at: None,
            usage_count: 0,
            max_usage: None,
        }
    }
    
    fn id(&self) -> &str {
        &self.id
    }
    
    fn key_data(&self) -> &[u8] {
        &self.key_data
    }
    
    fn key_type(&self) -> &MockKeyType {
        &self.key_type
    }
    
    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }
    
    fn is_usage_exceeded(&self) -> bool {
        if let Some(max_usage) = self.max_usage {
            self.usage_count >= max_usage
        } else {
            false
        }
    }
    
    fn can_use(&self) -> bool {
        !self.is_expired() && !self.is_usage_exceeded()
    }
    
    fn increment_usage(&mut self) -> Result<()> {
        if !self.can_use() {
            return Err(MockProtocolError::InvalidState("Key cannot be used".to_string()).into());
        }
        
        self.usage_count += 1;
        Ok(())
    }
    
    fn set_expiration(&mut self, expires_at: u64) {
        self.expires_at = Some(expires_at);
    }
    
    fn set_max_usage(&mut self, max_usage: u64) {
        self.max_usage = Some(max_usage);
    }
}

// Mock configuration types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MockConfiguration {
    protocol_version: String,
    encryption_algorithm: String,
    key_derivation_function: String,
    hash_algorithm: String,
    signature_algorithm: String,
    max_message_size: usize,
    session_timeout: u64,
    key_rotation_interval: u64,
    max_skipped_messages: usize,
    enable_forward_secrecy: bool,
    enable_post_compromise_security: bool,
    settings: HashMap<String, ConfigValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum ConfigValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<ConfigValue>),
    Object(HashMap<String, ConfigValue>),
}

impl MockConfiguration {
    fn default() -> Self {
        Self {
            protocol_version: "1.0".to_string(),
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_derivation_function: "HKDF-SHA256".to_string(),
            hash_algorithm: "SHA-256".to_string(),
            signature_algorithm: "Ed25519".to_string(),
            max_message_size: 1024 * 1024, // 1MB
            session_timeout: 3600, // 1 hour
            key_rotation_interval: 86400, // 24 hours
            max_skipped_messages: 1000,
            enable_forward_secrecy: true,
            enable_post_compromise_security: true,
            settings: HashMap::new(),
        }
    }
    
    fn validate(&self) -> Result<()> {
        if self.protocol_version.is_empty() {
            return Err(MockProtocolError::InvalidMessage("Empty protocol version".to_string()).into());
        }
        
        if self.max_message_size == 0 {
            return Err(MockProtocolError::InvalidMessage("Invalid max message size".to_string()).into());
        }
        
        if self.session_timeout == 0 {
            return Err(MockProtocolError::InvalidMessage("Invalid session timeout".to_string()).into());
        }
        
        if self.key_rotation_interval == 0 {
            return Err(MockProtocolError::InvalidMessage("Invalid key rotation interval".to_string()).into());
        }
        
        Ok(())
    }
    
    fn set_setting(&mut self, key: String, value: ConfigValue) {
        self.settings.insert(key, value);
    }
    
    fn get_setting(&self, key: &str) -> Option<&ConfigValue> {
        self.settings.get(key)
    }
    
    fn merge(&mut self, other: &MockConfiguration) {
        // Merge settings from other configuration
        for (key, value) in &other.settings {
            self.settings.insert(key.clone(), value.clone());
        }
    }
}

// Tests for message types
#[test]
fn test_message_creation() -> Result<()> {
    let message = MockMessage::new(
        "alice".to_string(),
        "bob".to_string(),
        b"Hello, Bob!".to_vec(),
        MockMessageType::Text,
    );
    
    assert!(!message.id().is_empty());
    assert_eq!(message.sender(), "alice");
    assert_eq!(message.recipient(), "bob");
    assert_eq!(message.content(), b"Hello, Bob!");
    assert_eq!(message.message_type(), &MockMessageType::Text);
    assert!(message.timestamp() > 0);
    
    Ok(())
}

#[test]
fn test_message_validation() -> Result<()> {
    // Valid message
    let valid_message = MockMessage::new(
        "alice".to_string(),
        "bob".to_string(),
        b"Valid content".to_vec(),
        MockMessageType::Text,
    );
    assert!(valid_message.validate().is_ok());
    
    // Invalid message with empty sender
    let mut invalid_message = valid_message.clone();
    invalid_message.sender = String::new();
    assert!(invalid_message.validate().is_err());
    
    // Invalid message with empty recipient
    let mut invalid_message = valid_message.clone();
    invalid_message.recipient = String::new();
    assert!(invalid_message.validate().is_err());
    
    // Invalid message with empty content
    let mut invalid_message = valid_message.clone();
    invalid_message.content = Vec::new();
    assert!(invalid_message.validate().is_err());
    
    Ok(())
}

#[test]
fn test_message_serialization() -> Result<()> {
    let mut message = MockMessage::new(
        "alice".to_string(),
        "bob".to_string(),
        b"Test message".to_vec(),
        MockMessageType::Text,
    );
    
    message.set_metadata("priority".to_string(), "high".to_string());
    message.set_metadata("encrypted".to_string(), "true".to_string());
    
    // Test serialization
    let serialized = message.serialize()?;
    assert!(!serialized.is_empty());
    
    // Test deserialization
    let deserialized = MockMessage::deserialize(&serialized)?;
    assert_eq!(message, deserialized);
    
    // Test metadata preservation
    assert_eq!(deserialized.get_metadata("priority"), Some(&"high".to_string()));
    assert_eq!(deserialized.get_metadata("encrypted"), Some(&"true".to_string()));
    
    Ok(())
}

#[test]
fn test_message_metadata() -> Result<()> {
    let mut message = MockMessage::new(
        "alice".to_string(),
        "bob".to_string(),
        b"Test message".to_vec(),
        MockMessageType::Text,
    );
    
    // Test setting and getting metadata
    message.set_metadata("key1".to_string(), "value1".to_string());
    message.set_metadata("key2".to_string(), "value2".to_string());
    
    assert_eq!(message.get_metadata("key1"), Some(&"value1".to_string()));
    assert_eq!(message.get_metadata("key2"), Some(&"value2".to_string()));
    assert_eq!(message.get_metadata("nonexistent"), None);
    
    // Test overwriting metadata
    message.set_metadata("key1".to_string(), "new_value1".to_string());
    assert_eq!(message.get_metadata("key1"), Some(&"new_value1".to_string()));
    
    Ok(())
}

// Tests for session state types
#[test]
fn test_session_state_properties() -> Result<()> {
    // Test active state
    let active_state = MockSessionState::Active;
    assert!(active_state.is_active());
    assert!(!active_state.is_terminated());
    assert!(!active_state.is_error());
    
    // Test terminated state
    let terminated_state = MockSessionState::Terminated;
    assert!(!terminated_state.is_active());
    assert!(terminated_state.is_terminated());
    assert!(!terminated_state.is_error());
    
    // Test error state
    let error_state = MockSessionState::Error("Test error".to_string());
    assert!(!error_state.is_active());
    assert!(!error_state.is_terminated());
    assert!(error_state.is_error());
    
    Ok(())
}

#[test]
fn test_session_state_transitions() -> Result<()> {
    let pending = MockSessionState::Pending;
    let establishing = MockSessionState::Establishing;
    let active = MockSessionState::Active;
    let suspended = MockSessionState::Suspended;
    let terminated = MockSessionState::Terminated;
    let error = MockSessionState::Error("Test error".to_string());
    
    // Valid transitions
    assert!(pending.can_transition_to(&establishing));
    assert!(establishing.can_transition_to(&active));
    assert!(establishing.can_transition_to(&error));
    assert!(active.can_transition_to(&suspended));
    assert!(active.can_transition_to(&terminated));
    assert!(active.can_transition_to(&error));
    assert!(suspended.can_transition_to(&active));
    assert!(suspended.can_transition_to(&terminated));
    
    // Invalid transitions
    assert!(!pending.can_transition_to(&active));
    assert!(!pending.can_transition_to(&suspended));
    assert!(!terminated.can_transition_to(&active));
    assert!(!terminated.can_transition_to(&establishing));
    
    // Can always transition to error
    assert!(pending.can_transition_to(&error));
    assert!(establishing.can_transition_to(&error));
    assert!(active.can_transition_to(&error));
    assert!(suspended.can_transition_to(&error));
    assert!(terminated.can_transition_to(&error));
    
    Ok(())
}

// Tests for key types
#[test]
fn test_key_creation() -> Result<()> {
    let key_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let key = MockKey::new(MockKeyType::Identity, key_data.clone());
    
    assert!(!key.id().is_empty());
    assert_eq!(key.key_data(), &key_data);
    assert_eq!(key.key_type(), &MockKeyType::Identity);
    assert!(key.created_at > 0);
    assert_eq!(key.usage_count, 0);
    assert!(key.can_use());
    
    Ok(())
}

#[test]
fn test_key_expiration() -> Result<()> {
    let key_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let mut key = MockKey::new(MockKeyType::Prekey, key_data);
    
    // Key should not be expired initially
    assert!(!key.is_expired());
    assert!(key.can_use());
    
    // Set expiration in the past
    let past_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() - 3600; // 1 hour ago
    
    key.set_expiration(past_time);
    assert!(key.is_expired());
    assert!(!key.can_use());
    
    // Set expiration in the future
    let future_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600; // 1 hour from now
    
    key.set_expiration(future_time);
    assert!(!key.is_expired());
    assert!(key.can_use());
    
    Ok(())
}

#[test]
fn test_key_usage_limits() -> Result<()> {
    let key_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let mut key = MockKey::new(MockKeyType::MessageKey, key_data);
    
    // Set usage limit
    key.set_max_usage(3);
    
    // Use key within limit
    assert!(key.can_use());
    key.increment_usage()?;
    assert_eq!(key.usage_count, 1);
    assert!(key.can_use());
    
    key.increment_usage()?;
    assert_eq!(key.usage_count, 2);
    assert!(key.can_use());
    
    key.increment_usage()?;
    assert_eq!(key.usage_count, 3);
    assert!(!key.can_use()); // Should be at limit
    
    // Try to use beyond limit
    let result = key.increment_usage();
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_key_serialization() -> Result<()> {
    let key_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let mut key = MockKey::new(MockKeyType::SenderKey, key_data);
    
    key.set_expiration(1234567890);
    key.set_max_usage(100);
    key.increment_usage()?;
    
    // Test serialization
    let serialized = serde_json::to_vec(&key)?;
    assert!(!serialized.is_empty());
    
    // Test deserialization
    let deserialized: MockKey = serde_json::from_slice(&serialized)?;
    assert_eq!(key, deserialized);
    
    Ok(())
}

// Tests for configuration types
#[test]
fn test_configuration_creation() -> Result<()> {
    let config = MockConfiguration::default();
    
    assert_eq!(config.protocol_version, "1.0");
    assert_eq!(config.encryption_algorithm, "AES-256-GCM");
    assert_eq!(config.key_derivation_function, "HKDF-SHA256");
    assert_eq!(config.hash_algorithm, "SHA-256");
    assert_eq!(config.signature_algorithm, "Ed25519");
    assert_eq!(config.max_message_size, 1024 * 1024);
    assert_eq!(config.session_timeout, 3600);
    assert_eq!(config.key_rotation_interval, 86400);
    assert_eq!(config.max_skipped_messages, 1000);
    assert!(config.enable_forward_secrecy);
    assert!(config.enable_post_compromise_security);
    
    Ok(())
}

#[test]
fn test_configuration_validation() -> Result<()> {
    let mut config = MockConfiguration::default();
    
    // Valid configuration
    assert!(config.validate().is_ok());
    
    // Invalid protocol version
    config.protocol_version = String::new();
    assert!(config.validate().is_err());
    config.protocol_version = "1.0".to_string();
    
    // Invalid max message size
    config.max_message_size = 0;
    assert!(config.validate().is_err());
    config.max_message_size = 1024;
    
    // Invalid session timeout
    config.session_timeout = 0;
    assert!(config.validate().is_err());
    config.session_timeout = 3600;
    
    // Invalid key rotation interval
    config.key_rotation_interval = 0;
    assert!(config.validate().is_err());
    
    Ok(())
}

#[test]
fn test_configuration_settings() -> Result<()> {
    let mut config = MockConfiguration::default();
    
    // Test setting and getting values
    config.set_setting("debug_mode".to_string(), ConfigValue::Boolean(true));
    config.set_setting("log_level".to_string(), ConfigValue::String("debug".to_string()));
    config.set_setting("max_connections".to_string(), ConfigValue::Integer(100));
    config.set_setting("timeout_multiplier".to_string(), ConfigValue::Float(1.5));
    
    assert_eq!(config.get_setting("debug_mode"), Some(&ConfigValue::Boolean(true)));
    assert_eq!(config.get_setting("log_level"), Some(&ConfigValue::String("debug".to_string())));
    assert_eq!(config.get_setting("max_connections"), Some(&ConfigValue::Integer(100)));
    assert_eq!(config.get_setting("timeout_multiplier"), Some(&ConfigValue::Float(1.5)));
    assert_eq!(config.get_setting("nonexistent"), None);
    
    Ok(())
}

#[test]
fn test_configuration_merge() -> Result<()> {
    let mut config1 = MockConfiguration::default();
    let mut config2 = MockConfiguration::default();
    
    config1.set_setting("setting1".to_string(), ConfigValue::String("value1".to_string()));
    config1.set_setting("setting2".to_string(), ConfigValue::Integer(42));
    
    config2.set_setting("setting2".to_string(), ConfigValue::Integer(100)); // Override
    config2.set_setting("setting3".to_string(), ConfigValue::Boolean(true)); // New
    
    config1.merge(&config2);
    
    assert_eq!(config1.get_setting("setting1"), Some(&ConfigValue::String("value1".to_string())));
    assert_eq!(config1.get_setting("setting2"), Some(&ConfigValue::Integer(100))); // Overridden
    assert_eq!(config1.get_setting("setting3"), Some(&ConfigValue::Boolean(true))); // Added
    
    Ok(())
}

#[test]
fn test_configuration_serialization() -> Result<()> {
    let mut config = MockConfiguration::default();
    config.set_setting("test_setting".to_string(), ConfigValue::String("test_value".to_string()));
    
    // Test serialization
    let serialized = serde_json::to_vec(&config)?;
    assert!(!serialized.is_empty());
    
    // Test deserialization
    let deserialized: MockConfiguration = serde_json::from_slice(&serialized)?;
    assert_eq!(config, deserialized);
    
    Ok(())
}

// Tests for error handling
#[test]
fn test_error_creation_and_display() -> Result<()> {
    let errors = vec![
        MockProtocolError::InvalidMessage("Test message".to_string()),
        MockProtocolError::CryptographicError("Crypto error".to_string()),
        MockProtocolError::NetworkError("Network error".to_string()),
        MockProtocolError::SessionNotFound("Session error".to_string()),
        MockProtocolError::KeyExchangeFailure("Key exchange error".to_string()),
        MockProtocolError::AuthenticationFailure("Auth error".to_string()),
        MockProtocolError::SerializationError("Serialization error".to_string()),
        MockProtocolError::DeserializationError("Deserialization error".to_string()),
        MockProtocolError::InvalidState("State error".to_string()),
        MockProtocolError::TimeoutError("Timeout error".to_string()),
    ];
    
    for error in errors {
        let error_string = error.to_string();
        assert!(!error_string.is_empty());
        assert!(error_string.contains("error") || error_string.contains("failure"));
        
        // Test that error implements std::error::Error
        let _: &dyn StdError = &error;
    }
    
    Ok(())
}

#[test]
fn test_error_equality() -> Result<()> {
    let error1 = MockProtocolError::InvalidMessage("Same message".to_string());
    let error2 = MockProtocolError::InvalidMessage("Same message".to_string());
    let error3 = MockProtocolError::InvalidMessage("Different message".to_string());
    let error4 = MockProtocolError::CryptographicError("Same message".to_string());
    
    assert_eq!(error1, error2);
    assert_ne!(error1, error3);
    assert_ne!(error1, error4);
    
    Ok(())
}

#[test]
fn test_error_propagation() -> Result<()> {
    fn function_that_fails() -> Result<()> {
        Err(MockProtocolError::InvalidMessage("Test error".to_string()).into())
    }
    
    fn function_that_propagates() -> Result<()> {
        function_that_fails()?;
        Ok(())
    }
    
    let result = function_that_propagates();
    assert!(result.is_err());
    
    let error_string = result.unwrap_err().to_string();
    assert!(error_string.contains("Invalid message"));
    assert!(error_string.contains("Test error"));
    
    Ok(())
}

// Tests for complex type interactions
#[test]
fn test_message_with_key_metadata() -> Result<()> {
    let key_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let key = MockKey::new(MockKeyType::MessageKey, key_data);
    
    let mut message = MockMessage::new(
        "alice".to_string(),
        "bob".to_string(),
        b"Encrypted content".to_vec(),
        MockMessageType::Text,
    );
    
    // Add key information to message metadata
    message.set_metadata("key_id".to_string(), key.id().to_string());
    message.set_metadata("key_type".to_string(), format!("{:?}", key.key_type()));
    message.set_metadata("encrypted".to_string(), "true".to_string());
    
    assert_eq!(message.get_metadata("key_id"), Some(&key.id().to_string()));
    assert_eq!(message.get_metadata("key_type"), Some(&"MessageKey".to_string()));
    assert_eq!(message.get_metadata("encrypted"), Some(&"true".to_string()));
    
    // Test serialization with metadata
    let serialized = message.serialize()?;
    let deserialized = MockMessage::deserialize(&serialized)?;
    
    assert_eq!(message, deserialized);
    assert_eq!(deserialized.get_metadata("key_id"), Some(&key.id().to_string()));
    
    Ok(())
}

#[test]
fn test_configuration_with_complex_values() -> Result<()> {
    let mut config = MockConfiguration::default();
    
    // Test array configuration
    let algorithms = vec![
        ConfigValue::String("AES-256-GCM".to_string()),
        ConfigValue::String("ChaCha20Poly1305".to_string()),
        ConfigValue::String("XChaCha20Poly1305".to_string()),
    ];
    config.set_setting("supported_algorithms".to_string(), ConfigValue::Array(algorithms));
    
    // Test object configuration
    let mut server_config = HashMap::new();
    server_config.insert("host".to_string(), ConfigValue::String("localhost".to_string()));
    server_config.insert("port".to_string(), ConfigValue::Integer(8080));
    server_config.insert("ssl_enabled".to_string(), ConfigValue::Boolean(true));
    config.set_setting("server".to_string(), ConfigValue::Object(server_config));
    
    // Verify complex values
    if let Some(ConfigValue::Array(ref algs)) = config.get_setting("supported_algorithms") {
        assert_eq!(algs.len(), 3);
        assert_eq!(algs[0], ConfigValue::String("AES-256-GCM".to_string()));
    } else {
        panic!("Expected array configuration");
    }
    
    if let Some(ConfigValue::Object(ref server)) = config.get_setting("server") {
        assert_eq!(server.get("host"), Some(&ConfigValue::String("localhost".to_string())));
        assert_eq!(server.get("port"), Some(&ConfigValue::Integer(8080)));
        assert_eq!(server.get("ssl_enabled"), Some(&ConfigValue::Boolean(true)));
    } else {
        panic!("Expected object configuration");
    }
    
    Ok(())
}

#[test]
fn test_error_chain_propagation() -> Result<()> {
    fn level_3_function() -> Result<()> {
        Err(MockProtocolError::CryptographicError("Level 3 error".to_string()).into())
    }
    
    fn level_2_function() -> Result<()> {
        level_3_function().map_err(|e| {
            MockProtocolError::InvalidState(format!("Level 2 wrapper: {}", e))
        })?;
        Ok(())
    }
    
    fn level_1_function() -> Result<()> {
        level_2_function().map_err(|e| {
            MockProtocolError::NetworkError(format!("Level 1 wrapper: {}", e))
        })?;
        Ok(())
    }
    
    let result = level_1_function();
    assert!(result.is_err());
    
    let error_string = result.unwrap_err().to_string();
    assert!(error_string.contains("Network error"));
    assert!(error_string.contains("Level 1 wrapper"));
    assert!(error_string.contains("Level 2 wrapper"));
    assert!(error_string.contains("Level 3 error"));
    
    Ok(())
}

#[test]
fn test_type_size_constraints() -> Result<()> {
    // Test that our types have reasonable memory footprints
    use std::mem::size_of;
    
    // Message types should be reasonably sized
    assert!(size_of::<MockMessage>() < 1024); // Should be less than 1KB
    assert!(size_of::<MockMessageType>() < 32); // Enum should be small
    
    // Key types should be compact
    assert!(size_of::<MockKey>() < 512); // Should be less than 512 bytes
    assert!(size_of::<MockKeyType>() < 16); // Enum should be very small
    
    // Session state should be minimal
    assert!(size_of::<MockSessionState>() < 64); // Should be very compact
    
    // Configuration should be reasonable
    assert!(size_of::<MockConfiguration>() < 2048); // Should be less than 2KB
    assert!(size_of::<ConfigValue>() < 128); // Should be reasonably sized
    
    Ok(())
}

#[test]
fn test_type_default_implementations() -> Result<()> {
    // Test that default configurations are valid
    let config = MockConfiguration::default();
    assert!(config.validate().is_ok());
    
    // Test that default values are sensible
    assert!(!config.protocol_version.is_empty());
    assert!(config.max_message_size > 0);
    assert!(config.session_timeout > 0);
    assert!(config.key_rotation_interval > 0);
    assert!(config.max_skipped_messages > 0);
    
    Ok(())
}

#[test]
fn test_concurrent_type_operations() -> Result<()> {
    use std::sync::Arc;
    use std::thread;
    
    let config = Arc::new(std::sync::Mutex::new(MockConfiguration::default()));
    let mut handles = Vec::new();
    
    // Spawn multiple threads modifying configuration
    for i in 0..10 {
        let config_clone = config.clone();
        let handle = thread::spawn(move || {
            let mut cfg = config_clone.lock().unwrap();
            cfg.set_setting(
                format!("thread_{}", i),
                ConfigValue::Integer(i as i64),
            );
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify all settings were added
    let final_config = config.lock().unwrap();
    for i in 0..10 {
        let setting_name = format!("thread_{}", i);
        assert_eq!(
            final_config.get_setting(&setting_name),
            Some(&ConfigValue::Integer(i as i64))
        );
    }
    
    Ok(())
}