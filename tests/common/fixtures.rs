//! Test fixtures for Signal Protocol testing
//! 
//! This module provides pre-configured test data, identities, sessions,
//! and other fixtures for consistent testing across the test suite.

use signal_crypto_lib::*;
use super::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Standard test identities for consistent testing
pub struct TestIdentities {
    pub alice: IdentityKeyPair,
    pub bob: IdentityKeyPair,
    pub charlie: IdentityKeyPair,
    pub dave: IdentityKeyPair,
    pub eve: IdentityKeyPair,
}

impl TestIdentities {
    pub fn new() -> Self {
        Self {
            alice: generate_identity_keypair(),
            bob: generate_identity_keypair(),
            charlie: generate_identity_keypair(),
            dave: generate_identity_keypair(),
            eve: generate_identity_keypair(),
        }
    }

    pub fn get_identity(&self, name: &str) -> Option<&IdentityKeyPair> {
        match name.to_lowercase().as_str() {
            "alice" => Some(&self.alice),
            "bob" => Some(&self.bob),
            "charlie" => Some(&self.charlie),
            "dave" => Some(&self.dave),
            "eve" => Some(&self.eve),
            _ => None,
        }
    }

    pub fn all_identities(&self) -> Vec<(&str, &IdentityKeyPair)> {
        vec![
            ("alice", &self.alice),
            ("bob", &self.bob),
            ("charlie", &self.charlie),
            ("dave", &self.dave),
            ("eve", &self.eve),
        ]
    }
}

impl Default for TestIdentities {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard test prekeys for X3DH testing
pub struct TestPreKeys {
    pub alice_prekeys: Vec<PreKeyPair>,
    pub bob_prekeys: Vec<PreKeyPair>,
    pub charlie_prekeys: Vec<PreKeyPair>,
}

impl TestPreKeys {
    pub fn new() -> Self {
        Self {
            alice_prekeys: (0..10).map(|i| generate_prekey_pair(i)).collect(),
            bob_prekeys: (0..10).map(|i| generate_prekey_pair(i + 10)).collect(),
            charlie_prekeys: (0..10).map(|i| generate_prekey_pair(i + 20)).collect(),
        }
    }

    pub fn get_prekeys(&self, user: &str) -> Option<&Vec<PreKeyPair>> {
        match user.to_lowercase().as_str() {
            "alice" => Some(&self.alice_prekeys),
            "bob" => Some(&self.bob_prekeys),
            "charlie" => Some(&self.charlie_prekeys),
            _ => None,
        }
    }

    pub fn get_prekey(&self, user: &str, index: usize) -> Option<&PreKeyPair> {
        self.get_prekeys(user)?.get(index)
    }
}

impl Default for TestPreKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard test messages for protocol testing
pub struct TestMessages {
    pub short_text: Vec<u8>,
    pub long_text: Vec<u8>,
    pub binary_data: Vec<u8>,
    pub empty_message: Vec<u8>,
    pub unicode_text: Vec<u8>,
    pub large_message: Vec<u8>,
}

impl TestMessages {
    pub fn new() -> Self {
        Self {
            short_text: b"Hello, World!".to_vec(),
            long_text: b"This is a longer test message that contains multiple sentences and should be sufficient for testing various aspects of the Signal Protocol implementation including encryption, decryption, and message handling.".to_vec(),
            binary_data: (0..256).map(|i| i as u8).collect(),
            empty_message: Vec::new(),
            unicode_text: "Hello, 世界! 🌍 Здравствуй мир! مرحبا بالعالم!".as_bytes().to_vec(),
            large_message: vec![b'A'; 1024 * 1024], // 1MB message
        }
    }

    pub fn get_message(&self, name: &str) -> Option<&Vec<u8>> {
        match name.to_lowercase().as_str() {
            "short" | "short_text" => Some(&self.short_text),
            "long" | "long_text" => Some(&self.long_text),
            "binary" | "binary_data" => Some(&self.binary_data),
            "empty" | "empty_message" => Some(&self.empty_message),
            "unicode" | "unicode_text" => Some(&self.unicode_text),
            "large" | "large_message" => Some(&self.large_message),
            _ => None,
        }
    }

    pub fn all_messages(&self) -> Vec<(&str, &Vec<u8>)> {
        vec![
            ("short_text", &self.short_text),
            ("long_text", &self.long_text),
            ("binary_data", &self.binary_data),
            ("empty_message", &self.empty_message),
            ("unicode_text", &self.unicode_text),
            ("large_message", &self.large_message),
        ]
    }
}

impl Default for TestMessages {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard test groups for group messaging tests
pub struct TestGroups {
    pub small_group: TestGroup,
    pub medium_group: TestGroup,
    pub large_group: TestGroup,
    pub enterprise_group: TestGroup,
}

impl TestGroups {
    pub fn new() -> Self {
        let mut small_group = TestGroup::new("small_group_001", "Small Test Group", "alice");
        small_group.add_member("bob");
        small_group.add_member("charlie");

        let mut medium_group = TestGroup::new("medium_group_001", "Medium Test Group", "alice");
        for i in 0..20 {
            medium_group.add_member(&format!("user_{:02}", i));
        }

        let mut large_group = TestGroup::new("large_group_001", "Large Test Group", "alice");
        for i in 0..100 {
            large_group.add_member(&format!("user_{:03}", i));
        }

        let mut enterprise_group = TestGroup::new("enterprise_group_001", "Enterprise Test Group", "admin");
        enterprise_group.add_member("alice");
        enterprise_group.add_member("bob");
        enterprise_group.add_member("charlie");
        enterprise_group.add_member("dave");
        enterprise_group.add_member("eve");

        Self {
            small_group,
            medium_group,
            large_group,
            enterprise_group,
        }
    }

    pub fn get_group(&self, name: &str) -> Option<&TestGroup> {
        match name.to_lowercase().as_str() {
            "small" | "small_group" => Some(&self.small_group),
            "medium" | "medium_group" => Some(&self.medium_group),
            "large" | "large_group" => Some(&self.large_group),
            "enterprise" | "enterprise_group" => Some(&self.enterprise_group),
            _ => None,
        }
    }

    pub fn all_groups(&self) -> Vec<(&str, &TestGroup)> {
        vec![
            ("small_group", &self.small_group),
            ("medium_group", &self.medium_group),
            ("large_group", &self.large_group),
            ("enterprise_group", &self.enterprise_group),
        ]
    }
}

impl Default for TestGroups {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete test fixture set
pub struct TestFixtures {
    pub identities: TestIdentities,
    pub prekeys: TestPreKeys,
    pub messages: TestMessages,
    pub groups: TestGroups,
}

impl TestFixtures {
    pub fn new() -> Self {
        Self {
            identities: TestIdentities::new(),
            prekeys: TestPreKeys::new(),
            messages: TestMessages::new(),
            groups: TestGroups::new(),
        }
    }

    /// Create a minimal fixture set for basic tests
    pub fn minimal() -> Self {
        Self::new()
    }

    /// Create an extended fixture set for comprehensive tests
    pub fn extended() -> Self {
        Self::new()
    }
}

impl Default for TestFixtures {
    fn default() -> Self {
        Self::new()
    }
}

/// Test data generators for various scenarios
pub struct TestDataGenerator;

impl TestDataGenerator {
    /// Generate test data for performance testing
    pub fn performance_data(size_mb: usize) -> Vec<u8> {
        vec![0xAA; size_mb * 1024 * 1024]
    }

    /// Generate test data with specific patterns
    pub fn patterned_data(pattern: &[u8], total_size: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(total_size);
        let pattern_len = pattern.len();
        
        for i in 0..total_size {
            data.push(pattern[i % pattern_len]);
        }
        
        data
    }

    /// Generate random test data with seed for reproducibility
    pub fn seeded_random_data(size: usize, seed: u64) -> Vec<u8> {
        generate_deterministic_data(size, seed)
    }

    /// Generate test data that compresses well
    pub fn compressible_data(size: usize) -> Vec<u8> {
        let pattern = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Self::patterned_data(pattern, size)
    }

    /// Generate test data that doesn't compress well
    pub fn incompressible_data(size: usize) -> Vec<u8> {
        generate_test_data(size)
    }

    /// Generate test messages for different scenarios
    pub fn scenario_messages() -> HashMap<String, Vec<u8>> {
        let mut messages = HashMap::new();
        
        messages.insert("heartbeat".to_string(), b"ping".to_vec());
        messages.insert("status_update".to_string(), b"User is typing...".to_vec());
        messages.insert("file_transfer_start".to_string(), b"FILE_TRANSFER_START:document.pdf:1024000".to_vec());
        messages.insert("file_transfer_chunk".to_string(), vec![0xFF; 8192]);
        messages.insert("file_transfer_end".to_string(), b"FILE_TRANSFER_END:SUCCESS".to_vec());
        messages.insert("group_invite".to_string(), b"GROUP_INVITE:test_group:alice".to_vec());
        messages.insert("group_leave".to_string(), b"GROUP_LEAVE:test_group:bob".to_vec());
        messages.insert("key_rotation".to_string(), b"KEY_ROTATION_REQUEST".to_vec());
        messages.insert("emergency_message".to_string(), b"EMERGENCY:HELP_NEEDED:LOCATION:40.7128,-74.0060".to_vec());
        
        messages
    }

    /// Generate test user profiles
    pub fn test_user_profiles() -> HashMap<String, TestUserProfile> {
        let mut profiles = HashMap::new();
        
        profiles.insert("alice".to_string(), TestUserProfile {
            user_id: "alice".to_string(),
            display_name: "Alice Smith".to_string(),
            email: "alice@example.com".to_string(),
            role: "user".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            created_at: Utc::now(),
            last_active: Utc::now(),
        });
        
        profiles.insert("bob".to_string(), TestUserProfile {
            user_id: "bob".to_string(),
            display_name: "Bob Johnson".to_string(),
            email: "bob@example.com".to_string(),
            role: "user".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            created_at: Utc::now(),
            last_active: Utc::now(),
        });
        
        profiles.insert("admin".to_string(), TestUserProfile {
            user_id: "admin".to_string(),
            display_name: "System Administrator".to_string(),
            email: "admin@example.com".to_string(),
            role: "admin".to_string(),
            permissions: vec!["read".to_string(), "write".to_string(), "admin".to_string(), "delete".to_string()],
            created_at: Utc::now(),
            last_active: Utc::now(),
        });
        
        profiles
    }
}

/// Test user profile structure
#[derive(Debug, Clone)]
pub struct TestUserProfile {
    pub user_id: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

/// Test environment configurations
pub struct TestEnvironments;

impl TestEnvironments {
    /// Development environment configuration
    pub fn development() -> TestConfig {
        TestConfig {
            enable_logging: true,
            test_timeout: Duration::from_secs(60),
            performance_mode: false,
            security_level: SecurityLevel::Standard,
            compliance_mode: ComplianceMode::None,
        }
    }

    /// Production-like environment configuration
    pub fn production() -> TestConfig {
        TestConfig {
            enable_logging: false,
            test_timeout: Duration::from_secs(30),
            performance_mode: true,
            security_level: SecurityLevel::High,
            compliance_mode: ComplianceMode::All,
        }
    }

    /// Performance testing environment
    pub fn performance() -> TestConfig {
        TestConfig {
            enable_logging: false,
            test_timeout: Duration::from_secs(300),
            performance_mode: true,
            security_level: SecurityLevel::Standard,
            compliance_mode: ComplianceMode::None,
        }
    }

    /// Security testing environment
    pub fn security() -> TestConfig {
        TestConfig {
            enable_logging: true,
            test_timeout: Duration::from_secs(120),
            performance_mode: false,
            security_level: SecurityLevel::Maximum,
            compliance_mode: ComplianceMode::All,
        }
    }

    /// CI/CD environment configuration
    pub fn ci_cd() -> TestConfig {
        TestConfig {
            enable_logging: false,
            test_timeout: Duration::from_secs(45),
            performance_mode: false,
            security_level: SecurityLevel::Standard,
            compliance_mode: ComplianceMode::GDPR,
        }
    }
}

/// Test scenario builder for complex test setups
pub struct TestScenarioBuilder {
    identities: Vec<String>,
    groups: Vec<String>,
    messages: Vec<String>,
    config: TestConfig,
}

impl TestScenarioBuilder {
    pub fn new() -> Self {
        Self {
            identities: Vec::new(),
            groups: Vec::new(),
            messages: Vec::new(),
            config: TestConfig::default(),
        }
    }

    pub fn with_identities(mut self, identities: Vec<&str>) -> Self {
        self.identities = identities.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_groups(mut self, groups: Vec<&str>) -> Self {
        self.groups = groups.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_messages(mut self, messages: Vec<&str>) -> Self {
        self.messages = messages.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_config(mut self, config: TestConfig) -> Self {
        self.config = config;
        self
    }

    pub fn build(self) -> TestScenario {
        TestScenario {
            identities: self.identities,
            groups: self.groups,
            messages: self.messages,
            config: self.config,
        }
    }
}

impl Default for TestScenarioBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete test scenario
#[derive(Debug, Clone)]
pub struct TestScenario {
    pub identities: Vec<String>,
    pub groups: Vec<String>,
    pub messages: Vec<String>,
    pub config: TestConfig,
}

impl TestScenario {
    /// Create a basic two-party scenario
    pub fn two_party() -> Self {
        TestScenarioBuilder::new()
            .with_identities(vec!["alice", "bob"])
            .with_messages(vec!["short_text", "long_text"])
            .build()
    }

    /// Create a small group scenario
    pub fn small_group() -> Self {
        TestScenarioBuilder::new()
            .with_identities(vec!["alice", "bob", "charlie"])
            .with_groups(vec!["small_group"])
            .with_messages(vec!["short_text", "long_text", "binary_data"])
            .build()
    }

    /// Create a performance testing scenario
    pub fn performance() -> Self {
        TestScenarioBuilder::new()
            .with_identities(vec!["alice", "bob"])
            .with_messages(vec!["large_message"])
            .with_config(TestEnvironments::performance())
            .build()
    }

    /// Create a security testing scenario
    pub fn security() -> Self {
        TestScenarioBuilder::new()
            .with_identities(vec!["alice", "bob", "eve"])
            .with_messages(vec!["short_text", "unicode_text"])
            .with_config(TestEnvironments::security())
            .build()
    }
}