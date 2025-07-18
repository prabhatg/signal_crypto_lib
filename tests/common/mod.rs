//! Common test utilities and helpers for Signal Protocol tests
//! 
//! This module provides shared utilities, fixtures, and helper functions
//! for comprehensive testing of all Signal Protocol features.

use signal_crypto_lib::*;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod fixtures;
pub mod helpers;
pub mod assertions;
pub mod mocks;

/// Test configuration for different scenarios
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub enable_logging: bool,
    pub test_timeout: Duration,
    pub performance_mode: bool,
    pub security_level: SecurityLevel,
    pub compliance_mode: ComplianceMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLevel {
    Basic,
    Standard,
    High,
    Maximum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceMode {
    None,
    GDPR,
    HIPAA,
    SOX,
    All,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            enable_logging: false,
            test_timeout: Duration::from_secs(30),
            performance_mode: false,
            security_level: SecurityLevel::Standard,
            compliance_mode: ComplianceMode::None,
        }
    }
}

/// Test context for maintaining state across test operations
pub struct TestContext {
    pub config: TestConfig,
    pub identities: HashMap<String, IdentityKeyPair>,
    pub sessions: HashMap<String, SessionState>,
    pub group_sessions: HashMap<String, GroupSessionState>,
    pub start_time: SystemTime,
    pub metrics: TestMetrics,
}

/// Test metrics for performance and behavior analysis
#[derive(Debug, Default)]
pub struct TestMetrics {
    pub operations_count: u64,
    pub total_duration: Duration,
    pub memory_usage: u64,
    pub crypto_operations: u64,
    pub network_calls: u64,
    pub errors_count: u64,
}

impl TestContext {
    pub fn new(config: TestConfig) -> Self {
        Self {
            config,
            identities: HashMap::new(),
            sessions: HashMap::new(),
            group_sessions: HashMap::new(),
            start_time: SystemTime::now(),
            metrics: TestMetrics::default(),
        }
    }

    pub fn with_default() -> Self {
        Self::new(TestConfig::default())
    }

    pub fn with_security_level(level: SecurityLevel) -> Self {
        let mut config = TestConfig::default();
        config.security_level = level;
        Self::new(config)
    }

    pub fn with_compliance(mode: ComplianceMode) -> Self {
        let mut config = TestConfig::default();
        config.compliance_mode = mode;
        Self::new(config)
    }

    /// Record a test operation for metrics
    pub fn record_operation(&mut self, operation: &str, duration: Duration) {
        self.metrics.operations_count += 1;
        self.metrics.total_duration += duration;
        
        if operation.contains("crypto") || operation.contains("encrypt") || operation.contains("decrypt") {
            self.metrics.crypto_operations += 1;
        }
        
        if operation.contains("network") || operation.contains("send") || operation.contains("receive") {
            self.metrics.network_calls += 1;
        }
    }

    /// Record an error for metrics
    pub fn record_error(&mut self, error: &str) {
        self.metrics.errors_count += 1;
        if self.config.enable_logging {
            eprintln!("Test error: {}", error);
        }
    }

    /// Get test duration since start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed().unwrap_or(Duration::ZERO)
    }

    /// Check if test should timeout
    pub fn should_timeout(&self) -> bool {
        self.elapsed() > self.config.test_timeout
    }

    /// Generate a unique test identifier
    pub fn generate_test_id(&self) -> String {
        format!("test_{}", Uuid::new_v4().simple())
    }

    /// Create a test user identity
    pub fn create_test_identity(&mut self, user_id: &str) -> &IdentityKeyPair {
        let identity = generate_identity_keypair();
        self.identities.insert(user_id.to_string(), identity);
        self.identities.get(user_id).unwrap()
    }

    /// Get or create a test identity
    pub fn get_or_create_identity(&mut self, user_id: &str) -> &IdentityKeyPair {
        if !self.identities.contains_key(user_id) {
            self.create_test_identity(user_id);
        }
        self.identities.get(user_id).unwrap()
    }

    /// Clean up test resources
    pub fn cleanup(&mut self) {
        self.identities.clear();
        self.sessions.clear();
        self.group_sessions.clear();
    }
}

/// Test result wrapper with additional context
#[derive(Debug)]
pub struct TestResult<T> {
    pub value: T,
    pub duration: Duration,
    pub metrics: TestMetrics,
    pub warnings: Vec<String>,
}

impl<T> TestResult<T> {
    pub fn new(value: T, duration: Duration) -> Self {
        Self {
            value,
            duration,
            metrics: TestMetrics::default(),
            warnings: Vec::new(),
        }
    }

    pub fn with_metrics(mut self, metrics: TestMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Macro for timing test operations
#[macro_export]
macro_rules! time_operation {
    ($ctx:expr, $op_name:expr, $block:block) => {{
        let start = std::time::SystemTime::now();
        let result = $block;
        let duration = start.elapsed().unwrap_or(std::time::Duration::ZERO);
        $ctx.record_operation($op_name, duration);
        result
    }};
}

/// Macro for asserting test conditions with context
#[macro_export]
macro_rules! test_assert {
    ($ctx:expr, $condition:expr, $message:expr) => {
        if !$condition {
            $ctx.record_error(&format!("Assertion failed: {}", $message));
            panic!("Test assertion failed: {}", $message);
        }
    };
}

/// Macro for asserting cryptographic properties
#[macro_export]
macro_rules! crypto_assert {
    ($condition:expr, $property:expr) => {
        assert!($condition, "Cryptographic property violated: {}", $property);
    };
}

/// Generate test data of specified size
pub fn generate_test_data(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut data = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut data);
    data
}

/// Generate deterministic test data for reproducible tests
pub fn generate_deterministic_data(size: usize, seed: u64) -> Vec<u8> {
    use rand::{RngCore, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

/// Create a test message with metadata
pub fn create_test_message(content: &str, sender: &str, recipient: Option<&str>) -> TestMessage {
    TestMessage {
        id: Uuid::new_v4().to_string(),
        content: content.to_string(),
        sender: sender.to_string(),
        recipient: recipient.map(|r| r.to_string()),
        timestamp: Utc::now(),
        metadata: HashMap::new(),
    }
}

/// Test message structure
#[derive(Debug, Clone)]
pub struct TestMessage {
    pub id: String,
    pub content: String,
    pub sender: String,
    pub recipient: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Test group structure
#[derive(Debug, Clone)]
pub struct TestGroup {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
    pub admin: String,
    pub created_at: DateTime<Utc>,
}

impl TestGroup {
    pub fn new(id: &str, name: &str, admin: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            members: vec![admin.to_string()],
            admin: admin.to_string(),
            created_at: Utc::now(),
        }
    }

    pub fn add_member(&mut self, member: &str) {
        if !self.members.contains(&member.to_string()) {
            self.members.push(member.to_string());
        }
    }

    pub fn remove_member(&mut self, member: &str) {
        self.members.retain(|m| m != member);
    }
}

/// Performance benchmark utilities
pub struct BenchmarkRunner {
    pub iterations: usize,
    pub warmup_iterations: usize,
    pub timeout: Duration,
}

impl BenchmarkRunner {
    pub fn new() -> Self {
        Self {
            iterations: 1000,
            warmup_iterations: 100,
            timeout: Duration::from_secs(60),
        }
    }

    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    pub fn with_warmup(mut self, warmup: usize) -> Self {
        self.warmup_iterations = warmup;
        self
    }

    pub fn run<F, T>(&self, name: &str, mut operation: F) -> BenchmarkResult
    where
        F: FnMut() -> T,
    {
        // Warmup
        for _ in 0..self.warmup_iterations {
            let _ = operation();
        }

        let mut durations = Vec::with_capacity(self.iterations);
        let start_time = SystemTime::now();

        for _ in 0..self.iterations {
            if start_time.elapsed().unwrap_or(Duration::ZERO) > self.timeout {
                break;
            }

            let iter_start = SystemTime::now();
            let _ = operation();
            let iter_duration = iter_start.elapsed().unwrap_or(Duration::ZERO);
            durations.push(iter_duration);
        }

        BenchmarkResult::from_durations(name, durations)
    }
}

/// Benchmark result with statistics
#[derive(Debug)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: usize,
    pub total_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub avg_duration: Duration,
    pub median_duration: Duration,
    pub p95_duration: Duration,
    pub p99_duration: Duration,
    pub ops_per_second: f64,
}

impl BenchmarkResult {
    pub fn from_durations(name: &str, mut durations: Vec<Duration>) -> Self {
        durations.sort();
        
        let iterations = durations.len();
        let total_duration: Duration = durations.iter().sum();
        let min_duration = durations.first().copied().unwrap_or(Duration::ZERO);
        let max_duration = durations.last().copied().unwrap_or(Duration::ZERO);
        let avg_duration = if iterations > 0 {
            total_duration / iterations as u32
        } else {
            Duration::ZERO
        };
        
        let median_duration = if iterations > 0 {
            durations[iterations / 2]
        } else {
            Duration::ZERO
        };
        
        let p95_duration = if iterations > 0 {
            durations[(iterations as f64 * 0.95) as usize]
        } else {
            Duration::ZERO
        };
        
        let p99_duration = if iterations > 0 {
            durations[(iterations as f64 * 0.99) as usize]
        } else {
            Duration::ZERO
        };
        
        let ops_per_second = if avg_duration.as_secs_f64() > 0.0 {
            1.0 / avg_duration.as_secs_f64()
        } else {
            0.0
        };

        Self {
            name: name.to_string(),
            iterations,
            total_duration,
            min_duration,
            max_duration,
            avg_duration,
            median_duration,
            p95_duration,
            p99_duration,
            ops_per_second,
        }
    }

    pub fn print_summary(&self) {
        println!("Benchmark: {}", self.name);
        println!("  Iterations: {}", self.iterations);
        println!("  Total time: {:?}", self.total_duration);
        println!("  Average: {:?}", self.avg_duration);
        println!("  Median: {:?}", self.median_duration);
        println!("  Min: {:?}", self.min_duration);
        println!("  Max: {:?}", self.max_duration);
        println!("  P95: {:?}", self.p95_duration);
        println!("  P99: {:?}", self.p99_duration);
        println!("  Ops/sec: {:.2}", self.ops_per_second);
    }
}

impl Default for BenchmarkRunner {
    fn default() -> Self {
        Self::new()
    }
}