// signal_crypto_lib/src/recovery.rs
// Advanced error recovery mechanisms for robust protocol operation

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::SessionState;
use crate::protocol::double_ratchet::DoubleRatchetError;
use crate::protocol::sesame::{GroupSessionState, SesameError};
use crate::session_manager::{SessionManager, SessionManagerError};

/// Recovery strategy for different types of errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStrategy {
    /// Retry the operation with exponential backoff
    RetryWithBackoff,
    /// Reset the session and start fresh
    ResetSession,
    /// Fallback to a simpler protocol version
    FallbackProtocol,
    /// Request fresh keys from the peer
    RequestFreshKeys,
    /// Ignore the error and continue
    IgnoreError,
    /// Fail immediately without recovery
    FailImmediately,
}

/// Error recovery configuration
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub backoff_multiplier: f64,
    pub session_reset_threshold: u32,
    pub enable_fallback: bool,
    pub enable_key_refresh: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            session_reset_threshold: 5,
            enable_fallback: true,
            enable_key_refresh: true,
        }
    }
}

/// Error recovery manager
pub struct ErrorRecoveryManager {
    config: RecoveryConfig,
    error_history: HashMap<String, ErrorHistory>,
    recovery_stats: RecoveryStats,
}

#[derive(Debug, Clone)]
struct ErrorHistory {
    errors: VecDeque<ErrorRecord>,
    consecutive_failures: u32,
    last_recovery_attempt: Option<SystemTime>,
    recovery_attempts: u32,
}

#[derive(Debug, Clone)]
struct ErrorRecord {
    error_type: String,
    timestamp: SystemTime,
    recovery_strategy: RecoveryStrategy,
    recovery_successful: Option<bool>,
}

#[derive(Debug, Default)]
pub struct RecoveryStats {
    pub total_errors: u64,
    pub successful_recoveries: u64,
    pub failed_recoveries: u64,
    pub session_resets: u64,
    pub fallback_activations: u64,
    pub key_refreshes: u64,
}

impl ErrorRecoveryManager {
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            error_history: HashMap::new(),
            recovery_stats: RecoveryStats::default(),
        }
    }
    
    /// Determine recovery strategy for a given error
    pub fn get_recovery_strategy(&mut self, session_id: &str, error: &ProtocolError) -> RecoveryStrategy {
        self.recovery_stats.total_errors += 1;
        
        let history = self.error_history.entry(session_id.to_string())
            .or_insert_with(|| ErrorHistory {
                errors: VecDeque::new(),
                consecutive_failures: 0,
                last_recovery_attempt: None,
                recovery_attempts: 0,
            });
        
        // Record the error
        history.errors.push_back(ErrorRecord {
            error_type: error.error_type(),
            timestamp: SystemTime::now(),
            recovery_strategy: RecoveryStrategy::RetryWithBackoff, // Will be updated
            recovery_successful: None,
        });
        
        // Keep only recent errors (last 100)
        while history.errors.len() > 100 {
            history.errors.pop_front();
        }
        
        // Determine strategy based on error type and history
        let strategy = match error {
            ProtocolError::DoubleRatchet(dr_error) => {
                if history.consecutive_failures >= self.config.session_reset_threshold {
                    RecoveryStrategy::ResetSession
                } else {
                    match dr_error {
                        DoubleRatchetError::DecryptionFailed => RecoveryStrategy::RequestFreshKeys,
                        DoubleRatchetError::InvalidMessageNumber => RecoveryStrategy::IgnoreError,
                        DoubleRatchetError::TooManySkippedMessages => RecoveryStrategy::ResetSession,
                        DoubleRatchetError::InvalidHeader => RecoveryStrategy::RetryWithBackoff,
                        _ => RecoveryStrategy::RetryWithBackoff,
                    }
                }
            },
            ProtocolError::Sesame(sesame_error) => {
                match sesame_error {
                    SesameError::InvalidSenderKey => RecoveryStrategy::RequestFreshKeys,
                    SesameError::DecryptionFailed => {
                        if history.consecutive_failures >= 3 {
                            RecoveryStrategy::RequestFreshKeys
                        } else {
                            RecoveryStrategy::RetryWithBackoff
                        }
                    }
                    SesameError::InvalidMessageNumber => RecoveryStrategy::IgnoreError,
                    _ => RecoveryStrategy::RetryWithBackoff,
                }
            },
            ProtocolError::SessionManager(sm_error) => {
                match sm_error {
                    SessionManagerError::DatabaseError(_) => RecoveryStrategy::RetryWithBackoff,
                    SessionManagerError::SerializationError(_) => RecoveryStrategy::ResetSession,
                    SessionManagerError::SessionNotFound => RecoveryStrategy::ResetSession,
                    SessionManagerError::InvalidSession => RecoveryStrategy::ResetSession,
                    SessionManagerError::StorageError(_) => RecoveryStrategy::RetryWithBackoff,
                    SessionManagerError::SecurityViolation(_) => RecoveryStrategy::FailImmediately,
                }
            },
            ProtocolError::Network(net_error) => {
                if history.consecutive_failures >= self.config.max_retries {
                    if self.config.enable_fallback {
                        RecoveryStrategy::FallbackProtocol
                    } else {
                        RecoveryStrategy::FailImmediately
                    }
                } else {
                    RecoveryStrategy::RetryWithBackoff
                }
            },
            ProtocolError::Cryptographic(_crypto_error) => {
                // Cryptographic errors are usually not recoverable
                RecoveryStrategy::FailImmediately
            },
        };
        
        // Update the last error record with the chosen strategy
        if let Some(last_error) = history.errors.back_mut() {
            last_error.recovery_strategy = strategy;
        }
        
        strategy
    }
    
    /// Execute recovery strategy
    pub fn execute_recovery(
        &mut self,
        session_id: &str,
        strategy: RecoveryStrategy,
        session_manager: &mut SessionManager,
    ) -> Result<RecoveryResult, RecoveryError> {
        // Get recovery attempts for backoff calculation before borrowing mutably
        let recovery_attempts = self.error_history.get(session_id)
            .map(|h| h.recovery_attempts)
            .unwrap_or(0);
        
        // Execute the recovery strategy first
        let result = match strategy {
            RecoveryStrategy::RetryWithBackoff => {
                let backoff_duration = self.calculate_backoff(recovery_attempts);
                Ok(RecoveryResult::RetryAfter(backoff_duration))
            },
            RecoveryStrategy::ResetSession => self.execute_session_reset(session_id, session_manager),
            RecoveryStrategy::FallbackProtocol => self.execute_fallback_protocol(session_id),
            RecoveryStrategy::RequestFreshKeys => self.execute_key_refresh(session_id),
            RecoveryStrategy::IgnoreError => Ok(RecoveryResult::Ignored),
            RecoveryStrategy::FailImmediately => Err(RecoveryError::RecoveryFailed),
        };
        
        // Now update history and statistics
        let history = self.error_history.entry(session_id.to_string())
            .or_insert_with(|| ErrorHistory {
                errors: VecDeque::new(),
                consecutive_failures: 0,
                last_recovery_attempt: None,
                recovery_attempts: 0,
            });
        
        history.recovery_attempts += 1;
        history.last_recovery_attempt = Some(SystemTime::now());
        
        // Update statistics and history based on result
        match &result {
            Ok(_) => {
                self.recovery_stats.successful_recoveries += 1;
                history.consecutive_failures = 0;
                if let Some(last_error) = history.errors.back_mut() {
                    last_error.recovery_successful = Some(true);
                }
            }
            Err(_) => {
                self.recovery_stats.failed_recoveries += 1;
                history.consecutive_failures += 1;
                if let Some(last_error) = history.errors.back_mut() {
                    last_error.recovery_successful = Some(false);
                }
            }
        }
        
        result
    }
    
    fn handle_double_ratchet_error(&self, error: &DoubleRatchetError, history: &ErrorHistory) -> RecoveryStrategy {
        match error {
            DoubleRatchetError::DecryptionFailed => {
                if history.consecutive_failures >= self.config.session_reset_threshold {
                    RecoveryStrategy::ResetSession
                } else {
                    RecoveryStrategy::RequestFreshKeys
                }
            }
            DoubleRatchetError::InvalidMessageNumber => RecoveryStrategy::IgnoreError,
            DoubleRatchetError::TooManySkippedMessages => RecoveryStrategy::ResetSession,
            DoubleRatchetError::InvalidHeader => RecoveryStrategy::RetryWithBackoff,
            _ => RecoveryStrategy::RetryWithBackoff,
        }
    }
    
    fn handle_sesame_error(&self, error: &SesameError, history: &ErrorHistory) -> RecoveryStrategy {
        match error {
            SesameError::InvalidSenderKey => RecoveryStrategy::RequestFreshKeys,
            SesameError::DecryptionFailed => {
                if history.consecutive_failures >= 3 {
                    RecoveryStrategy::RequestFreshKeys
                } else {
                    RecoveryStrategy::RetryWithBackoff
                }
            }
            SesameError::InvalidMessageNumber => RecoveryStrategy::IgnoreError,
            _ => RecoveryStrategy::RetryWithBackoff,
        }
    }
    
    fn handle_session_manager_error(&self, error: &SessionManagerError, _history: &ErrorHistory) -> RecoveryStrategy {
        match error {
            SessionManagerError::DatabaseError(_) => RecoveryStrategy::RetryWithBackoff,
            SessionManagerError::SerializationError(_) => RecoveryStrategy::ResetSession,
            SessionManagerError::SessionNotFound => RecoveryStrategy::ResetSession,
            SessionManagerError::InvalidSession => RecoveryStrategy::ResetSession,
            SessionManagerError::StorageError(_) => RecoveryStrategy::RetryWithBackoff,
            SessionManagerError::SecurityViolation(_) => RecoveryStrategy::FailImmediately,
        }
    }
    
    fn handle_network_error(&self, _error: &NetworkError, history: &ErrorHistory) -> RecoveryStrategy {
        if history.consecutive_failures >= self.config.max_retries {
            if self.config.enable_fallback {
                RecoveryStrategy::FallbackProtocol
            } else {
                RecoveryStrategy::FailImmediately
            }
        } else {
            RecoveryStrategy::RetryWithBackoff
        }
    }
    
    fn handle_crypto_error(&self, _error: &CryptographicError, _history: &ErrorHistory) -> RecoveryStrategy {
        // Cryptographic errors are usually not recoverable
        RecoveryStrategy::FailImmediately
    }
    
    fn execute_retry_with_backoff(&self, _session_id: &str, history: &ErrorHistory) -> Result<RecoveryResult, RecoveryError> {
        let backoff_duration = self.calculate_backoff(history.recovery_attempts);
        
        Ok(RecoveryResult::RetryAfter(backoff_duration))
    }
    
    fn execute_session_reset(&mut self, session_id: &str, session_manager: &mut SessionManager) -> Result<RecoveryResult, RecoveryError> {
        // Delete the existing session
        if let Err(_) = session_manager.delete_session(session_id) {
            return Err(RecoveryError::SessionResetFailed);
        }
        
        self.recovery_stats.session_resets += 1;
        
        // Clear error history for this session
        self.error_history.remove(session_id);
        
        Ok(RecoveryResult::SessionReset)
    }
    
    fn execute_fallback_protocol(&mut self, _session_id: &str) -> Result<RecoveryResult, RecoveryError> {
        if !self.config.enable_fallback {
            return Err(RecoveryError::FallbackDisabled);
        }
        
        self.recovery_stats.fallback_activations += 1;
        
        Ok(RecoveryResult::FallbackActivated)
    }
    
    fn execute_key_refresh(&mut self, _session_id: &str) -> Result<RecoveryResult, RecoveryError> {
        if !self.config.enable_key_refresh {
            return Err(RecoveryError::KeyRefreshDisabled);
        }
        
        self.recovery_stats.key_refreshes += 1;
        
        Ok(RecoveryResult::KeyRefreshRequested)
    }
    
    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let backoff_ms = self.config.initial_backoff.as_millis() as f64 
            * self.config.backoff_multiplier.powi(attempt as i32);
        
        let backoff_duration = Duration::from_millis(backoff_ms as u64);
        
        std::cmp::min(backoff_duration, self.config.max_backoff)
    }
    
    /// Check if a session should be considered unhealthy
    pub fn is_session_unhealthy(&self, session_id: &str) -> bool {
        if let Some(history) = self.error_history.get(session_id) {
            // Consider unhealthy if too many consecutive failures
            if history.consecutive_failures >= self.config.session_reset_threshold {
                return true;
            }
            
            // Consider unhealthy if too many errors in recent time
            let recent_errors = history.errors.iter()
                .filter(|error| {
                    error.timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(300) // 5 minutes
                })
                .count();
            
            if recent_errors >= 10 {
                return true;
            }
        }
        
        false
    }
    
    /// Get recovery statistics
    pub fn get_stats(&self) -> &RecoveryStats {
        &self.recovery_stats
    }
    
    /// Get error history for a session
    pub fn get_error_history(&self, session_id: &str) -> Option<&ErrorHistory> {
        self.error_history.get(session_id)
    }
    
    /// Clear old error history
    pub fn cleanup_old_history(&mut self, max_age: Duration) {
        let cutoff_time = SystemTime::now() - max_age;
        
        self.error_history.retain(|_, history| {
            // Remove old errors
            history.errors.retain(|error| error.timestamp > cutoff_time);
            
            // Keep history if it has recent errors or recent recovery attempts
            !history.errors.is_empty() || 
            history.last_recovery_attempt.map_or(false, |time| time > cutoff_time)
        });
    }
}

/// Result of a recovery operation
#[derive(Debug, Clone)]
pub enum RecoveryResult {
    /// Retry the operation after the specified duration
    RetryAfter(Duration),
    /// Session was reset, need to establish new session
    SessionReset,
    /// Fallback protocol activated
    FallbackActivated,
    /// Fresh keys requested from peer
    KeyRefreshRequested,
    /// Error was ignored
    Ignored,
}

/// Recovery operation errors
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryError {
    NoErrorHistory,
    RecoveryFailed,
    SessionResetFailed,
    FallbackDisabled,
    KeyRefreshDisabled,
    MaxRetriesExceeded,
}

/// Unified protocol error type for recovery handling
#[derive(Debug, Clone)]
pub enum ProtocolError {
    DoubleRatchet(DoubleRatchetError),
    Sesame(SesameError),
    SessionManager(SessionManagerError),
    Network(NetworkError),
    Cryptographic(CryptographicError),
}

impl ProtocolError {
    pub fn error_type(&self) -> String {
        match self {
            ProtocolError::DoubleRatchet(e) => format!("DoubleRatchet::{:?}", e),
            ProtocolError::Sesame(e) => format!("Sesame::{:?}", e),
            ProtocolError::SessionManager(e) => format!("SessionManager::{:?}", e),
            ProtocolError::Network(e) => format!("Network::{:?}", e),
            ProtocolError::Cryptographic(e) => format!("Cryptographic::{:?}", e),
        }
    }
}

#[derive(Debug, Clone)]
pub enum NetworkError {
    ConnectionTimeout,
    ConnectionLost,
    InvalidResponse,
    ServerError,
}

#[derive(Debug, Clone)]
pub enum CryptographicError {
    InvalidKey,
    InvalidSignature,
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,
}

/// Circuit breaker for preventing cascading failures
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    failure_count: u32,
    last_failure_time: Option<SystemTime>,
    state: CircuitBreakerState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,   // Normal operation
    Open,     // Failing fast
    HalfOpen, // Testing recovery
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            failure_count: 0,
            last_failure_time: None,
            state: CircuitBreakerState::Closed,
        }
    }
    
    pub fn call<F, T, E>(&mut self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        match self.state {
            CircuitBreakerState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed().unwrap_or(Duration::ZERO) >= self.recovery_timeout {
                        self.state = CircuitBreakerState::HalfOpen;
                    } else {
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                }
            }
            CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {}
        }
        
        match operation() {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(error) => {
                self.on_failure();
                Err(CircuitBreakerError::OperationFailed(error))
            }
        }
    }
    
    fn on_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitBreakerState::Closed;
    }
    
    fn on_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(SystemTime::now());
        
        if self.failure_count >= self.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }
    
    pub fn get_state(&self) -> CircuitBreakerState {
        self.state
    }
    
    pub fn get_failure_count(&self) -> u32 {
        self.failure_count
    }
}

#[derive(Debug, Clone)]
pub enum CircuitBreakerError<E> {
    CircuitOpen,
    OperationFailed(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_recovery_strategy_selection() {
        let mut manager = ErrorRecoveryManager::new(RecoveryConfig::default());
        
        let error = ProtocolError::DoubleRatchet(DoubleRatchetError::DecryptionFailed);
        let strategy = manager.get_recovery_strategy("session1", &error);
        
        assert_eq!(strategy, RecoveryStrategy::RequestFreshKeys);
    }
    
    #[test]
    fn test_backoff_calculation() {
        let config = RecoveryConfig::default();
        let manager = ErrorRecoveryManager::new(config);
        
        let backoff1 = manager.calculate_backoff(0);
        let backoff2 = manager.calculate_backoff(1);
        let backoff3 = manager.calculate_backoff(2);
        
        assert!(backoff2 > backoff1);
        assert!(backoff3 > backoff2);
    }
    
    #[test]
    fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new(3, Duration::from_millis(100));
        
        // Should be closed initially
        assert_eq!(breaker.get_state(), CircuitBreakerState::Closed);
        
        // Simulate failures
        for _ in 0..3 {
            let _ = breaker.call(|| -> Result<(), &str> { Err("error") });
        }
        
        // Should be open after threshold failures
        assert_eq!(breaker.get_state(), CircuitBreakerState::Open);
        
        // Should fail fast when open
        let result = breaker.call(|| -> Result<(), &str> { Ok(()) });
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }
    
    #[test]
    fn test_session_health_check() {
        let mut manager = ErrorRecoveryManager::new(RecoveryConfig::default());
        
        // Add multiple errors for a session
        for _ in 0..6 {
            let error = ProtocolError::DoubleRatchet(DoubleRatchetError::DecryptionFailed);
            manager.get_recovery_strategy("unhealthy_session", &error);
        }
        
        assert!(manager.is_session_unhealthy("unhealthy_session"));
        assert!(!manager.is_session_unhealthy("healthy_session"));
    }
    
    #[test]
    fn test_error_history_cleanup() {
        let mut manager = ErrorRecoveryManager::new(RecoveryConfig::default());
        
        let error = ProtocolError::Network(NetworkError::ConnectionTimeout);
        manager.get_recovery_strategy("test_session", &error);
        
        // Should have history
        assert!(manager.get_error_history("test_session").is_some());
        
        // Cleanup with very short max age
        manager.cleanup_old_history(Duration::from_nanos(1));
        
        // History should be cleaned up
        assert!(manager.get_error_history("test_session").is_none());
    }
}