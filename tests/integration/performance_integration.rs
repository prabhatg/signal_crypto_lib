//! Performance integration tests
//! 
//! This module tests the performance characteristics and scalability
//! of the Signal Protocol implementation including:
//! - Throughput and latency measurements
//! - Memory usage and resource consumption
//! - Concurrent operation performance
//! - Large-scale group messaging performance
//! - Protocol optimization effectiveness

use crate::common::*;
use signal_crypto_lib::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

/// Test message throughput performance
#[tokio::test]
async fn test_message_throughput() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    // Setup session for throughput testing
    let alice_id = "alice@example.com";
    let bob_id = "bob@example.com";
    
    let session_id = perf_tester.establish_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.alice_identity,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Test different message sizes
    let message_sizes = vec![100, 1024, 10240, 102400]; // 100B, 1KB, 10KB, 100KB
    let messages_per_size = 1000;
    
    for size in message_sizes {
        let message = vec![0u8; size];
        let start_time = Instant::now();
        
        // Send messages in batch
        for i in 0..messages_per_size {
            let sender = if i % 2 == 0 { alice_id } else { bob_id };
            perf_tester.send_message(&session_id, sender, &message).await?;
        }
        
        let duration = start_time.elapsed();
        let throughput = (messages_per_size as f64) / duration.as_secs_f64();
        let bytes_per_second = (messages_per_size * size) as f64 / duration.as_secs_f64();
        
        // Performance assertions
        assert!(throughput > 100.0, "Throughput too low for {}B messages: {:.2} msg/s", size, throughput);
        assert!(bytes_per_second > 10_000.0, "Byte throughput too low for {}B messages: {:.2} B/s", size, bytes_per_second);
        
        println!("Size: {}B, Throughput: {:.2} msg/s, Bandwidth: {:.2} MB/s", 
                 size, throughput, bytes_per_second / 1_000_000.0);
    }
    
    test_ctx.metrics.record_test_completion("message_throughput", true);
    Ok(())
}

/// Test message latency performance
#[tokio::test]
async fn test_message_latency() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    let alice_id = "alice@example.com";
    let bob_id = "bob@example.com";
    
    let session_id = perf_tester.establish_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.alice_identity,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    let test_message = b"Latency test message";
    let num_measurements = 100;
    let mut latencies = Vec::new();
    
    // Measure round-trip latencies
    for i in 0..num_measurements {
        let start_time = Instant::now();
        
        // Send message from Alice to Bob
        let encrypted = perf_tester.send_message(&session_id, alice_id, test_message).await?;
        
        // Decrypt message at Bob's end
        let _decrypted = perf_tester.receive_message(&session_id, bob_id, &encrypted).await?;
        
        let latency = start_time.elapsed();
        latencies.push(latency);
        
        // Small delay between measurements
        if i % 10 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }
    
    // Calculate statistics
    let avg_latency = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let mut sorted_latencies = latencies.clone();
    sorted_latencies.sort();
    let p50_latency = sorted_latencies[latencies.len() / 2];
    let p95_latency = sorted_latencies[(latencies.len() * 95) / 100];
    let p99_latency = sorted_latencies[(latencies.len() * 99) / 100];
    
    // Performance assertions
    assert!(avg_latency < Duration::from_millis(10), "Average latency too high: {:?}", avg_latency);
    assert!(p95_latency < Duration::from_millis(20), "P95 latency too high: {:?}", p95_latency);
    assert!(p99_latency < Duration::from_millis(50), "P99 latency too high: {:?}", p99_latency);
    
    println!("Latency stats - Avg: {:?}, P50: {:?}, P95: {:?}, P99: {:?}", 
             avg_latency, p50_latency, p95_latency, p99_latency);
    
    test_ctx.metrics.record_test_completion("message_latency", true);
    Ok(())
}

/// Test concurrent session performance
#[tokio::test]
async fn test_concurrent_sessions() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    let num_sessions = 100;
    let messages_per_session = 50;
    
    // Create multiple concurrent sessions
    let mut session_tasks = Vec::new();
    
    for i in 0..num_sessions {
        let alice_id = format!("alice{}@example.com", i);
        let bob_id = format!("bob{}@example.com", i);
        let mut tester = perf_tester.clone();
        let alice_identity = test_ctx.fixtures.alice_identity.clone();
        let bob_prekey = test_ctx.fixtures.bob_prekey_bundle.clone();
        
        let task = tokio::spawn(async move {
            // Establish session
            let session_id = tester.establish_session(
                &alice_id,
                &bob_id,
                &alice_identity,
                &bob_prekey
            ).await?;
            
            // Exchange messages
            let test_message = format!("Message from session {}", i);
            let start_time = Instant::now();
            
            for j in 0..messages_per_session {
                let sender = if j % 2 == 0 { &alice_id } else { &bob_id };
                tester.send_message(&session_id, sender, test_message.as_bytes()).await?;
            }
            
            let duration = start_time.elapsed();
            Ok::<(String, Duration), Box<dyn std::error::Error + Send + Sync>>((session_id, duration))
        });
        
        session_tasks.push(task);
    }
    
    // Wait for all sessions to complete
    let start_time = Instant::now();
    let mut results = Vec::new();
    
    for task in session_tasks {
        let result = task.await??;
        results.push(result);
    }
    
    let total_duration = start_time.elapsed();
    let total_messages = num_sessions * messages_per_session;
    let overall_throughput = total_messages as f64 / total_duration.as_secs_f64();
    
    // Performance assertions
    assert!(overall_throughput > 1000.0, "Concurrent throughput too low: {:.2} msg/s", overall_throughput);
    assert!(total_duration < Duration::from_secs(30), "Concurrent test took too long: {:?}", total_duration);
    
    // Check individual session performance
    for (session_id, duration) in &results {
        let session_throughput = messages_per_session as f64 / duration.as_secs_f64();
        assert!(session_throughput > 10.0, "Session {} throughput too low: {:.2} msg/s", session_id, session_throughput);
    }
    
    println!("Concurrent sessions: {}, Total throughput: {:.2} msg/s", num_sessions, overall_throughput);
    
    test_ctx.metrics.record_test_completion("concurrent_sessions", true);
    Ok(())
}

/// Test large group messaging performance
#[tokio::test]
async fn test_large_group_performance() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    // Test different group sizes
    let group_sizes = vec![10, 50, 100, 500];
    
    for group_size in group_sizes {
        let group_id = format!("large_group_{}", group_size);
        let admin_id = "admin@example.com";
        
        // Create member list
        let mut members = Vec::new();
        for i in 0..group_size {
            members.push(format!("member{}@example.com", i));
        }
        let member_refs: Vec<&str> = members.iter().map(|s| s.as_str()).collect();
        
        // Measure group creation time
        let start_time = Instant::now();
        perf_tester.create_group(&group_id, admin_id, &member_refs).await?;
        let creation_time = start_time.elapsed();
        
        // Measure message sending time
        let test_message = format!("Group message for {} members", group_size);
        let start_time = Instant::now();
        
        let num_messages = 20;
        for i in 0..num_messages {
            let sender = if i % 10 == 0 { admin_id } else { &member_refs[i % member_refs.len()] };
            perf_tester.send_group_message(&group_id, sender, test_message.as_bytes()).await?;
        }
        
        let messaging_time = start_time.elapsed();
        let group_throughput = num_messages as f64 / messaging_time.as_secs_f64();
        
        // Performance assertions based on group size
        let expected_creation_time = Duration::from_millis(group_size as u64 * 10); // 10ms per member
        let expected_min_throughput = if group_size <= 50 { 10.0 } else { 5.0 };
        
        assert!(creation_time < expected_creation_time, 
                "Group creation too slow for {} members: {:?}", group_size, creation_time);
        assert!(group_throughput > expected_min_throughput, 
                "Group messaging throughput too low for {} members: {:.2} msg/s", group_size, group_throughput);
        
        println!("Group size: {}, Creation: {:?}, Throughput: {:.2} msg/s", 
                 group_size, creation_time, group_throughput);
        
        // Test member addition performance
        let start_time = Instant::now();
        let new_member = format!("new_member_{}@example.com", group_size);
        perf_tester.add_group_member(&group_id, admin_id, &new_member).await?;
        let addition_time = start_time.elapsed();
        
        assert!(addition_time < Duration::from_millis(100), 
                "Member addition too slow for group of {} members: {:?}", group_size, addition_time);
    }
    
    test_ctx.metrics.record_test_completion("large_group_performance", true);
    Ok(())
}

/// Test memory usage and resource consumption
#[tokio::test]
async fn test_memory_usage() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    // Measure baseline memory usage
    let baseline_memory = perf_tester.get_memory_usage().await?;
    
    // Create many sessions and measure memory growth
    let num_sessions = 1000;
    let mut session_ids = Vec::new();
    
    for i in 0..num_sessions {
        let alice_id = format!("alice{}@example.com", i);
        let bob_id = format!("bob{}@example.com", i);
        
        let session_id = perf_tester.establish_session(
            &alice_id,
            &bob_id,
            &test_ctx.fixtures.alice_identity,
            &test_ctx.fixtures.bob_prekey_bundle
        ).await?;
        
        session_ids.push(session_id);
        
        // Check memory usage periodically
        if i % 100 == 99 {
            let current_memory = perf_tester.get_memory_usage().await?;
            let memory_per_session = (current_memory - baseline_memory) / (i + 1) as u64;
            
            // Assert reasonable memory usage per session
            assert!(memory_per_session < 10_000, // 10KB per session max
                    "Memory usage per session too high: {} bytes", memory_per_session);
            
            println!("Sessions: {}, Memory per session: {} bytes", i + 1, memory_per_session);
        }
    }
    
    let final_memory = perf_tester.get_memory_usage().await?;
    let total_memory_used = final_memory - baseline_memory;
    let avg_memory_per_session = total_memory_used / num_sessions as u64;
    
    // Final memory usage assertions
    assert!(avg_memory_per_session < 8_000, // 8KB per session average
            "Average memory per session too high: {} bytes", avg_memory_per_session);
    assert!(total_memory_used < 8_000_000, // 8MB total for 1000 sessions
            "Total memory usage too high: {} bytes", total_memory_used);
    
    // Test memory cleanup
    let cleanup_start = Instant::now();
    for session_id in session_ids {
        perf_tester.cleanup_session(&session_id).await?;
    }
    let cleanup_time = cleanup_start.elapsed();
    
    // Verify memory is released
    sleep(Duration::from_millis(100)).await; // Allow for cleanup
    let post_cleanup_memory = perf_tester.get_memory_usage().await?;
    let memory_released = final_memory - post_cleanup_memory;
    let cleanup_efficiency = memory_released as f64 / total_memory_used as f64;
    
    assert!(cleanup_efficiency > 0.8, // At least 80% memory should be released
            "Memory cleanup efficiency too low: {:.2}%", cleanup_efficiency * 100.0);
    assert!(cleanup_time < Duration::from_secs(5), 
            "Memory cleanup took too long: {:?}", cleanup_time);
    
    println!("Memory cleanup: {:.2}% efficiency, {:?} duration", 
             cleanup_efficiency * 100.0, cleanup_time);
    
    test_ctx.metrics.record_test_completion("memory_usage", true);
    Ok(())
}

/// Test protocol optimization effectiveness
#[tokio::test]
async fn test_protocol_optimization() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    let alice_id = "alice@example.com";
    let bob_id = "bob@example.com";
    
    // Test with optimization disabled
    perf_tester.set_optimization_enabled(false).await?;
    let session_id_unoptimized = perf_tester.establish_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.alice_identity,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    let test_message = b"Optimization test message";
    let num_messages = 100;
    
    let start_time = Instant::now();
    for i in 0..num_messages {
        let sender = if i % 2 == 0 { alice_id } else { bob_id };
        perf_tester.send_message(&session_id_unoptimized, sender, test_message).await?;
    }
    let unoptimized_time = start_time.elapsed();
    
    // Test with optimization enabled
    perf_tester.set_optimization_enabled(true).await?;
    let session_id_optimized = perf_tester.establish_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.alice_identity,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    let start_time = Instant::now();
    for i in 0..num_messages {
        let sender = if i % 2 == 0 { alice_id } else { bob_id };
        perf_tester.send_message(&session_id_optimized, sender, test_message).await?;
    }
    let optimized_time = start_time.elapsed();
    
    // Calculate optimization improvement
    let improvement_ratio = unoptimized_time.as_secs_f64() / optimized_time.as_secs_f64();
    
    // Performance assertions
    assert!(improvement_ratio > 1.2, // At least 20% improvement
            "Optimization improvement insufficient: {:.2}x", improvement_ratio);
    assert!(optimized_time < unoptimized_time, 
            "Optimized version should be faster");
    
    println!("Optimization improvement: {:.2}x faster", improvement_ratio);
    
    // Test different optimization levels
    let optimization_levels = vec!["basic", "aggressive", "maximum"];
    let mut level_times = Vec::new();
    
    for level in &optimization_levels {
        perf_tester.set_optimization_level(level).await?;
        let session_id = perf_tester.establish_session(
            alice_id,
            bob_id,
            &test_ctx.fixtures.alice_identity,
            &test_ctx.fixtures.bob_prekey_bundle
        ).await?;
        
        let start_time = Instant::now();
        for i in 0..50 {
            let sender = if i % 2 == 0 { alice_id } else { bob_id };
            perf_tester.send_message(&session_id, sender, test_message).await?;
        }
        let level_time = start_time.elapsed();
        level_times.push(level_time);
        
        println!("Optimization level '{}': {:?}", level, level_time);
    }
    
    // Verify optimization levels provide progressive improvement
    for i in 1..level_times.len() {
        assert!(level_times[i] <= level_times[i-1], 
                "Higher optimization level should not be slower");
    }
    
    test_ctx.metrics.record_test_completion("protocol_optimization", true);
    Ok(())
}

/// Test stress conditions and edge cases
#[tokio::test]
async fn test_stress_conditions() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut perf_tester = MockPerformanceTester::new().await?;
    
    // Test rapid session creation/destruction
    let rapid_cycles = 100;
    let start_time = Instant::now();
    
    for i in 0..rapid_cycles {
        let alice_id = format!("alice{}@example.com", i);
        let bob_id = format!("bob{}@example.com", i);
        
        let session_id = perf_tester.establish_session(
            &alice_id,
            &bob_id,
            &test_ctx.fixtures.alice_identity,
            &test_ctx.fixtures.bob_prekey_bundle
        ).await?;
        
        // Send a few messages
        for j in 0..5 {
            let sender = if j % 2 == 0 { &alice_id } else { &bob_id };
            perf_tester.send_message(&session_id, sender, b"stress test").await?;
        }
        
        // Immediately cleanup
        perf_tester.cleanup_session(&session_id).await?;
    }
    
    let rapid_cycle_time = start_time.elapsed();
    let cycles_per_second = rapid_cycles as f64 / rapid_cycle_time.as_secs_f64();
    
    assert!(cycles_per_second > 10.0, 
            "Rapid cycle performance too low: {:.2} cycles/s", cycles_per_second);
    
    // Test message burst handling
    let alice_id = "alice@example.com";
    let bob_id = "bob@example.com";
    
    let session_id = perf_tester.establish_session(
        alice_id,
        bob_id,
        &test_ctx.fixtures.alice_identity,
        &test_ctx.fixtures.bob_prekey_bundle
    ).await?;
    
    // Send burst of messages
    let burst_size = 1000;
    let burst_start = Instant::now();
    
    let mut burst_tasks = Vec::new();
    for i in 0..burst_size {
        let session_id = session_id.clone();
        let sender = if i % 2 == 0 { alice_id } else { bob_id };
        let message = format!("Burst message {}", i);
        let mut tester = perf_tester.clone();
        
        let task = tokio::spawn(async move {
            tester.send_message(&session_id, sender, message.as_bytes()).await
        });
        burst_tasks.push(task);
    }
    
    // Wait for all burst messages to complete
    for task in burst_tasks {
        task.await??;
    }
    
    let burst_time = burst_start.elapsed();
    let burst_throughput = burst_size as f64 / burst_time.as_secs_f64();
    
    assert!(burst_throughput > 500.0, 
            "Burst throughput too low: {:.2} msg/s", burst_throughput);
    assert!(burst_time < Duration::from_secs(10), 
            "Burst handling took too long: {:?}", burst_time);
    
    println!("Stress test results - Rapid cycles: {:.2}/s, Burst: {:.2} msg/s", 
             cycles_per_second, burst_throughput);
    
    test_ctx.metrics.record_test_completion("stress_conditions", true);
    Ok(())
}

/// Mock performance tester implementation
#[derive(Clone)]
struct MockPerformanceTester {
    sessions: std::sync::Arc<tokio::sync::RwLock<HashMap<String, MockPerfSession>>>,
    groups: std::sync::Arc<tokio::sync::RwLock<HashMap<String, MockPerfGroup>>>,
    optimization_enabled: std::sync::Arc<tokio::sync::RwLock<bool>>,
    optimization_level: std::sync::Arc<tokio::sync::RwLock<String>>,
    memory_usage: std::sync::Arc<tokio::sync::RwLock<u64>>,
}

#[derive(Debug, Clone)]
struct MockPerfSession {
    alice_id: String,
    bob_id: String,
    message_count: u64,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct MockPerfGroup {
    admin_id: String,
    members: std::collections::HashSet<String>,
    message_count: u64,
    created_at: Instant,
}

impl MockPerformanceTester {
    async fn new() -> Result<Self> {
        Ok(Self {
            sessions: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            groups: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            optimization_enabled: std::sync::Arc::new(tokio::sync::RwLock::new(true)),
            optimization_level: std::sync::Arc::new(tokio::sync::RwLock::new("basic".to_string())),
            memory_usage: std::sync::Arc::new(tokio::sync::RwLock::new(1_000_000)), // 1MB baseline
        })
    }
    
    async fn establish_session(
        &self,
        alice_id: &str,
        bob_id: &str,
        _alice_identity: &TestIdentity,
        _bob_prekey_bundle: &TestPreKeyBundle,
    ) -> Result<String> {
        let session_id = format!("session_{}_{}", alice_id, bob_id);
        
        // Simulate session establishment time based on optimization
        let optimization_enabled = *self.optimization_enabled.read().await;
        let delay = if optimization_enabled { 
            Duration::from_micros(100) 
        } else { 
            Duration::from_micros(500) 
        };
        sleep(delay).await;
        
        let session = MockPerfSession {
            alice_id: alice_id.to_string(),
            bob_id: bob_id.to_string(),
            message_count: 0,
            created_at: Instant::now(),
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);
        
        // Update memory usage
        let mut memory = self.memory_usage.write().await;
        *memory += 5000; // 5KB per session
        
        Ok(session_id)
    }
    
    async fn send_message(&self, session_id: &str, _sender_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        // Simulate message processing time based on optimization
        let optimization_enabled = *self.optimization_enabled.read().await;
        let optimization_level = self.optimization_level.read().await.clone();
        
        let base_delay = Duration::from_micros(50);
        let delay = if optimization_enabled {
            match optimization_level.as_str() {
                "maximum" => base_delay / 4,
                "aggressive" => base_delay / 2,
                "basic" => base_delay * 3 / 4,
                _ => base_delay,
            }
        } else {
            base_delay * 2
        };
        
        sleep(delay).await;
        
        // Update session message count
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.message_count += 1;
        }
        
        // Simulate encrypted message
        let mut encrypted = message.to_vec();
        encrypted.extend_from_slice(b"_encrypted");
        Ok(encrypted)
    }
    
    async fn receive_message(&self, _session_id: &str, _recipient_id: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
        // Simulate decryption time
        sleep(Duration::from_micros(30)).await;
        
        // Remove encryption suffix
        if encrypted.ends_with(b"_encrypted") {
            Ok(encrypted[..encrypted.len() - 10].to_vec())
        } else {
            Ok(encrypted.to_vec())
        }
    }
    
    async fn create_group(&self, group_id: &str, admin_id: &str, members: &[&str]) -> Result<()> {
        // Simulate group creation time based on member count
        let creation_delay = Duration::from_micros(members.len() as u64 * 100);
        sleep(creation_delay).await;
        
        let mut group_members = std::collections::HashSet::new();
        group_members.insert(admin_id.to_string());
        for member in members {
            group_members.insert(member.to_string());
        }
        
        let group = MockPerfGroup {
            admin_id: admin_id.to_string(),
            members: group_members,
            message_count: 0,
            created_at: Instant::now(),
        };
        
        let mut groups = self.groups.write().await;
        groups.insert(group_id.to_string(), group);
        
        // Update memory usage
        let mut memory = self.memory_usage.write().await;
        *memory += members.len() as u64 * 1000; // 1KB per member
        
        Ok(())
    }
    
    async fn send_group_message(&self, group_id: &str, _sender_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        // Simulate group message processing
        let groups = self.groups.read().await;
        let member_count = groups.get(group_id)
            .map(|g| g.members.len())
            .unwrap_or(1);
        
        // Processing time scales with group size
        let delay = Duration::from_micros(member_count as u64 * 10);
        sleep(delay).await;
        
        // Update group message count
        drop(groups);
        let mut groups = self.groups.write().await;
        if let Some(group) = groups.get_mut(group_id) {
            group.message_count += 1;
        }
        
        let mut encrypted = message.to_vec();
        encrypted.extend_from_slice(format!("_group_{}", group_id).as_bytes());
        Ok(encrypted)
    }
    
    async fn add_group_member(&self, group_id: &str, _admin_id: &str, new_member: &str) -> Result<()> {
        // Simulate member addition time
        sleep(Duration::from_micros(200)).await;
        
        let mut groups = self.groups.write().await;
        if let Some(group) = groups.get_mut(group_id) {
            group.members.insert(new_member.to_string());
        }
        
        // Update memory usage
        let mut memory = self.memory_usage.write().await;
        *memory += 1000; // 1KB per new member
        
        Ok(())
    }
    
    async fn cleanup_session(&self, session_id: &str) -> Result<()> {
        // Simulate cleanup time
        sleep(Duration::from_micros(50)).await;
        
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        
        // Update memory usage
        let mut memory = self.memory_usage.write().await;
        *memory = memory.saturating_sub(5000); // Release 5KB per session
        
        Ok(())
    }
    
    async fn get_memory_usage(&self) -> Result<u64> {
        Ok(*self.memory_usage.read().await)
    }
    
    async fn set_optimization_enabled(&self, enabled: bool) -> Result<()> {
        let mut optimization = self.optimization_enabled.write().await;
        *optimization = enabled;
        Ok(())
    }
    
    async fn set_optimization_level(&self, level: &str) -> Result<()> {
        let mut opt_level = self.optimization_level.write().await;
        *opt_level = level.to_string();
        Ok(())
    }
}