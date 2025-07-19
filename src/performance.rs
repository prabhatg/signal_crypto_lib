/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Performance optimizations with LRU caching, object pooling, and memory management.
 * Implements session caching, key derivation optimization, memory pools,
 * and performance monitoring for high-throughput cryptographic operations.
 */

// signal_crypto_lib/src/performance.rs
// Performance optimizations including caching and object pooling

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use crate::types::*;
use crate::SessionState;
use crate::protocol::sesame::GroupSessionState;

/// LRU Cache for frequently accessed data
pub struct LruCache<K, V> {
    capacity: usize,
    map: HashMap<K, (V, usize)>, // (value, access_order)
    access_counter: usize,
}

impl<K: Clone + std::hash::Hash + Eq, V: Clone> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            access_counter: 0,
        }
    }
    
    pub fn get(&mut self, key: &K) -> Option<V> {
        if let Some((value, _)) = self.map.get(key) {
            let value_clone = value.clone();
            self.access_counter += 1;
            self.map.insert(key.clone(), (value_clone.clone(), self.access_counter));
            Some(value_clone)
        } else {
            None
        }
    }
    
    pub fn put(&mut self, key: K, value: V) {
        if self.map.len() >= self.capacity && !self.map.contains_key(&key) {
            // Remove least recently used item
            if let Some((lru_key, _)) = self.map.iter()
                .min_by_key(|(_, (_, access_order))| *access_order)
                .map(|(k, (_, order))| (k.clone(), *order)) {
                self.map.remove(&lru_key);
            }
        }
        
        self.access_counter += 1;
        self.map.insert(key, (value, self.access_counter));
    }
    
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key).map(|(value, _)| value)
    }
    
    pub fn clear(&mut self) {
        self.map.clear();
        self.access_counter = 0;
    }
    
    pub fn len(&self) -> usize {
        self.map.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Session cache for quick access to active sessions
pub struct SessionCache {
    individual_sessions: Arc<RwLock<LruCache<String, SessionState>>>,
    group_sessions: Arc<RwLock<LruCache<String, GroupSessionState>>>,
    cache_stats: Arc<Mutex<CacheStats>>,
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl SessionCache {
    pub fn new(individual_capacity: usize, group_capacity: usize) -> Self {
        Self {
            individual_sessions: Arc::new(RwLock::new(LruCache::new(individual_capacity))),
            group_sessions: Arc::new(RwLock::new(LruCache::new(group_capacity))),
            cache_stats: Arc::new(Mutex::new(CacheStats::default())),
        }
    }
    
    pub fn get_individual_session(&self, session_id: &str) -> Option<SessionState> {
        let mut cache = self.individual_sessions.write().unwrap();
        let result = cache.get(&session_id.to_string());
        
        let mut stats = self.cache_stats.lock().unwrap();
        if result.is_some() {
            stats.hits += 1;
        } else {
            stats.misses += 1;
        }
        
        result
    }
    
    pub fn put_individual_session(&self, session_id: String, session: SessionState) {
        let mut cache = self.individual_sessions.write().unwrap();
        let was_full = cache.len() >= cache.capacity;
        cache.put(session_id, session);
        
        if was_full {
            let mut stats = self.cache_stats.lock().unwrap();
            stats.evictions += 1;
        }
    }
    
    pub fn get_group_session(&self, group_id: &str) -> Option<GroupSessionState> {
        let mut cache = self.group_sessions.write().unwrap();
        let result = cache.get(&group_id.to_string());
        
        let mut stats = self.cache_stats.lock().unwrap();
        if result.is_some() {
            stats.hits += 1;
        } else {
            stats.misses += 1;
        }
        
        result
    }
    
    pub fn put_group_session(&self, group_id: String, session: GroupSessionState) {
        let mut cache = self.group_sessions.write().unwrap();
        let was_full = cache.len() >= cache.capacity;
        cache.put(group_id, session);
        
        if was_full {
            let mut stats = self.cache_stats.lock().unwrap();
            stats.evictions += 1;
        }
    }
    
    pub fn remove_individual_session(&self, session_id: &str) {
        let mut cache = self.individual_sessions.write().unwrap();
        cache.remove(&session_id.to_string());
    }
    
    pub fn remove_group_session(&self, group_id: &str) {
        let mut cache = self.group_sessions.write().unwrap();
        cache.remove(&group_id.to_string());
    }
    
    pub fn get_stats(&self) -> CacheStats {
        let stats = self.cache_stats.lock().unwrap();
        CacheStats {
            hits: stats.hits,
            misses: stats.misses,
            evictions: stats.evictions,
        }
    }
    
    pub fn get_hit_ratio(&self) -> f64 {
        let stats = self.cache_stats.lock().unwrap();
        let total = stats.hits + stats.misses;
        if total > 0 {
            stats.hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

/// Object pool for reusing expensive-to-create objects
pub struct ObjectPool<T> {
    objects: Arc<Mutex<VecDeque<T>>>,
    factory: Arc<dyn Fn() -> T + Send + Sync>,
    max_size: usize,
}

impl<T> ObjectPool<T> {
    pub fn new<F>(factory: F, max_size: usize) -> Self 
    where 
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            objects: Arc::new(Mutex::new(VecDeque::new())),
            factory: Arc::new(factory),
            max_size,
        }
    }
    
    pub fn get(&self) -> PooledObject<T> {
        let mut objects = self.objects.lock().unwrap();
        let object = objects.pop_front().unwrap_or_else(|| (self.factory)());
        
        PooledObject {
            object: Some(object),
            pool: self.objects.clone(),
            max_size: self.max_size,
        }
    }
    
    pub fn size(&self) -> usize {
        self.objects.lock().unwrap().len()
    }
}

/// RAII wrapper for pooled objects
pub struct PooledObject<T> {
    object: Option<T>,
    pool: Arc<Mutex<VecDeque<T>>>,
    max_size: usize,
}

impl<T> PooledObject<T> {
    pub fn as_ref(&self) -> &T {
        self.object.as_ref().unwrap()
    }
    
    pub fn as_mut(&mut self) -> &mut T {
        self.object.as_mut().unwrap()
    }
}

impl<T> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(object) = self.object.take() {
            let mut pool = self.pool.lock().unwrap();
            if pool.len() < self.max_size {
                pool.push_back(object);
            }
        }
    }
}

impl<T> std::ops::Deref for PooledObject<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.object.as_ref().unwrap()
    }
}

impl<T> std::ops::DerefMut for PooledObject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.object.as_mut().unwrap()
    }
}

/// Key derivation cache for expensive HKDF operations
pub struct KeyDerivationCache {
    cache: Arc<RwLock<LruCache<KeyDerivationKey, Vec<u8>>>>,
    max_age: Duration,
    timestamps: Arc<RwLock<HashMap<KeyDerivationKey, SystemTime>>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct KeyDerivationKey {
    input_hash: [u8; 32],
    salt_hash: [u8; 32],
    info_hash: [u8; 32],
    output_len: usize,
}

impl KeyDerivationCache {
    pub fn new(capacity: usize, max_age: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
            max_age,
            timestamps: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub fn get_or_derive<F>(&self, input: &[u8], salt: &[u8], info: &[u8], output_len: usize, derive_fn: F) -> Vec<u8>
    where
        F: FnOnce() -> Vec<u8>,
    {
        let key = self.create_key(input, salt, info, output_len);
        
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            let timestamps = self.timestamps.read().unwrap();
            
            if let Some(cached_value) = cache.map.get(&key) {
                if let Some(&timestamp) = timestamps.get(&key) {
                    if timestamp.elapsed().unwrap_or(self.max_age) < self.max_age {
                        return cached_value.0.clone();
                    }
                }
            }
        }
        
        // Derive new value
        let derived = derive_fn();
        
        // Cache the result
        {
            let mut cache = self.cache.write().unwrap();
            let mut timestamps = self.timestamps.write().unwrap();
            
            cache.put(key.clone(), derived.clone());
            timestamps.insert(key, SystemTime::now());
        }
        
        derived
    }
    
    fn create_key(&self, input: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> KeyDerivationKey {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(input);
        let input_hash: [u8; 32] = hasher.finalize().into();
        
        let mut hasher = Sha256::new();
        hasher.update(salt);
        let salt_hash: [u8; 32] = hasher.finalize().into();
        
        let mut hasher = Sha256::new();
        hasher.update(info);
        let info_hash: [u8; 32] = hasher.finalize().into();
        
        KeyDerivationKey {
            input_hash,
            salt_hash,
            info_hash,
            output_len,
        }
    }
    
    pub fn clear_expired(&self) {
        let mut cache = self.cache.write().unwrap();
        let mut timestamps = self.timestamps.write().unwrap();
        
        let now = SystemTime::now();
        let expired_keys: Vec<_> = timestamps.iter()
            .filter(|(_, &timestamp)| now.duration_since(timestamp).unwrap_or(Duration::ZERO) >= self.max_age)
            .map(|(key, _)| key.clone())
            .collect();
        
        for key in expired_keys {
            cache.remove(&key);
            timestamps.remove(&key);
        }
    }
}

/// Memory pool for reducing allocations
pub struct MemoryPool {
    small_buffers: ObjectPool<Vec<u8>>,  // 1KB buffers
    medium_buffers: ObjectPool<Vec<u8>>, // 4KB buffers
    large_buffers: ObjectPool<Vec<u8>>,  // 16KB buffers
}

impl MemoryPool {
    pub fn new() -> Self {
        Self {
            small_buffers: ObjectPool::new(|| Vec::with_capacity(1024), 50),
            medium_buffers: ObjectPool::new(|| Vec::with_capacity(4096), 20),
            large_buffers: ObjectPool::new(|| Vec::with_capacity(16384), 10),
        }
    }
    
    pub fn get_buffer(&self, min_size: usize) -> PooledObject<Vec<u8>> {
        if min_size <= 1024 {
            let mut buffer = self.small_buffers.get();
            buffer.clear();
            buffer.reserve(min_size);
            buffer
        } else if min_size <= 4096 {
            let mut buffer = self.medium_buffers.get();
            buffer.clear();
            buffer.reserve(min_size);
            buffer
        } else {
            let mut buffer = self.large_buffers.get();
            buffer.clear();
            buffer.reserve(min_size);
            buffer
        }
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance monitoring and optimization hints
#[derive(Debug, Default)]
pub struct PerformanceMonitor {
    pub operation_times: HashMap<String, Vec<Duration>>,
    pub memory_usage: HashMap<String, usize>,
    pub cache_performance: HashMap<String, CacheStats>,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn record_operation_time(&mut self, operation: &str, duration: Duration) {
        self.operation_times.entry(operation.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
    }
    
    pub fn record_memory_usage(&mut self, component: &str, bytes: usize) {
        self.memory_usage.insert(component.to_string(), bytes);
    }
    
    pub fn record_cache_stats(&mut self, cache_name: &str, stats: CacheStats) {
        self.cache_performance.insert(cache_name.to_string(), stats);
    }
    
    pub fn get_average_operation_time(&self, operation: &str) -> Option<Duration> {
        if let Some(times) = self.operation_times.get(operation) {
            if !times.is_empty() {
                let total: Duration = times.iter().sum();
                Some(total / times.len() as u32)
            } else {
                None
            }
        } else {
            None
        }
    }
    
    pub fn get_operation_percentile(&self, operation: &str, percentile: f64) -> Option<Duration> {
        if let Some(times) = self.operation_times.get(operation) {
            if times.is_empty() {
                return None;
            }
            
            let mut sorted_times = times.clone();
            sorted_times.sort();
            
            let index = ((sorted_times.len() as f64 - 1.0) * percentile / 100.0).round() as usize;
            Some(sorted_times[index.min(sorted_times.len() - 1)])
        } else {
            None
        }
    }
    
    pub fn get_total_memory_usage(&self) -> usize {
        self.memory_usage.values().sum()
    }
    
    pub fn get_optimization_hints(&self) -> Vec<String> {
        let mut hints = Vec::new();
        
        // Check for slow operations
        for (operation, times) in &self.operation_times {
            if let Some(avg_time) = self.get_average_operation_time(operation) {
                if avg_time > Duration::from_millis(100) {
                    hints.push(format!("Operation '{}' is slow (avg: {:?})", operation, avg_time));
                }
            }
        }
        
        // Check cache hit ratios
        for (cache_name, stats) in &self.cache_performance {
            let total = stats.hits + stats.misses;
            if total > 0 {
                let hit_ratio = stats.hits as f64 / total as f64;
                if hit_ratio < 0.8 {
                    hints.push(format!("Cache '{}' has low hit ratio: {:.2}%", cache_name, hit_ratio * 100.0));
                }
            }
        }
        
        // Check memory usage
        let total_memory = self.get_total_memory_usage();
        if total_memory > 100 * 1024 * 1024 { // 100MB
            hints.push(format!("High memory usage: {} MB", total_memory / (1024 * 1024)));
        }
        
        hints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lru_cache() {
        let mut cache = LruCache::new(2);
        
        cache.put("a", 1);
        cache.put("b", 2);
        
        assert_eq!(cache.get(&"a"), Some(1)); // "a" gets access order 3
        assert_eq!(cache.get(&"b"), Some(2)); // "b" gets access order 4 (most recent)
        
        // Adding third item should evict least recently used
        // After getting "a" and "b", "b" was accessed more recently, so "a" should be evicted
        cache.put("c", 3);
        assert_eq!(cache.get(&"b"), Some(2)); // "b" should still be there
        assert_eq!(cache.get(&"c"), Some(3)); // "c" should be there
        assert_eq!(cache.get(&"a"), None); // "a" was evicted (least recently used)
    }
    
    #[test]
    fn test_session_cache() {
        let cache = SessionCache::new(2, 2);
        
        let session1 = SessionState {
            session_id: "session1".to_string(),
            registration_id: 1,
            device_id: 1,
            dh_self_private: vec![0u8; 32],
            dh_self_public: vec![0u8; 32],
            dh_remote: None,
            root_key: vec![0u8; 32],
            chain_key_send: None,
            chain_key_recv: None,
            header_key_send: None,
            header_key_recv: None,
            next_header_key_send: None,
            next_header_key_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            mk_skipped: std::collections::HashMap::new(),
            max_skip: 1000,
        };
        let session2 = SessionState {
            session_id: "session2".to_string(),
            registration_id: 2,
            device_id: 2,
            dh_self_private: vec![0u8; 32],
            dh_self_public: vec![0u8; 32],
            dh_remote: None,
            root_key: vec![0u8; 32],
            chain_key_send: None,
            chain_key_recv: None,
            header_key_send: None,
            header_key_recv: None,
            next_header_key_send: None,
            next_header_key_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            mk_skipped: std::collections::HashMap::new(),
            max_skip: 1000,
        };
        
        cache.put_individual_session("s1".to_string(), session1.clone());
        cache.put_individual_session("s2".to_string(), session2.clone());
        
        assert!(cache.get_individual_session("s1").is_some());
        assert!(cache.get_individual_session("s2").is_some());
        
        let stats = cache.get_stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 0);
    }
    
    #[test]
    fn test_object_pool() {
        let pool = ObjectPool::new(|| Vec::<u8>::with_capacity(1024), 5);
        
        {
            let mut obj1 = pool.get();
            obj1.push(1);
            obj1.push(2);
            assert_eq!(obj1.len(), 2);
        } // obj1 is returned to pool here
        
        assert_eq!(pool.size(), 1);
        
        let mut obj2 = pool.get();
        // The pooled object retains its data, so we need to clear it manually
        // This is the expected behavior - the pool doesn't automatically clear objects
        assert_eq!(obj2.len(), 2); // Should contain previous data
        obj2.clear(); // Clear it manually
        assert_eq!(obj2.len(), 0); // Now it should be empty
    }
    
    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new();
        
        let small_buffer = pool.get_buffer(512);
        assert!(small_buffer.capacity() >= 512);
        
        let large_buffer = pool.get_buffer(8192);
        assert!(large_buffer.capacity() >= 8192);
    }
    
    #[test]
    fn test_performance_monitor() {
        let mut monitor = PerformanceMonitor::new();
        
        monitor.record_operation_time("encrypt", Duration::from_millis(5));
        monitor.record_operation_time("encrypt", Duration::from_millis(7));
        monitor.record_operation_time("encrypt", Duration::from_millis(3));
        
        let avg_time = monitor.get_average_operation_time("encrypt").unwrap();
        assert_eq!(avg_time, Duration::from_millis(5));
        
        let p95 = monitor.get_operation_percentile("encrypt", 95.0).unwrap();
        assert_eq!(p95, Duration::from_millis(7));
    }
}