// tests/unit/prekey.rs
//! Unit tests for prekey management functionality

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

// Mock prekey structures
#[derive(Debug, Clone)]
struct MockPreKey {
    id: u32,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    created_at: u64,
}

impl MockPreKey {
    fn new(id: u32) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id,
            public_key: vec![id as u8; 32],
            private_key: vec![(id + 100) as u8; 32],
            created_at: timestamp,
        }
    }
    
    fn id(&self) -> u32 {
        self.id
    }
    
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    
    fn created_at(&self) -> u64 {
        self.created_at
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.private_key);
        data.extend_from_slice(&self.created_at.to_be_bytes());
        data
    }
    
    fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 72 { // 4 + 32 + 32 + 8
            return Err("Invalid prekey data".into());
        }
        
        let id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let public_key = data[4..36].to_vec();
        let private_key = data[36..68].to_vec();
        let created_at = u64::from_be_bytes([
            data[68], data[69], data[70], data[71],
            data[72], data[73], data[74], data[75]
        ]);
        
        Ok(Self {
            id,
            public_key,
            private_key,
            created_at,
        })
    }
}

#[derive(Debug, Clone)]
struct MockSignedPreKey {
    id: u32,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    signature: Vec<u8>,
    created_at: u64,
}

impl MockSignedPreKey {
    fn new(id: u32, identity_private_key: &[u8]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let public_key = vec![id as u8; 32];
        let private_key = vec![(id + 200) as u8; 32];
        
        // Mock signature generation
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&public_key);
        signature_data.extend_from_slice(identity_private_key);
        let signature = signature_data.iter().map(|&b| b.wrapping_add(1)).collect();
        
        Self {
            id,
            public_key,
            private_key,
            signature,
            created_at: timestamp,
        }
    }
    
    fn id(&self) -> u32 {
        self.id
    }
    
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    
    fn created_at(&self) -> u64 {
        self.created_at
    }
    
    fn verify_signature(&self, identity_public_key: &[u8]) -> bool {
        // Mock signature verification
        let mut expected_signature_data = Vec::new();
        expected_signature_data.extend_from_slice(&self.public_key);
        expected_signature_data.extend_from_slice(identity_public_key);
        let expected_signature: Vec<u8> = expected_signature_data
            .iter()
            .map(|&b| b.wrapping_add(1))
            .collect();
        
        self.signature == expected_signature
    }
}

#[derive(Debug, Clone)]
struct MockPreKeyBundle {
    identity_key: Vec<u8>,
    signed_prekey: MockSignedPreKey,
    prekey: Option<MockPreKey>,
    registration_id: u32,
}

impl MockPreKeyBundle {
    fn new(
        identity_key: Vec<u8>,
        signed_prekey: MockSignedPreKey,
        prekey: Option<MockPreKey>,
        registration_id: u32,
    ) -> Self {
        Self {
            identity_key,
            signed_prekey,
            prekey,
            registration_id,
        }
    }
    
    fn identity_key(&self) -> &[u8] {
        &self.identity_key
    }
    
    fn signed_prekey(&self) -> &MockSignedPreKey {
        &self.signed_prekey
    }
    
    fn prekey(&self) -> Option<&MockPreKey> {
        self.prekey.as_ref()
    }
    
    fn registration_id(&self) -> u32 {
        self.registration_id
    }
}

// Mock prekey manager
struct MockPreKeyManager {
    prekeys: RwLock<HashMap<u32, MockPreKey>>,
    signed_prekeys: RwLock<HashMap<u32, MockSignedPreKey>>,
    next_prekey_id: RwLock<u32>,
    next_signed_prekey_id: RwLock<u32>,
    registration_id: u32,
}

impl MockPreKeyManager {
    fn new(registration_id: u32) -> Self {
        Self {
            prekeys: RwLock::new(HashMap::new()),
            signed_prekeys: RwLock::new(HashMap::new()),
            next_prekey_id: RwLock::new(1),
            next_signed_prekey_id: RwLock::new(1),
            registration_id,
        }
    }
    
    async fn generate_prekeys(&self, count: u32) -> Result<Vec<MockPreKey>> {
        let mut prekeys = Vec::new();
        let mut next_id = self.next_prekey_id.write().await;
        let mut stored_prekeys = self.prekeys.write().await;
        
        for _ in 0..count {
            let prekey = MockPreKey::new(*next_id);
            stored_prekeys.insert(*next_id, prekey.clone());
            prekeys.push(prekey);
            *next_id += 1;
        }
        
        Ok(prekeys)
    }
    
    async fn generate_signed_prekey(&self, identity_private_key: &[u8]) -> Result<MockSignedPreKey> {
        let mut next_id = self.next_signed_prekey_id.write().await;
        let signed_prekey = MockSignedPreKey::new(*next_id, identity_private_key);
        
        let mut stored_signed_prekeys = self.signed_prekeys.write().await;
        stored_signed_prekeys.insert(*next_id, signed_prekey.clone());
        
        *next_id += 1;
        Ok(signed_prekey)
    }
    
    async fn get_prekey(&self, id: u32) -> Result<Option<MockPreKey>> {
        let prekeys = self.prekeys.read().await;
        Ok(prekeys.get(&id).cloned())
    }
    
    async fn get_signed_prekey(&self, id: u32) -> Result<Option<MockSignedPreKey>> {
        let signed_prekeys = self.signed_prekeys.read().await;
        Ok(signed_prekeys.get(&id).cloned())
    }
    
    async fn remove_prekey(&self, id: u32) -> Result<bool> {
        let mut prekeys = self.prekeys.write().await;
        Ok(prekeys.remove(&id).is_some())
    }
    
    async fn remove_signed_prekey(&self, id: u32) -> Result<bool> {
        let mut signed_prekeys = self.signed_prekeys.write().await;
        Ok(signed_prekeys.remove(&id).is_some())
    }
    
    async fn list_prekeys(&self) -> Result<Vec<u32>> {
        let prekeys = self.prekeys.read().await;
        Ok(prekeys.keys().cloned().collect())
    }
    
    async fn list_signed_prekeys(&self) -> Result<Vec<u32>> {
        let signed_prekeys = self.signed_prekeys.read().await;
        Ok(signed_prekeys.keys().cloned().collect())
    }
    
    async fn count_prekeys(&self) -> Result<usize> {
        let prekeys = self.prekeys.read().await;
        Ok(prekeys.len())
    }
    
    async fn count_signed_prekeys(&self) -> Result<usize> {
        let signed_prekeys = self.signed_prekeys.read().await;
        Ok(signed_prekeys.len())
    }
    
    async fn create_prekey_bundle(
        &self,
        identity_key: Vec<u8>,
        signed_prekey_id: u32,
        prekey_id: Option<u32>,
    ) -> Result<MockPreKeyBundle> {
        let signed_prekey = self.get_signed_prekey(signed_prekey_id).await?
            .ok_or("Signed prekey not found")?;
        
        let prekey = if let Some(id) = prekey_id {
            self.get_prekey(id).await?
        } else {
            None
        };
        
        Ok(MockPreKeyBundle::new(
            identity_key,
            signed_prekey,
            prekey,
            self.registration_id,
        ))
    }
    
    async fn cleanup_old_prekeys(&self, max_age_seconds: u64) -> Result<usize> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut prekeys = self.prekeys.write().await;
        let mut removed_count = 0;
        
        prekeys.retain(|_, prekey| {
            let age = current_time.saturating_sub(prekey.created_at);
            if age > max_age_seconds {
                removed_count += 1;
                false
            } else {
                true
            }
        });
        
        Ok(removed_count)
    }
    
    async fn cleanup_old_signed_prekeys(&self, max_age_seconds: u64, keep_latest: usize) -> Result<usize> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut signed_prekeys = self.signed_prekeys.write().await;
        
        // Sort by creation time (newest first)
        let mut sorted_keys: Vec<_> = signed_prekeys.iter().collect();
        sorted_keys.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
        
        let mut removed_count = 0;
        let mut keys_to_remove = Vec::new();
        
        for (i, (id, signed_prekey)) in sorted_keys.iter().enumerate() {
            if i >= keep_latest {
                let age = current_time.saturating_sub(signed_prekey.created_at);
                if age > max_age_seconds {
                    keys_to_remove.push(**id);
                    removed_count += 1;
                }
            }
        }
        
        for id in keys_to_remove {
            signed_prekeys.remove(&id);
        }
        
        Ok(removed_count)
    }
    
    async fn export_prekeys(&self) -> Result<Vec<u8>> {
        let prekeys = self.prekeys.read().await;
        let signed_prekeys = self.signed_prekeys.read().await;
        
        let mut export_data = Vec::new();
        
        // Export prekeys count
        export_data.extend_from_slice(&(prekeys.len() as u32).to_be_bytes());
        
        // Export prekeys
        for prekey in prekeys.values() {
            let serialized = prekey.serialize();
            export_data.extend_from_slice(&(serialized.len() as u32).to_be_bytes());
            export_data.extend_from_slice(&serialized);
        }
        
        // Export signed prekeys count
        export_data.extend_from_slice(&(signed_prekeys.len() as u32).to_be_bytes());
        
        // Export signed prekeys (simplified serialization)
        for signed_prekey in signed_prekeys.values() {
            export_data.extend_from_slice(&signed_prekey.id.to_be_bytes());
            export_data.extend_from_slice(&(signed_prekey.public_key.len() as u32).to_be_bytes());
            export_data.extend_from_slice(&signed_prekey.public_key);
        }
        
        Ok(export_data)
    }
    
    async fn import_prekeys(&self, data: &[u8]) -> Result<usize> {
        if data.len() < 4 {
            return Err("Invalid import data".into());
        }
        
        let mut offset = 0;
        let prekey_count = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;
        
        let mut imported_count = 0;
        let mut prekeys = self.prekeys.write().await;
        
        for _ in 0..prekey_count {
            if offset + 4 > data.len() {
                break;
            }
            
            let prekey_size = u32::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]) as usize;
            offset += 4;
            
            if offset + prekey_size > data.len() {
                break;
            }
            
            if let Ok(prekey) = MockPreKey::deserialize(&data[offset..offset + prekey_size]) {
                prekeys.insert(prekey.id, prekey);
                imported_count += 1;
            }
            
            offset += prekey_size;
        }
        
        Ok(imported_count)
    }
    
    async fn rotate_signed_prekey(&self, identity_private_key: &[u8]) -> Result<MockSignedPreKey> {
        // Generate new signed prekey
        let new_signed_prekey = self.generate_signed_prekey(identity_private_key).await?;
        
        // Clean up old signed prekeys (keep only the latest 3)
        self.cleanup_old_signed_prekeys(0, 3).await?;
        
        Ok(new_signed_prekey)
    }
    
    async fn get_prekey_statistics(&self) -> Result<PreKeyStatistics> {
        let prekeys = self.prekeys.read().await;
        let signed_prekeys = self.signed_prekeys.read().await;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut oldest_prekey_age = 0u64;
        let mut newest_prekey_age = u64::MAX;
        
        for prekey in prekeys.values() {
            let age = current_time.saturating_sub(prekey.created_at);
            oldest_prekey_age = oldest_prekey_age.max(age);
            newest_prekey_age = newest_prekey_age.min(age);
        }
        
        if newest_prekey_age == u64::MAX {
            newest_prekey_age = 0;
        }
        
        Ok(PreKeyStatistics {
            total_prekeys: prekeys.len(),
            total_signed_prekeys: signed_prekeys.len(),
            oldest_prekey_age,
            newest_prekey_age,
        })
    }
}

#[derive(Debug)]
struct PreKeyStatistics {
    total_prekeys: usize,
    total_signed_prekeys: usize,
    oldest_prekey_age: u64,
    newest_prekey_age: u64,
}

#[tokio::test]
async fn test_prekey_generation() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate prekeys
    let prekeys = manager.generate_prekeys(10).await?;
    
    // Verify prekeys
    assert_eq!(prekeys.len(), 10);
    
    for (i, prekey) in prekeys.iter().enumerate() {
        assert_eq!(prekey.id(), (i + 1) as u32);
        assert_eq!(prekey.public_key().len(), 32);
        assert_eq!(prekey.private_key().len(), 32);
        assert_ne!(prekey.public_key(), prekey.private_key());
    }
    
    // Verify prekeys are stored
    let count = manager.count_prekeys().await?;
    assert_eq!(count, 10);
    
    Ok(())
}

#[tokio::test]
async fn test_signed_prekey_generation() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    let identity_private_key = vec![42u8; 32];
    let identity_public_key = vec![43u8; 32];
    
    // Generate signed prekey
    let signed_prekey = manager.generate_signed_prekey(&identity_private_key).await?;
    
    // Verify signed prekey
    assert_eq!(signed_prekey.id(), 1);
    assert_eq!(signed_prekey.public_key().len(), 32);
    assert_eq!(signed_prekey.private_key().len(), 32);
    assert!(!signed_prekey.signature().is_empty());
    
    // Verify signature (mock verification)
    assert!(signed_prekey.verify_signature(&identity_public_key));
    
    // Verify signed prekey is stored
    let count = manager.count_signed_prekeys().await?;
    assert_eq!(count, 1);
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_retrieval() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate prekeys
    let prekeys = manager.generate_prekeys(5).await?;
    let first_prekey = &prekeys[0];
    
    // Retrieve prekey
    let retrieved = manager.get_prekey(first_prekey.id()).await?;
    assert!(retrieved.is_some());
    
    let retrieved_prekey = retrieved.unwrap();
    assert_eq!(retrieved_prekey.id(), first_prekey.id());
    assert_eq!(retrieved_prekey.public_key(), first_prekey.public_key());
    assert_eq!(retrieved_prekey.private_key(), first_prekey.private_key());
    
    // Try to retrieve non-existent prekey
    let non_existent = manager.get_prekey(999).await?;
    assert!(non_existent.is_none());
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_removal() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate prekeys
    let prekeys = manager.generate_prekeys(3).await?;
    let first_prekey_id = prekeys[0].id();
    
    // Verify prekey exists
    assert!(manager.get_prekey(first_prekey_id).await?.is_some());
    
    // Remove prekey
    let removed = manager.remove_prekey(first_prekey_id).await?;
    assert!(removed);
    
    // Verify prekey is removed
    assert!(manager.get_prekey(first_prekey_id).await?.is_none());
    
    // Try to remove non-existent prekey
    let not_removed = manager.remove_prekey(999).await?;
    assert!(!not_removed);
    
    // Verify count is updated
    let count = manager.count_prekeys().await?;
    assert_eq!(count, 2);
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_bundle_creation() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    let identity_key = vec![100u8; 32];
    let identity_private_key = vec![101u8; 32];
    
    // Generate prekeys and signed prekey
    let prekeys = manager.generate_prekeys(1).await?;
    let signed_prekey = manager.generate_signed_prekey(&identity_private_key).await?;
    
    // Create prekey bundle with prekey
    let bundle = manager.create_prekey_bundle(
        identity_key.clone(),
        signed_prekey.id(),
        Some(prekeys[0].id()),
    ).await?;
    
    assert_eq!(bundle.identity_key(), &identity_key);
    assert_eq!(bundle.signed_prekey().id(), signed_prekey.id());
    assert!(bundle.prekey().is_some());
    assert_eq!(bundle.prekey().unwrap().id(), prekeys[0].id());
    assert_eq!(bundle.registration_id(), 12345);
    
    // Create prekey bundle without prekey
    let bundle_no_prekey = manager.create_prekey_bundle(
        identity_key.clone(),
        signed_prekey.id(),
        None,
    ).await?;
    
    assert!(bundle_no_prekey.prekey().is_none());
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_cleanup() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate prekeys
    manager.generate_prekeys(5).await?;
    
    // Cleanup with very short max age (should remove all)
    let removed = manager.cleanup_old_prekeys(0).await?;
    assert_eq!(removed, 5);
    
    // Verify all prekeys are removed
    let count = manager.count_prekeys().await?;
    assert_eq!(count, 0);
    
    Ok(())
}

#[tokio::test]
async fn test_signed_prekey_cleanup() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    let identity_private_key = vec![42u8; 32];
    
    // Generate multiple signed prekeys
    for _ in 0..5 {
        manager.generate_signed_prekey(&identity_private_key).await?;
        tokio::time::sleep(Duration::from_millis(10)).await; // Ensure different timestamps
    }
    
    // Cleanup keeping latest 2, with very short max age
    let removed = manager.cleanup_old_signed_prekeys(0, 2).await?;
    assert_eq!(removed, 3);
    
    // Verify only 2 signed prekeys remain
    let count = manager.count_signed_prekeys().await?;
    assert_eq!(count, 2);
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_serialization() -> Result<()> {
    let original = MockPreKey::new(42);
    
    // Serialize
    let serialized = original.serialize();
    assert!(!serialized.is_empty());
    
    // Deserialize
    let deserialized = MockPreKey::deserialize(&serialized)?;
    
    // Verify
    assert_eq!(deserialized.id(), original.id());
    assert_eq!(deserialized.public_key(), original.public_key());
    assert_eq!(deserialized.private_key(), original.private_key());
    assert_eq!(deserialized.created_at(), original.created_at());
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_export_import() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate prekeys
    let original_prekeys = manager.generate_prekeys(3).await?;
    
    // Export prekeys
    let exported_data = manager.export_prekeys().await?;
    assert!(!exported_data.is_empty());
    
    // Clear prekeys
    for prekey in &original_prekeys {
        manager.remove_prekey(prekey.id()).await?;
    }
    assert_eq!(manager.count_prekeys().await?, 0);
    
    // Import prekeys
    let imported_count = manager.import_prekeys(&exported_data).await?;
    assert_eq!(imported_count, 3);
    
    // Verify imported prekeys
    assert_eq!(manager.count_prekeys().await?, 3);
    
    for original_prekey in &original_prekeys {
        let imported = manager.get_prekey(original_prekey.id()).await?;
        assert!(imported.is_some());
        
        let imported_prekey = imported.unwrap();
        assert_eq!(imported_prekey.id(), original_prekey.id());
        assert_eq!(imported_prekey.public_key(), original_prekey.public_key());
    }
    
    Ok(())
}

#[tokio::test]
async fn test_signed_prekey_rotation() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    let identity_private_key = vec![42u8; 32];
    
    // Generate initial signed prekeys
    for _ in 0..5 {
        manager.generate_signed_prekey(&identity_private_key).await?;
    }
    
    let initial_count = manager.count_signed_prekeys().await?;
    assert_eq!(initial_count, 5);
    
    // Rotate signed prekey
    let new_signed_prekey = manager.rotate_signed_prekey(&identity_private_key).await?;
    
    // Verify new signed prekey is created
    assert_eq!(new_signed_prekey.id(), 6);
    
    // Verify old signed prekeys are cleaned up (should keep only latest 3)
    let final_count = manager.count_signed_prekeys().await?;
    assert_eq!(final_count, 3);
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_statistics() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    let identity_private_key = vec![42u8; 32];
    
    // Generate prekeys and signed prekeys
    manager.generate_prekeys(10).await?;
    manager.generate_signed_prekey(&identity_private_key).await?;
    manager.generate_signed_prekey(&identity_private_key).await?;
    
    // Get statistics
    let stats = manager.get_prekey_statistics().await?;
    
    assert_eq!(stats.total_prekeys, 10);
    assert_eq!(stats.total_signed_prekeys, 2);
    assert!(stats.oldest_prekey_age >= 0);
    assert!(stats.newest_prekey_age >= 0);
    assert!(stats.oldest_prekey_age >= stats.newest_prekey_age);
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_prekey_operations() -> Result<()> {
    let manager = std::sync::Arc::new(MockPreKeyManager::new(12345));
    let identity_private_key = vec![42u8; 32];
    let mut handles = Vec::new();
    
    // Spawn multiple concurrent operations
    for i in 0..10 {
        let manager_clone = manager.clone();
        let identity_private_key_clone = identity_private_key.clone();
        
        let handle = tokio::spawn(async move {
            // Generate prekeys
            let _prekeys = manager_clone.generate_prekeys(5).await?;
            
            // Generate signed prekey
            let _signed_prekey = manager_clone.generate_signed_prekey(&identity_private_key_clone).await?;
            
            // List prekeys
            let _prekey_list = manager_clone.list_prekeys().await?;
            
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    for handle in handles {
        handle.await??;
    }
    
    // Verify final state
    let prekey_count = manager.count_prekeys().await?;
    let signed_prekey_count = manager.count_signed_prekeys().await?;
    
    assert_eq!(prekey_count, 50); // 10 * 5
    assert_eq!(signed_prekey_count, 10); // 10 * 1
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_id_uniqueness() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate multiple batches of prekeys
    let batch1 = manager.generate_prekeys(5).await?;
    let batch2 = manager.generate_prekeys(5).await?;
    
    // Verify all IDs are unique
    let mut all_ids = Vec::new();
    for prekey in batch1.iter().chain(batch2.iter()) {
        all_ids.push(prekey.id());
    }
    
    all_ids.sort();
    for i in 1..all_ids.len() {
        assert_ne!(all_ids[i-1], all_ids[i], "Duplicate prekey ID found");
    }
    
    // Verify IDs are sequential
    for (i, &id) in all_ids.iter().enumerate() {
        assert_eq!(id, (i + 1) as u32);
    }
    
    Ok(())
}

#[tokio::test]
async fn test_invalid_prekey_operations() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Test creating bundle with non-existent signed prekey
    let result = manager.create_prekey_bundle(
        vec![1, 2, 3],
        999, // non-existent signed prekey ID
        None,
    ).await;
    assert!(result.is_err());
    
    // Test creating bundle with non-existent prekey
    let identity_private_key = vec![42u8; 32];
    let signed_prekey = manager.generate_signed_prekey(&identity_private_key).await?;
    
    let result = manager.create_prekey_bundle(
        vec![1, 2, 3],
        signed_prekey.id(),
        Some(999), // non-existent prekey ID
    ).await;
    assert!(result.is_err());
    
    // Test invalid serialization data
    let invalid_data = vec![1, 2, 3]; // too short
    let result = MockPreKey::deserialize(&invalid_data);
    assert!(result.is_err());
    
    // Test invalid import data
    let invalid_import_data = vec![1, 2]; // too short
    let imported = manager.import_prekeys(&invalid_import_data).await?;
    assert_eq!(imported, 0);
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_bundle_validation() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    let identity_key = vec![100u8; 32];
    let identity_private_key = vec![101u8; 32];
    let identity_public_key = vec![102u8; 32];
    
    // Generate signed prekey and prekey
    let signed_prekey = manager.generate_signed_prekey(&identity_private_key).await?;
    let prekeys = manager.generate_prekeys(1).await?;
    
    // Create valid bundle
    let bundle = manager.create_prekey_bundle(
        identity_key.clone(),
        signed_prekey.id(),
        Some(prekeys[0].id()),
    ).await?;
    
    // Verify bundle components
    assert_eq!(bundle.identity_key(), &identity_key);
    assert_eq!(bundle.registration_id(), 12345);
    
    // Verify signed prekey signature
    assert!(bundle.signed_prekey().verify_signature(&identity_public_key));
    
    // Verify prekey is present
    assert!(bundle.prekey().is_some());
    assert_eq!(bundle.prekey().unwrap().id(), prekeys[0].id());
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_age_tracking() -> Result<()> {
    let manager = MockPreKeyManager::new(12345);
    
    // Generate prekeys with small delay to ensure different timestamps
    let prekey1 = manager.generate_prekeys(1).await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let prekey2 = manager.generate_prekeys(1).await?;
    
    // Verify timestamps are different
    assert!(prekey2[0].created_at() >= prekey1[0].created_at());
    
    // Get statistics
    let stats = manager.get_prekey_statistics().await?;
    assert_eq!(stats.total_prekeys, 2);
    assert!(stats.oldest_prekey_age >= stats.newest_prekey_age);
    
    Ok(())
}

#[tokio::test]
async fn test_prekey_manager_edge_cases() -> Result<()> {
    let manager = MockPreKeyManager::new(0); // Edge case: registration ID 0
    
    // Test with zero prekeys
    let prekeys = manager.generate_prekeys(0).await?;
    assert!(prekeys.is_empty());
    
    // Test statistics with no prekeys
    let stats = manager.get_prekey_statistics().await?;
    assert_eq!(stats.total_prekeys, 0);
    assert_eq!(stats.total_signed_prekeys, 0);
    assert_eq!(stats.oldest_prekey_age, 0);
    assert_eq!(stats.newest_prekey_age, 0);
    
    // Test cleanup with no prekeys
    let removed = manager.cleanup_old_prekeys(0).await?;
    assert_eq!(removed, 0);
    
    let removed = manager.cleanup_old_signed_prekeys(0, 1).await?;
    assert_eq!(removed, 0);
    
    // Test export with no prekeys
    let exported = manager.export_prekeys().await?;
    assert!(!exported.is_empty()); // Should contain counts even if zero
    
    Ok(())
}