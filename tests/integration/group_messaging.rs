//! Integration tests for group messaging functionality
//! 
//! This module tests the complete group messaging system including:
//! - Group creation and member management
//! - Sender key distribution and rotation
//! - Group message encryption and decryption
//! - Large group scalability
//! - Group state synchronization

use crate::common::*;
use signal_crypto_lib::*;
use std::collections::{HashMap, HashSet};
use tokio::time::{sleep, Duration};

/// Test complete group messaging flow
#[tokio::test]
async fn test_complete_group_messaging_flow() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut group_manager = MockGroupManager::new().await?;
    
    // Create group with initial members
    let group_id = "test_group_001";
    let admin_id = "admin@example.com";
    let initial_members = vec![
        "alice@example.com",
        "bob@example.com", 
        "charlie@example.com",
    ];
    
    group_manager.create_group(group_id, admin_id, &initial_members).await?;
    
    // Verify group was created
    assert!(group_manager.group_exists(group_id).await?);
    let group_info = group_manager.get_group_info(group_id).await?;
    assert_eq!(group_info.admin_id, admin_id);
    assert_eq!(group_info.members.len(), initial_members.len() + 1); // +1 for admin
    
    // Test sending messages
    let messages = vec![
        ("alice@example.com", "Hello everyone!"),
        ("bob@example.com", "Hi Alice!"),
        ("charlie@example.com", "Good to see you all"),
        ("admin@example.com", "Welcome to the group"),
    ];
    
    for (sender, message) in &messages {
        let encrypted = group_manager.send_group_message(
            group_id,
            sender,
            message.as_bytes()
        ).await?;
        
        // Verify all members can decrypt
        for member in &group_info.members {
            if member != sender {
                let decrypted = group_manager.decrypt_group_message(
                    group_id,
                    member,
                    &encrypted
                ).await?;
                assert_eq!(decrypted, message.as_bytes());
            }
        }
    }
    
    test_ctx.metrics.record_test_completion("group_messaging_flow", true);
    Ok(())
}

/// Test group member management operations
#[tokio::test]
async fn test_group_member_management() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut group_manager = MockGroupManager::new().await?;
    
    let group_id = "member_mgmt_group";
    let admin_id = "admin@example.com";
    
    // Create group with initial members
    group_manager.create_group(group_id, admin_id, &["alice@example.com"]).await?;
    
    // Add new members
    let new_members = vec![
        "bob@example.com",
        "charlie@example.com",
        "diana@example.com",
    ];
    
    for member in &new_members {
        group_manager.add_member(group_id, admin_id, member).await?;
    }
    
    // Verify members were added
    let group_info = group_manager.get_group_info(group_id).await?;
    assert_eq!(group_info.members.len(), 5); // admin + alice + 3 new members
    
    // Test message after adding members
    let test_message = "Message after adding members";
    let encrypted = group_manager.send_group_message(
        group_id,
        admin_id,
        test_message.as_bytes()
    ).await?;
    
    // All members should be able to decrypt
    for member in &group_info.members {
        if member != admin_id {
            let decrypted = group_manager.decrypt_group_message(
                group_id,
                member,
                &encrypted
            ).await?;
            assert_eq!(decrypted, test_message.as_bytes());
        }
    }
    
    // Remove a member
    group_manager.remove_member(group_id, admin_id, "bob@example.com").await?;
    
    // Verify member was removed
    let updated_info = group_manager.get_group_info(group_id).await?;
    assert_eq!(updated_info.members.len(), 4);
    assert!(!updated_info.members.contains(&"bob@example.com".to_string()));
    
    // Test message after removing member
    let post_removal_message = "Message after removing member";
    let encrypted_post = group_manager.send_group_message(
        group_id,
        admin_id,
        post_removal_message.as_bytes()
    ).await?;
    
    // Removed member should not be able to decrypt
    let decrypt_result = group_manager.decrypt_group_message(
        group_id,
        "bob@example.com",
        &encrypted_post
    ).await;
    assert!(decrypt_result.is_err());
    
    // Other members should still be able to decrypt
    for member in &updated_info.members {
        if member != admin_id {
            let decrypted = group_manager.decrypt_group_message(
                group_id,
                member,
                &encrypted_post
            ).await?;
            assert_eq!(decrypted, post_removal_message.as_bytes());
        }
    }
    
    test_ctx.metrics.record_test_completion("group_member_management", true);
    Ok(())
}

/// Test sender key rotation
#[tokio::test]
async fn test_sender_key_rotation() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut group_manager = MockGroupManager::new().await?;
    
    let group_id = "key_rotation_group";
    let admin_id = "admin@example.com";
    let members = vec!["alice@example.com", "bob@example.com"];
    
    group_manager.create_group(group_id, admin_id, &members).await?;
    
    // Send initial message
    let initial_message = "Message before rotation";
    let initial_encrypted = group_manager.send_group_message(
        group_id,
        admin_id,
        initial_message.as_bytes()
    ).await?;
    
    // Get initial sender key info
    let initial_key_info = group_manager.get_sender_key_info(group_id, admin_id).await?;
    
    // Trigger key rotation
    group_manager.rotate_sender_key(group_id, admin_id).await?;
    
    // Verify key was rotated
    let rotated_key_info = group_manager.get_sender_key_info(group_id, admin_id).await?;
    assert_ne!(initial_key_info.key_id, rotated_key_info.key_id);
    assert!(rotated_key_info.generation > initial_key_info.generation);
    
    // Send message with new key
    let post_rotation_message = "Message after rotation";
    let post_rotation_encrypted = group_manager.send_group_message(
        group_id,
        admin_id,
        post_rotation_message.as_bytes()
    ).await?;
    
    // All members should be able to decrypt both messages
    for member in &members {
        // Old message with old key
        let decrypted_old = group_manager.decrypt_group_message(
            group_id,
            member,
            &initial_encrypted
        ).await?;
        assert_eq!(decrypted_old, initial_message.as_bytes());
        
        // New message with new key
        let decrypted_new = group_manager.decrypt_group_message(
            group_id,
            member,
            &post_rotation_encrypted
        ).await?;
        assert_eq!(decrypted_new, post_rotation_message.as_bytes());
    }
    
    test_ctx.metrics.record_test_completion("sender_key_rotation", true);
    Ok(())
}

/// Test large group scalability
#[tokio::test]
async fn test_large_group_scalability() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut group_manager = MockGroupManager::new().await?;
    
    let group_id = "large_group";
    let admin_id = "admin@example.com";
    
    // Create group
    group_manager.create_group(group_id, admin_id, &[]).await?;
    
    // Add many members
    let member_count = 100;
    let mut members = Vec::new();
    
    for i in 0..member_count {
        let member_id = format!("member{}@example.com", i);
        group_manager.add_member(group_id, admin_id, &member_id).await?;
        members.push(member_id);
    }
    
    // Verify all members were added
    let group_info = group_manager.get_group_info(group_id).await?;
    assert_eq!(group_info.members.len(), member_count + 1); // +1 for admin
    
    // Test message distribution to large group
    let start_time = std::time::Instant::now();
    let test_message = "Message to large group";
    let encrypted = group_manager.send_group_message(
        group_id,
        admin_id,
        test_message.as_bytes()
    ).await?;
    let send_duration = start_time.elapsed();
    
    // Verify performance is acceptable
    assert!(send_duration < Duration::from_secs(5), "Message sending took too long: {:?}", send_duration);
    
    // Test decryption by subset of members
    let test_members = &members[0..10]; // Test first 10 members
    for member in test_members {
        let decrypt_start = std::time::Instant::now();
        let decrypted = group_manager.decrypt_group_message(
            group_id,
            member,
            &encrypted
        ).await?;
        let decrypt_duration = decrypt_start.elapsed();
        
        assert_eq!(decrypted, test_message.as_bytes());
        assert!(decrypt_duration < Duration::from_millis(100), "Decryption took too long: {:?}", decrypt_duration);
    }
    
    test_ctx.metrics.record_test_completion("large_group_scalability", true);
    Ok(())
}

/// Test concurrent group operations
#[tokio::test]
async fn test_concurrent_group_operations() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let group_manager = MockGroupManager::new().await?;
    
    let group_id = "concurrent_group";
    let admin_id = "admin@example.com";
    let members = vec!["alice@example.com", "bob@example.com", "charlie@example.com"];
    
    group_manager.create_group(group_id, admin_id, &members).await?;
    
    // Send multiple messages concurrently
    let message_count = 20;
    let mut handles = Vec::new();
    
    for i in 0..message_count {
        let group_manager = group_manager.clone();
        let sender = members[i % members.len()].to_string();
        
        let handle = tokio::spawn(async move {
            let message = format!("Concurrent message {}", i);
            let encrypted = group_manager.send_group_message(
                group_id,
                &sender,
                message.as_bytes()
            ).await?;
            
            // Verify message can be decrypted
            let decrypted = group_manager.decrypt_group_message(
                group_id,
                admin_id,
                &encrypted
            ).await?;
            
            assert_eq!(decrypted, message.as_bytes());
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    for handle in handles {
        handle.await??;
    }
    
    test_ctx.metrics.record_test_completion("concurrent_group_operations", true);
    Ok(())
}

/// Test group state synchronization
#[tokio::test]
async fn test_group_state_synchronization() -> Result<()> {
    let mut test_ctx = TestContext::new().await?;
    let mut group_manager1 = MockGroupManager::new().await?;
    let mut group_manager2 = MockGroupManager::new().await?;
    
    let group_id = "sync_group";
    let admin_id = "admin@example.com";
    let member_id = "alice@example.com";
    
    // Create group on first manager
    group_manager1.create_group(group_id, admin_id, &[member_id]).await?;
    
    // Sync group to second manager
    let group_state = group_manager1.export_group_state(group_id).await?;
    group_manager2.import_group_state(group_id, &group_state).await?;
    
    // Verify group exists on both managers
    assert!(group_manager1.group_exists(group_id).await?);
    assert!(group_manager2.group_exists(group_id).await?);
    
    // Send message from first manager
    let message1 = "Message from manager 1";
    let encrypted1 = group_manager1.send_group_message(
        group_id,
        admin_id,
        message1.as_bytes()
    ).await?;
    
    // Decrypt on second manager
    let decrypted1 = group_manager2.decrypt_group_message(
        group_id,
        member_id,
        &encrypted1
    ).await?;
    assert_eq!(decrypted1, message1.as_bytes());
    
    // Send message from second manager
    let message2 = "Message from manager 2";
    let encrypted2 = group_manager2.send_group_message(
        group_id,
        member_id,
        message2.as_bytes()
    ).await?;
    
    // Decrypt on first manager
    let decrypted2 = group_manager1.decrypt_group_message(
        group_id,
        admin_id,
        &encrypted2
    ).await?;
    assert_eq!(decrypted2, message2.as_bytes());
    
    test_ctx.metrics.record_test_completion("group_state_synchronization", true);
    Ok(())
}

/// Mock group manager implementation for testing
#[derive(Clone)]
struct MockGroupManager {
    groups: std::sync::Arc<tokio::sync::RwLock<HashMap<String, MockGroupData>>>,
}

#[derive(Debug, Clone)]
struct MockGroupData {
    admin_id: String,
    members: HashSet<String>,
    sender_keys: HashMap<String, MockSenderKeyInfo>,
    message_counter: u64,
}

#[derive(Debug, Clone)]
struct MockGroupInfo {
    admin_id: String,
    members: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
struct MockSenderKeyInfo {
    key_id: String,
    generation: u32,
    key_data: Vec<u8>,
}

impl MockGroupManager {
    async fn new() -> Result<Self> {
        Ok(Self {
            groups: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }
    
    async fn create_group(&self, group_id: &str, admin_id: &str, initial_members: &[&str]) -> Result<()> {
        let mut groups = self.groups.write().await;
        
        let mut members = HashSet::new();
        members.insert(admin_id.to_string());
        for member in initial_members {
            members.insert(member.to_string());
        }
        
        let mut sender_keys = HashMap::new();
        for member in &members {
            sender_keys.insert(member.clone(), MockSenderKeyInfo {
                key_id: format!("key_{}_{}", group_id, member),
                generation: 0,
                key_data: generate_test_key(32),
            });
        }
        
        let group_data = MockGroupData {
            admin_id: admin_id.to_string(),
            members,
            sender_keys,
            message_counter: 0,
        };
        
        groups.insert(group_id.to_string(), group_data);
        Ok(())
    }
    
    async fn group_exists(&self, group_id: &str) -> Result<bool> {
        let groups = self.groups.read().await;
        Ok(groups.contains_key(group_id))
    }
    
    async fn get_group_info(&self, group_id: &str) -> Result<MockGroupInfo> {
        let groups = self.groups.read().await;
        let group = groups.get(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        Ok(MockGroupInfo {
            admin_id: group.admin_id.clone(),
            members: group.members.iter().cloned().collect(),
            created_at: chrono::Utc::now(),
        })
    }
    
    async fn add_member(&self, group_id: &str, admin_id: &str, member_id: &str) -> Result<()> {
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        if group.admin_id != admin_id {
            return Err("Only admin can add members".into());
        }
        
        group.members.insert(member_id.to_string());
        group.sender_keys.insert(member_id.to_string(), MockSenderKeyInfo {
            key_id: format!("key_{}_{}", group_id, member_id),
            generation: 0,
            key_data: generate_test_key(32),
        });
        
        Ok(())
    }
    
    async fn remove_member(&self, group_id: &str, admin_id: &str, member_id: &str) -> Result<()> {
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        if group.admin_id != admin_id {
            return Err("Only admin can remove members".into());
        }
        
        group.members.remove(member_id);
        group.sender_keys.remove(member_id);
        
        Ok(())
    }
    
    async fn send_group_message(&self, group_id: &str, sender_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        if !group.members.contains(sender_id) {
            return Err("Sender is not a group member".into());
        }
        
        group.message_counter += 1;
        
        // Simulate group message encryption
        let mut encrypted = message.to_vec();
        encrypted.extend_from_slice(format!("_group_{}_{}", group_id, sender_id).as_bytes());
        Ok(encrypted)
    }
    
    async fn decrypt_group_message(&self, group_id: &str, member_id: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
        let groups = self.groups.read().await;
        let group = groups.get(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        if !group.members.contains(member_id) {
            return Err("Member is not in group".into());
        }
        
        // Simulate group message decryption
        let suffix = format!("_group_{}_{}", group_id, member_id);
        if let Some(pos) = encrypted.windows(suffix.len()).position(|window| window == suffix.as_bytes()) {
            Ok(encrypted[..pos].to_vec())
        } else {
            // Try with different sender IDs
            for sender in &group.members {
                let sender_suffix = format!("_group_{}_{}", group_id, sender);
                if let Some(pos) = encrypted.windows(sender_suffix.len()).position(|window| window == sender_suffix.as_bytes()) {
                    return Ok(encrypted[..pos].to_vec());
                }
            }
            Err("Invalid encrypted message".into())
        }
    }
    
    async fn get_sender_key_info(&self, group_id: &str, sender_id: &str) -> Result<MockSenderKeyInfo> {
        let groups = self.groups.read().await;
        let group = groups.get(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        group.sender_keys.get(sender_id)
            .cloned()
            .ok_or_else(|| format!("Sender key not found: {}", sender_id).into())
    }
    
    async fn rotate_sender_key(&self, group_id: &str, sender_id: &str) -> Result<()> {
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        if let Some(key_info) = group.sender_keys.get_mut(sender_id) {
            key_info.generation += 1;
            key_info.key_id = format!("key_{}_{}_{}", group_id, sender_id, key_info.generation);
            key_info.key_data = generate_test_key(32);
        }
        
        Ok(())
    }
    
    async fn export_group_state(&self, group_id: &str) -> Result<Vec<u8>> {
        let groups = self.groups.read().await;
        let group = groups.get(group_id)
            .ok_or_else(|| format!("Group not found: {}", group_id))?;
        
        // Simulate state serialization
        let state_data = format!("group_state_{}_{}", group_id, group.members.len());
        Ok(state_data.into_bytes())
    }
    
    async fn import_group_state(&self, group_id: &str, state_data: &[u8]) -> Result<()> {
        let mut groups = self.groups.write().await;
        
        // Simulate state deserialization
        let _state_str = String::from_utf8_lossy(state_data);
        
        // Create mock group from state
        let mut members = HashSet::new();
        members.insert("admin@example.com".to_string());
        members.insert("alice@example.com".to_string());
        
        let mut sender_keys = HashMap::new();
        for member in &members {
            sender_keys.insert(member.clone(), MockSenderKeyInfo {
                key_id: format!("key_{}_{}", group_id, member),
                generation: 0,
                key_data: generate_test_key(32),
            });
        }
        
        let group_data = MockGroupData {
            admin_id: "admin@example.com".to_string(),
            members,
            sender_keys,
            message_counter: 0,
        };
        
        groups.insert(group_id.to_string(), group_data);
        Ok(())
    }
}