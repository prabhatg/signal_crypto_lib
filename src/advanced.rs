// signal_crypto_lib/src/advanced.rs
// Advanced protocol features and optimizations

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::types::{DoubleRatchetMessage, SessionState};
use crate::group_sender_key::SenderKeyMessage;
use crate::protocol::sesame::GroupSessionState;

/// Protocol version for compatibility and migration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 0, patch: 0 };
    
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major && self.minor <= other.minor
    }
    
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        bytes[0..2].copy_from_slice(&self.major.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.minor.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.patch.to_be_bytes());
        bytes
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 6 {
            return Err("Invalid version bytes length");
        }
        
        let major = u16::from_be_bytes([bytes[0], bytes[1]]);
        let minor = u16::from_be_bytes([bytes[2], bytes[3]]);
        let patch = u16::from_be_bytes([bytes[4], bytes[5]]);
        
        Ok(Self { major, minor, patch })
    }
}

/// Message batching for improved efficiency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageBatch {
    pub version: ProtocolVersion,
    pub batch_id: u64,
    pub timestamp: u64,
    pub messages: Vec<BatchedMessage>,
    pub compression: CompressionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchedMessage {
    pub message_id: u64,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub metadata: MessageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    DoubleRatchet,
    SenderKey,
    Control,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub sender_id: String,
    pub recipient_id: Option<String>,
    pub group_id: Option<String>,
    pub priority: MessagePriority,
    pub delivery_receipt_requested: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Zlib,
    Lz4,
}

/// Message batcher for efficient transmission
pub struct MessageBatcher {
    pending_messages: VecDeque<BatchedMessage>,
    batch_size_limit: usize,
    batch_time_limit: Duration,
    last_batch_time: SystemTime,
    next_batch_id: u64,
    compression_threshold: usize,
}

impl MessageBatcher {
    pub fn new(batch_size_limit: usize, batch_time_limit: Duration) -> Self {
        Self {
            pending_messages: VecDeque::new(),
            batch_size_limit,
            batch_time_limit,
            last_batch_time: SystemTime::now(),
            next_batch_id: 1,
            compression_threshold: 1024, // Compress if batch > 1KB
        }
    }
    
    /// Add a message to the batch
    pub fn add_message(&mut self, message: BatchedMessage) {
        self.pending_messages.push_back(message);
    }
    
    /// Check if batch should be sent
    pub fn should_send_batch(&self) -> bool {
        if self.pending_messages.is_empty() {
            return false;
        }
        
        // Send if size limit reached
        if self.pending_messages.len() >= self.batch_size_limit {
            return true;
        }
        
        // Send if time limit reached
        if let Ok(elapsed) = self.last_batch_time.elapsed() {
            if elapsed >= self.batch_time_limit {
                return true;
            }
        }
        
        // Send if high priority message present
        self.pending_messages.iter().any(|msg| {
            matches!(msg.metadata.priority, MessagePriority::High | MessagePriority::Critical)
        })
    }
    
    /// Create and return a batch
    pub fn create_batch(&mut self) -> Option<MessageBatch> {
        if self.pending_messages.is_empty() {
            return None;
        }
        
        let messages: Vec<_> = self.pending_messages.drain(..).collect();
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;
        self.last_batch_time = SystemTime::now();
        
        // Determine compression type
        let total_size: usize = messages.iter().map(|m| m.payload.len()).sum();
        let compression = if total_size > self.compression_threshold {
            CompressionType::Zlib
        } else {
            CompressionType::None
        };
        
        Some(MessageBatch {
            version: ProtocolVersion::CURRENT,
            batch_id,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            messages,
            compression,
        })
    }
    
    /// Force create batch regardless of limits
    pub fn force_batch(&mut self) -> Option<MessageBatch> {
        if self.pending_messages.is_empty() {
            None
        } else {
            self.create_batch()
        }
    }
}

/// Message compression utilities
pub struct MessageCompressor;

impl MessageCompressor {
    /// Compress message batch
    pub fn compress_batch(batch: &MessageBatch) -> Result<Vec<u8>, CompressionError> {
        let serialized = serde_json::to_vec(batch)
            .map_err(|_| CompressionError::SerializationFailed)?;
        
        match batch.compression {
            CompressionType::None => Ok(serialized),
            CompressionType::Zlib => Self::compress_zlib(&serialized),
            CompressionType::Lz4 => Self::compress_lz4(&serialized),
        }
    }
    
    /// Decompress message batch
    pub fn decompress_batch(data: &[u8], compression: CompressionType) -> Result<MessageBatch, CompressionError> {
        let decompressed = match compression {
            CompressionType::None => data.to_vec(),
            CompressionType::Zlib => Self::decompress_zlib(data)?,
            CompressionType::Lz4 => Self::decompress_lz4(data)?,
        };
        
        serde_json::from_slice(&decompressed)
            .map_err(|_| CompressionError::DeserializationFailed)
    }
    
    fn compress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).map_err(|_| CompressionError::CompressionFailed)?;
        encoder.finish().map_err(|_| CompressionError::CompressionFailed)
    }
    
    fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        
        let mut decoder = ZlibDecoder::new(data);
        let mut result = Vec::new();
        decoder.read_to_end(&mut result).map_err(|_| CompressionError::DecompressionFailed)?;
        Ok(result)
    }
    
    fn compress_lz4(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // Placeholder for LZ4 compression
        // In a real implementation, you'd use the lz4 crate
        Ok(data.to_vec())
    }
    
    fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // Placeholder for LZ4 decompression
        // In a real implementation, you'd use the lz4 crate
        Ok(data.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompressionError {
    SerializationFailed,
    DeserializationFailed,
    CompressionFailed,
    DecompressionFailed,
}

/// Advanced group management with roles and permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedGroupSession {
    pub group_id: String,
    pub group_name: String,
    pub creation_time: u64,
    pub members: HashMap<String, GroupMember>,
    pub roles: HashMap<String, GroupRole>,
    pub permissions: GroupPermissions,
    pub session_state: GroupSessionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub user_id: String,
    pub display_name: String,
    pub role_id: String,
    pub joined_time: u64,
    pub last_seen: u64,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRole {
    pub role_id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
    pub priority: u32, // Higher number = higher priority
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    SendMessages,
    AddMembers,
    RemoveMembers,
    ChangeGroupName,
    ChangeGroupSettings,
    ManageRoles,
    DeleteMessages,
    PinMessages,
    MuteMembers,
    AdministerGroup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPermissions {
    pub default_role: String,
    pub admin_role: String,
    pub require_admin_approval: bool,
    pub allow_member_invites: bool,
    pub message_history_visible: bool,
}

impl AdvancedGroupSession {
    pub fn new(group_id: String, creator_id: String, creator_public_key: Vec<u8>) -> Self {
        let mut members = HashMap::new();
        let mut roles = HashMap::new();
        
        // Create default roles
        let admin_role = GroupRole {
            role_id: "admin".to_string(),
            name: "Administrator".to_string(),
            permissions: vec![
                Permission::SendMessages,
                Permission::AddMembers,
                Permission::RemoveMembers,
                Permission::ChangeGroupName,
                Permission::ChangeGroupSettings,
                Permission::ManageRoles,
                Permission::DeleteMessages,
                Permission::PinMessages,
                Permission::MuteMembers,
                Permission::AdministerGroup,
            ],
            priority: 100,
        };
        
        let member_role = GroupRole {
            role_id: "member".to_string(),
            name: "Member".to_string(),
            permissions: vec![Permission::SendMessages],
            priority: 10,
        };
        
        roles.insert("admin".to_string(), admin_role);
        roles.insert("member".to_string(), member_role);
        
        // Add creator as admin
        let creator = GroupMember {
            user_id: creator_id,
            display_name: "Creator".to_string(),
            role_id: "admin".to_string(),
            joined_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            public_key: creator_public_key,
        };
        
        members.insert(creator.user_id.clone(), creator);
        
        Self {
            group_id: group_id.clone(),
            group_name: format!("Group {}", group_id),
            creation_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            members,
            roles,
            permissions: GroupPermissions {
                default_role: "member".to_string(),
                admin_role: "admin".to_string(),
                require_admin_approval: false,
                allow_member_invites: true,
                message_history_visible: true,
            },
            session_state: GroupSessionState::new(&group_id, "creator"),
        }
    }
    
    /// Check if user has permission
    pub fn has_permission(&self, user_id: &str, permission: &Permission) -> bool {
        if let Some(member) = self.members.get(user_id) {
            if let Some(role) = self.roles.get(&member.role_id) {
                return role.permissions.contains(permission);
            }
        }
        false
    }
    
    /// Add member to group
    pub fn add_member(&mut self, user_id: String, public_key: Vec<u8>, added_by: &str) -> Result<(), GroupError> {
        // Check if adder has permission
        if !self.has_permission(added_by, &Permission::AddMembers) {
            return Err(GroupError::InsufficientPermissions);
        }
        
        if self.members.contains_key(&user_id) {
            return Err(GroupError::MemberAlreadyExists);
        }
        
        let member = GroupMember {
            user_id: user_id.clone(),
            display_name: user_id.clone(),
            role_id: self.permissions.default_role.clone(),
            joined_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            public_key,
        };
        
        self.members.insert(user_id, member);
        Ok(())
    }
    
    /// Remove member from group
    pub fn remove_member(&mut self, user_id: &str, removed_by: &str) -> Result<(), GroupError> {
        // Check if remover has permission
        if !self.has_permission(removed_by, &Permission::RemoveMembers) {
            return Err(GroupError::InsufficientPermissions);
        }
        
        if !self.members.contains_key(user_id) {
            return Err(GroupError::MemberNotFound);
        }
        
        // Can't remove yourself if you're the last admin
        if user_id == removed_by {
            let admin_count = self.members.values()
                .filter(|m| m.role_id == self.permissions.admin_role)
                .count();
            if admin_count <= 1 {
                return Err(GroupError::CannotRemoveLastAdmin);
            }
        }
        
        self.members.remove(user_id);
        Ok(())
    }
    
    /// Change member role
    pub fn change_member_role(&mut self, user_id: &str, new_role_id: &str, changed_by: &str) -> Result<(), GroupError> {
        if !self.has_permission(changed_by, &Permission::ManageRoles) {
            return Err(GroupError::InsufficientPermissions);
        }
        
        if !self.roles.contains_key(new_role_id) {
            return Err(GroupError::RoleNotFound);
        }
        
        if let Some(member) = self.members.get_mut(user_id) {
            member.role_id = new_role_id.to_string();
            Ok(())
        } else {
            Err(GroupError::MemberNotFound)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupError {
    InsufficientPermissions,
    MemberAlreadyExists,
    MemberNotFound,
    RoleNotFound,
    CannotRemoveLastAdmin,
}

/// Message delivery receipts and acknowledgments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub message_id: u64,
    pub recipient_id: String,
    pub status: DeliveryStatus,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Sent,
    Delivered,
    Read,
    Failed,
}

/// Protocol metrics for monitoring and optimization
#[derive(Debug, Clone, Default)]
pub struct ProtocolMetrics {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub encryption_time_ms: u64,
    pub decryption_time_ms: u64,
    pub key_exchanges: u64,
    pub ratchet_steps: u64,
    pub compression_ratio: f64,
}

impl ProtocolMetrics {
    pub fn record_message_sent(&mut self, bytes: usize) {
        self.messages_sent += 1;
        self.bytes_sent += bytes as u64;
    }
    
    pub fn record_message_received(&mut self, bytes: usize) {
        self.messages_received += 1;
        self.bytes_received += bytes as u64;
    }
    
    pub fn record_encryption_time(&mut self, duration: Duration) {
        self.encryption_time_ms += duration.as_millis() as u64;
    }
    
    pub fn record_decryption_time(&mut self, duration: Duration) {
        self.decryption_time_ms += duration.as_millis() as u64;
    }
    
    pub fn record_key_exchange(&mut self) {
        self.key_exchanges += 1;
    }
    
    pub fn record_ratchet_step(&mut self) {
        self.ratchet_steps += 1;
    }
    
    pub fn update_compression_ratio(&mut self, original_size: usize, compressed_size: usize) {
        if original_size > 0 {
            self.compression_ratio = compressed_size as f64 / original_size as f64;
        }
    }
    
    pub fn get_average_encryption_time(&self) -> f64 {
        if self.messages_sent > 0 {
            self.encryption_time_ms as f64 / self.messages_sent as f64
        } else {
            0.0
        }
    }
    
    pub fn get_average_decryption_time(&self) -> f64 {
        if self.messages_received > 0 {
            self.decryption_time_ms as f64 / self.messages_received as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_version() {
        let v1 = ProtocolVersion { major: 1, minor: 0, patch: 0 };
        let v2 = ProtocolVersion { major: 1, minor: 1, patch: 0 };
        let v3 = ProtocolVersion { major: 2, minor: 0, patch: 0 };
        
        assert!(v1.is_compatible(&v2));
        assert!(!v1.is_compatible(&v3));
        
        let bytes = v1.to_bytes();
        let parsed = ProtocolVersion::from_bytes(&bytes).unwrap();
        assert_eq!(v1, parsed);
    }
    
    #[test]
    fn test_message_batcher() {
        let mut batcher = MessageBatcher::new(3, Duration::from_millis(100));
        
        let message = BatchedMessage {
            message_id: 1,
            message_type: MessageType::DoubleRatchet,
            payload: vec![1, 2, 3],
            metadata: MessageMetadata {
                sender_id: "alice".to_string(),
                recipient_id: Some("bob".to_string()),
                group_id: None,
                priority: MessagePriority::Normal,
                delivery_receipt_requested: false,
            },
        };
        
        batcher.add_message(message.clone());
        assert!(!batcher.should_send_batch());
        
        batcher.add_message(message.clone());
        batcher.add_message(message.clone());
        assert!(batcher.should_send_batch());
        
        let batch = batcher.create_batch().unwrap();
        assert_eq!(batch.messages.len(), 3);
    }
    
    #[test]
    fn test_message_compression() {
        let batch = MessageBatch {
            version: ProtocolVersion::CURRENT,
            batch_id: 1,
            timestamp: 1234567890,
            messages: vec![],
            compression: CompressionType::Zlib,
        };
        
        let compressed = MessageCompressor::compress_batch(&batch).unwrap();
        let decompressed = MessageCompressor::decompress_batch(&compressed, CompressionType::Zlib).unwrap();
        
        assert_eq!(batch.batch_id, decompressed.batch_id);
        assert_eq!(batch.timestamp, decompressed.timestamp);
    }
    
    #[test]
    fn test_advanced_group_management() {
        let mut group = AdvancedGroupSession::new(
            "group1".to_string(),
            "alice".to_string(),
            vec![1, 2, 3],
        );
        
        // Alice should have admin permissions
        assert!(group.has_permission("alice", &Permission::AddMembers));
        
        // Add Bob as member
        assert!(group.add_member("bob".to_string(), vec![4, 5, 6], "alice").is_ok());
        
        // Bob should not have admin permissions
        assert!(!group.has_permission("bob", &Permission::AddMembers));
        
        // Bob cannot add members
        assert!(group.add_member("charlie".to_string(), vec![7, 8, 9], "bob").is_err());
        
        // Alice can change Bob's role
        assert!(group.change_member_role("bob", "admin", "alice").is_ok());
        
        // Now Bob should have admin permissions
        assert!(group.has_permission("bob", &Permission::AddMembers));
    }
    
    #[test]
    fn test_protocol_metrics() {
        let mut metrics = ProtocolMetrics::default();
        
        metrics.record_message_sent(100);
        metrics.record_message_received(150);
        metrics.record_encryption_time(Duration::from_millis(5));
        metrics.record_decryption_time(Duration::from_millis(3));
        
        assert_eq!(metrics.messages_sent, 1);
        assert_eq!(metrics.messages_received, 1);
        assert_eq!(metrics.bytes_sent, 100);
        assert_eq!(metrics.bytes_received, 150);
        assert_eq!(metrics.get_average_encryption_time(), 5.0);
        assert_eq!(metrics.get_average_decryption_time(), 3.0);
    }
}