/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * FFI bindings for group messaging functionality with Sesame protocol support.
 * Provides C-compatible interface for group session management, member operations,
 * and secure group message encryption/decryption for Dart/Flutter integration.
 */

// signal_crypto_lib/src/group_ffi.rs
// FFI bindings for group messaging functionality

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::group::{generate_sender_key, encrypt_group_message, decrypt_group_message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSession {
    pub group_id: String,
    pub members: HashMap<String, GroupMember>,
    pub sender_keys: HashMap<String, SenderKey>,
    pub created_at: String,
    pub updated_at: String,
    pub creator_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub member_id: String,
    pub identity_key: Vec<u8>,
    pub identity_key_ed: Vec<u8>,
    pub joined_at: String,
    pub role: String, // "admin", "member"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    pub message_id: String,
    pub group_id: String,
    pub sender_id: String,
    pub encrypted_message: EncryptedMessage,
    pub timestamp: String,
    pub message_type: String, // "text", "media", "system"
}

// Group Session Management FFI
#[no_mangle]
pub extern "C" fn ffi_create_group_session_json(
    group_id: *const c_char,
    creator_identity_json: *const c_char,
    creator_id: *const c_char,
) -> *mut c_char {
    if group_id.is_null() || creator_identity_json.is_null() || creator_id.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let group_id_str = unsafe { CStr::from_ptr(group_id) }.to_str();
    if group_id_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in group_id").unwrap().into_raw();
    }
    
    let creator_id_str = unsafe { CStr::from_ptr(creator_id) }.to_str();
    if creator_id_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in creator_id").unwrap().into_raw();
    }
    
    let creator_identity_str = unsafe { CStr::from_ptr(creator_identity_json) }.to_str();
    if creator_identity_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in creator identity").unwrap().into_raw();
    }
    
    let creator_identity: Result<IdentityKeyPair, _> = serde_json::from_str(creator_identity_str.unwrap());
    if creator_identity.is_err() {
        return CString::new("ERROR: failed to parse creator identity").unwrap().into_raw();
    }
    
    let identity = creator_identity.unwrap();
    let creator_member = GroupMember {
        member_id: creator_id_str.unwrap().to_string(),
        identity_key: identity.dh_public.clone(),
        identity_key_ed: identity.ed_public.clone(),
        joined_at: chrono::Utc::now().to_rfc3339(),
        role: "admin".to_string(),
    };
    
    let sender_key = generate_sender_key();
    let mut members = HashMap::new();
    let mut sender_keys = HashMap::new();
    
    members.insert(creator_id_str.unwrap().to_string(), creator_member);
    sender_keys.insert(creator_id_str.unwrap().to_string(), sender_key);
    
    let group_session = GroupSession {
        group_id: group_id_str.unwrap().to_string(),
        members,
        sender_keys,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        creator_id: creator_id_str.unwrap().to_string(),
    };
    
    let result = serde_json::json!({
        "success": true,
        "group_session": group_session,
        "error": null
    });
    
    match serde_json::to_string(&result) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn ffi_add_group_member_json(
    group_session_json: *const c_char,
    member_identity_json: *const c_char,
    member_id: *const c_char,
) -> *mut c_char {
    if group_session_json.is_null() || member_identity_json.is_null() || member_id.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let group_session_str = unsafe { CStr::from_ptr(group_session_json) }.to_str();
    if group_session_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in group session").unwrap().into_raw();
    }
    
    let member_identity_str = unsafe { CStr::from_ptr(member_identity_json) }.to_str();
    if member_identity_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in member identity").unwrap().into_raw();
    }
    
    let member_id_str = unsafe { CStr::from_ptr(member_id) }.to_str();
    if member_id_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in member_id").unwrap().into_raw();
    }
    
    let mut group_session: Result<GroupSession, _> = serde_json::from_str(group_session_str.unwrap());
    if group_session.is_err() {
        return CString::new("ERROR: failed to parse group session").unwrap().into_raw();
    }
    
    let member_identity: Result<IdentityKeyPair, _> = serde_json::from_str(member_identity_str.unwrap());
    if member_identity.is_err() {
        return CString::new("ERROR: failed to parse member identity").unwrap().into_raw();
    }
    
    let identity = member_identity.unwrap();
    let new_member = GroupMember {
        member_id: member_id_str.unwrap().to_string(),
        identity_key: identity.dh_public.clone(),
        identity_key_ed: identity.ed_public.clone(),
        joined_at: chrono::Utc::now().to_rfc3339(),
        role: "member".to_string(),
    };
    
    let sender_key = generate_sender_key();
    let mut session = group_session.unwrap();
    
    session.members.insert(member_id_str.unwrap().to_string(), new_member);
    session.sender_keys.insert(member_id_str.unwrap().to_string(), sender_key);
    session.updated_at = chrono::Utc::now().to_rfc3339();
    
    let result = serde_json::json!({
        "success": true,
        "group_session": session,
        "error": null
    });
    
    match serde_json::to_string(&result) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn ffi_remove_group_member_json(
    group_session_json: *const c_char,
    member_id: *const c_char,
) -> *mut c_char {
    if group_session_json.is_null() || member_id.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let group_session_str = unsafe { CStr::from_ptr(group_session_json) }.to_str();
    if group_session_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in group session").unwrap().into_raw();
    }
    
    let member_id_str = unsafe { CStr::from_ptr(member_id) }.to_str();
    if member_id_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in member_id").unwrap().into_raw();
    }
    
    let mut group_session: Result<GroupSession, _> = serde_json::from_str(group_session_str.unwrap());
    if group_session.is_err() {
        return CString::new("ERROR: failed to parse group session").unwrap().into_raw();
    }
    
    let mut session = group_session.unwrap();
    let member_id_string = member_id_str.unwrap().to_string();
    
    if !session.members.contains_key(&member_id_string) {
        return CString::new("ERROR: member not found in group").unwrap().into_raw();
    }
    
    session.members.remove(&member_id_string);
    session.sender_keys.remove(&member_id_string);
    session.updated_at = chrono::Utc::now().to_rfc3339();
    
    let result = serde_json::json!({
        "success": true,
        "group_session": session,
        "error": null
    });
    
    match serde_json::to_string(&result) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
    }
}

// Group Message Operations FFI
#[no_mangle]
pub extern "C" fn ffi_encrypt_group_message_json(
    group_session_json: *const c_char,
    sender_id: *const c_char,
    plaintext: *const c_char,
) -> *mut c_char {
    if group_session_json.is_null() || sender_id.is_null() || plaintext.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let group_session_str = unsafe { CStr::from_ptr(group_session_json) }.to_str();
    if group_session_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in group session").unwrap().into_raw();
    }
    
    let sender_id_str = unsafe { CStr::from_ptr(sender_id) }.to_str();
    if sender_id_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in sender_id").unwrap().into_raw();
    }
    
    let plaintext_str = unsafe { CStr::from_ptr(plaintext) }.to_str();
    if plaintext_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in plaintext").unwrap().into_raw();
    }
    
    let group_session: Result<GroupSession, _> = serde_json::from_str(group_session_str.unwrap());
    if group_session.is_err() {
        return CString::new("ERROR: failed to parse group session").unwrap().into_raw();
    }
    
    let session = group_session.unwrap();
    let sender_id_string = sender_id_str.unwrap().to_string();
    
    let sender_key = match session.sender_keys.get(&sender_id_string) {
        Some(key) => key,
        None => return CString::new("ERROR: sender not found in group").unwrap().into_raw(),
    };
    
    let encrypted_message = encrypt_group_message(sender_key, plaintext_str.unwrap());
    
    let group_message = GroupMessage {
        message_id: uuid::Uuid::new_v4().to_string(),
        group_id: session.group_id.clone(),
        sender_id: sender_id_string,
        encrypted_message,
        timestamp: chrono::Utc::now().to_rfc3339(),
        message_type: "text".to_string(),
    };
    
    let result = serde_json::json!({
        "success": true,
        "group_message": group_message,
        "error": null
    });
    
    match serde_json::to_string(&result) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn ffi_decrypt_group_message_json(
    group_session_json: *const c_char,
    group_message_json: *const c_char,
) -> *mut c_char {
    if group_session_json.is_null() || group_message_json.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let group_session_str = unsafe { CStr::from_ptr(group_session_json) }.to_str();
    if group_session_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in group session").unwrap().into_raw();
    }
    
    let group_message_str = unsafe { CStr::from_ptr(group_message_json) }.to_str();
    if group_message_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in group message").unwrap().into_raw();
    }
    
    let group_session: Result<GroupSession, _> = serde_json::from_str(group_session_str.unwrap());
    if group_session.is_err() {
        return CString::new("ERROR: failed to parse group session").unwrap().into_raw();
    }
    
    let group_message: Result<GroupMessage, _> = serde_json::from_str(group_message_str.unwrap());
    if group_message.is_err() {
        return CString::new("ERROR: failed to parse group message").unwrap().into_raw();
    }
    
    let session = group_session.unwrap();
    let message = group_message.unwrap();
    
    let sender_key = match session.sender_keys.get(&message.sender_id) {
        Some(key) => key,
        None => return CString::new("ERROR: sender not found in group").unwrap().into_raw(),
    };
    
    match std::panic::catch_unwind(|| {
        decrypt_group_message(sender_key, &message.encrypted_message)
    }) {
        Ok(plaintext) => {
            let result = serde_json::json!({
                "success": true,
                "plaintext": plaintext,
                "sender_id": message.sender_id,
                "timestamp": message.timestamp,
                "error": null
            });
            match serde_json::to_string(&result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
            }
        }
        Err(_) => {
            let error_result = serde_json::json!({
                "success": false,
                "plaintext": null,
                "sender_id": null,
                "timestamp": null,
                "error": "Group message decryption failed"
            });
            match serde_json::to_string(&error_result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize error").unwrap().into_raw(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity_keypair;
    
    #[test]
    fn test_group_session_creation() {
        let creator_identity = generate_identity_keypair();
        let creator_json = serde_json::to_string(&creator_identity).unwrap();
        let creator_json_ptr = CString::new(creator_json).unwrap().into_raw();
        let group_id_ptr = CString::new("test_group_123").unwrap().into_raw();
        let creator_id_ptr = CString::new("creator_user_1").unwrap().into_raw();
        
        let result_ptr = ffi_create_group_session_json(
            group_id_ptr,
            creator_json_ptr,
            creator_id_ptr,
        );
        
        assert!(!result_ptr.is_null());
        
        let result_str = unsafe { CStr::from_ptr(result_ptr) }.to_str().unwrap();
        assert!(!result_str.starts_with("ERROR"));
        
        let result: serde_json::Value = serde_json::from_str(result_str).unwrap();
        assert_eq!(result["success"], true);
        assert!(result["group_session"].is_object());
        
        unsafe {
            let _ = CString::from_raw(creator_json_ptr);
            let _ = CString::from_raw(group_id_ptr);
            let _ = CString::from_raw(creator_id_ptr);
            let _ = CString::from_raw(result_ptr);
        }
    }
    
    #[test]
    fn test_group_message_encryption_decryption() {
        // Create group session
        let creator_identity = generate_identity_keypair();
        let creator_json = serde_json::to_string(&creator_identity).unwrap();
        let creator_json_ptr = CString::new(creator_json).unwrap().into_raw();
        let group_id_ptr = CString::new("test_group_123").unwrap().into_raw();
        let creator_id_ptr = CString::new("creator_user_1").unwrap().into_raw();
        
        let session_result_ptr = ffi_create_group_session_json(
            group_id_ptr,
            creator_json_ptr,
            creator_id_ptr,
        );
        
        let session_result_str = unsafe { CStr::from_ptr(session_result_ptr) }.to_str().unwrap();
        let session_result: serde_json::Value = serde_json::from_str(session_result_str).unwrap();
        let group_session_json = serde_json::to_string(&session_result["group_session"]).unwrap();
        
        // Encrypt message
        let group_session_ptr = CString::new(group_session_json.clone()).unwrap().into_raw();
        let sender_id_ptr = CString::new("creator_user_1").unwrap().into_raw();
        let plaintext_ptr = CString::new("Hello, group!").unwrap().into_raw();
        
        let encrypt_result_ptr = ffi_encrypt_group_message_json(
            group_session_ptr,
            sender_id_ptr,
            plaintext_ptr,
        );
        
        let encrypt_result_str = unsafe { CStr::from_ptr(encrypt_result_ptr) }.to_str().unwrap();
        let encrypt_result: serde_json::Value = serde_json::from_str(encrypt_result_str).unwrap();
        assert_eq!(encrypt_result["success"], true);
        
        // Decrypt message
        let group_message_json = serde_json::to_string(&encrypt_result["group_message"]).unwrap();
        let group_session_ptr2 = CString::new(group_session_json).unwrap().into_raw();
        let group_message_ptr = CString::new(group_message_json).unwrap().into_raw();
        
        let decrypt_result_ptr = ffi_decrypt_group_message_json(
            group_session_ptr2,
            group_message_ptr,
        );
        
        let decrypt_result_str = unsafe { CStr::from_ptr(decrypt_result_ptr) }.to_str().unwrap();
        let decrypt_result: serde_json::Value = serde_json::from_str(decrypt_result_str).unwrap();
        assert_eq!(decrypt_result["success"], true);
        assert_eq!(decrypt_result["plaintext"], "Hello, group!");
        
        // Cleanup
        unsafe {
            let _ = CString::from_raw(creator_json_ptr);
            let _ = CString::from_raw(group_id_ptr);
            let _ = CString::from_raw(creator_id_ptr);
            let _ = CString::from_raw(session_result_ptr);
            let _ = CString::from_raw(group_session_ptr);
            let _ = CString::from_raw(sender_id_ptr);
            let _ = CString::from_raw(plaintext_ptr);
            let _ = CString::from_raw(encrypt_result_ptr);
            let _ = CString::from_raw(group_session_ptr2);
            let _ = CString::from_raw(group_message_ptr);
            let _ = CString::from_raw(decrypt_result_ptr);
        }
    }
}