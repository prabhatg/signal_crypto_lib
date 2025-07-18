// signal_crypto_lib/src/api.rs
// FFI bindings for Dart/Flutter integration

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;
use std::slice;

use crate::types::*;
use crate::identity::generate_identity_keypair;
use crate::prekey::{generate_signed_prekey, generate_one_time_prekey};
use crate::protocol::x3dh::x3dh_alice_init;
use crate::session_manager::SessionManager;

// Error codes for FFI
pub const SUCCESS: c_int = 0;
pub const ERROR_INVALID_INPUT: c_int = -1;
pub const ERROR_ENCRYPTION_FAILED: c_int = -2;
pub const ERROR_DECRYPTION_FAILED: c_int = -3;
pub const ERROR_SESSION_NOT_FOUND: c_int = -4;
pub const ERROR_STORAGE_FAILED: c_int = -5;
pub const ERROR_SERIALIZATION_FAILED: c_int = -6;

// Helper function to convert Rust string to C string
fn string_to_c_char(s: String) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

// Helper function to convert C string to Rust string
fn c_char_to_string(ptr: *const c_char) -> Result<String, std::str::Utf8Error> {
    unsafe {
        CStr::from_ptr(ptr).to_str().map(|s| s.to_string())
    }
}

// Helper function to free C string
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// Helper function to free byte array
#[no_mangle]
pub extern "C" fn free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

// Identity key generation
#[no_mangle]
pub extern "C" fn generate_identity_keys(
    dh_public: *mut *mut u8,
    dh_private: *mut *mut u8,
    ed_public: *mut *mut u8,
    ed_private: *mut *mut u8,
) -> c_int {
    let identity = generate_identity_keypair();
    
    unsafe {
        // Allocate and copy DH public key
        let dh_pub_vec = identity.dh_public.clone().into_boxed_slice();
        *dh_public = dh_pub_vec.as_ptr() as *mut u8;
        std::mem::forget(dh_pub_vec);
        
        // Allocate and copy DH private key
        let dh_priv_vec = identity.dh_private.clone().into_boxed_slice();
        *dh_private = dh_priv_vec.as_ptr() as *mut u8;
        std::mem::forget(dh_priv_vec);
        
        // Allocate and copy Ed25519 public key
        let ed_pub_vec = identity.ed_public.clone().into_boxed_slice();
        *ed_public = ed_pub_vec.as_ptr() as *mut u8;
        std::mem::forget(ed_pub_vec);
        
        // Allocate and copy Ed25519 private key
        let ed_priv_vec = identity.ed_private.clone().into_boxed_slice();
        *ed_private = ed_priv_vec.as_ptr() as *mut u8;
        std::mem::forget(ed_priv_vec);
    }
    
    SUCCESS
}

// Prekey generation
#[no_mangle]
pub extern "C" fn generate_signed_prekey_ffi(
    identity_private: *const u8,
    prekey_id: c_uint,
    public_key: *mut *mut u8,
    private_key: *mut *mut u8,
    signature: *mut *mut u8,
) -> c_int {
    // For FFI, we'd need to properly deserialize the identity keypair
    // This is a placeholder - proper implementation would deserialize IdentityKeyPair
    ERROR_INVALID_INPUT
}

// One-time prekey generation
#[no_mangle]
pub extern "C" fn generate_one_time_prekey_ffi(
    prekey_id: c_uint,
    public_key: *mut *mut u8,
    private_key: *mut *mut u8,
) -> c_int {
    let prekey = generate_one_time_prekey(prekey_id);
    
    unsafe {
        let pub_vec = prekey.public.clone().into_boxed_slice();
        *public_key = pub_vec.as_ptr() as *mut u8;
        std::mem::forget(pub_vec);
        
        let priv_vec = prekey.private.clone().into_boxed_slice();
        *private_key = priv_vec.as_ptr() as *mut u8;
        std::mem::forget(priv_vec);
    }
    
    SUCCESS
}

// X3DH key agreement (Alice side)
#[no_mangle]
pub extern "C" fn x3dh_alice_init_ffi(
    alice_identity: *const u8,
    bob_prekey_bundle: *const u8,
    bob_prekey_bundle_len: usize,
    initial_message: *mut *mut u8,
    initial_message_len: *mut usize,
    session_state: *mut *mut u8,
    session_state_len: *mut usize,
) -> c_int {
    // This is a simplified FFI wrapper - in practice you'd need proper serialization
    // For now, return an error to indicate this needs proper implementation
    ERROR_INVALID_INPUT
}

// Session Manager FFI
#[no_mangle]
pub extern "C" fn session_manager_new(
    db_path: *const c_char,
    storage_key: *const u8,
) -> *mut SessionManager {
    let db_path_str = match c_char_to_string(db_path) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    
    let storage_key_slice = unsafe { slice::from_raw_parts(storage_key, 32) };
    let storage_key_array: [u8; 32] = match storage_key_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return ptr::null_mut(),
    };
    
    let db_path = if db_path_str.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(db_path_str))
    };
    
    match SessionManager::new(db_path, storage_key_array) {
        Ok(manager) => Box::into_raw(Box::new(manager)),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn session_manager_free(manager: *mut SessionManager) {
    if !manager.is_null() {
        unsafe {
            let _ = Box::from_raw(manager);
        }
    }
}

#[no_mangle]
pub extern "C" fn session_manager_store_session(
    manager: *mut SessionManager,
    session_data: *const u8,
    session_data_len: usize,
    remote_identity: *const c_char,
) -> c_int {
    if manager.is_null() {
        return ERROR_INVALID_INPUT;
    }
    
    let remote_identity_str = match c_char_to_string(remote_identity) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    
    // For FFI, we'd need to deserialize the session data
    // This is a placeholder - proper implementation would deserialize SessionState
    ERROR_INVALID_INPUT
}

#[no_mangle]
pub extern "C" fn session_manager_load_session(
    manager: *mut SessionManager,
    remote_identity: *const c_char,
    session_data: *mut *mut u8,
    session_data_len: *mut usize,
) -> c_int {
    if manager.is_null() {
        return ERROR_INVALID_INPUT;
    }
    
    let remote_identity_str = match c_char_to_string(remote_identity) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    
    // For FFI, we'd need to serialize the session data
    // This is a placeholder - proper implementation would serialize SessionState
    ERROR_INVALID_INPUT
}

#[no_mangle]
pub extern "C" fn session_manager_delete_session(
    manager: *mut SessionManager,
    remote_identity: *const c_char,
) -> c_int {
    if manager.is_null() {
        return ERROR_INVALID_INPUT;
    }
    
    let remote_identity_str = match c_char_to_string(remote_identity) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    
    unsafe {
        match (*manager).delete_session(&remote_identity_str) {
            Ok(_) => SUCCESS,
            Err(_) => ERROR_STORAGE_FAILED,
        }
    }
}

#[no_mangle]
pub extern "C" fn session_manager_cleanup_expired(
    manager: *mut SessionManager,
) -> c_int {
    if manager.is_null() {
        return ERROR_INVALID_INPUT;
    }
    
    unsafe {
        match (*manager).cleanup_expired_sessions() {
            Ok(_) => SUCCESS,
            Err(_) => ERROR_STORAGE_FAILED,
        }
    }
}

// Group session management
#[no_mangle]
pub extern "C" fn session_manager_store_group_session(
    manager: *mut SessionManager,
    group_session_data: *const u8,
    group_session_data_len: usize,
) -> c_int {
    if manager.is_null() {
        return ERROR_INVALID_INPUT;
    }
    
    // For FFI, we'd need to deserialize the group session data
    // This is a placeholder - proper implementation would deserialize GroupSessionState
    ERROR_INVALID_INPUT
}

#[no_mangle]
pub extern "C" fn session_manager_load_group_session(
    manager: *mut SessionManager,
    group_id: *const c_char,
    sender_id: *const c_char,
    session_data: *mut *mut u8,
    session_data_len: *mut usize,
) -> c_int {
    if manager.is_null() {
        return ERROR_INVALID_INPUT;
    }
    
    let group_id_str = match c_char_to_string(group_id) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    
    let sender_id_str = match c_char_to_string(sender_id) {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    
    // For FFI, we'd need to serialize the group session data
    // This is a placeholder - proper implementation would serialize GroupSessionState
    ERROR_INVALID_INPUT
}

// Utility functions for getting array lengths
#[no_mangle]
pub extern "C" fn get_identity_key_length() -> usize {
    32
}

#[no_mangle]
pub extern "C" fn get_signature_length() -> usize {
    64
}

#[no_mangle]
pub extern "C" fn get_shared_secret_length() -> usize {
    32
}