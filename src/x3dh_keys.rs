// signal_crypto_lib/src/x3dh_keys.rs

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::types::*;
use crate::identity::generate_identity_keypair;
use crate::x3dh::create_simple_prekey_bundle;

// FFI bindings for Dart via C-ABI
#[no_mangle]
pub extern "C" fn ffi_free_string(ptr: *mut c_char) {
    if ptr.is_null() { 
        return; 
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn ffi_generate_identity_keypair_json() -> *mut c_char {
    let identity = generate_identity_keypair();
    match serde_json::to_string(&identity) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => CString::new("ERROR: serialize failed").unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn ffi_generate_prekey_bundle_json(identity_json: *const c_char) -> *mut c_char {
    if identity_json.is_null() {
        return CString::new("ERROR: null identity").unwrap().into_raw();
    }
    
    let identity_str = unsafe { CStr::from_ptr(identity_json) }.to_str();
    if identity_str.is_err() {
        return CString::new("ERROR: invalid UTF8").unwrap().into_raw();
    }
    
    let identity: Result<IdentityKeyPair, _> = serde_json::from_str(identity_str.unwrap());
    if identity.is_err() {
        return CString::new("ERROR: parse failed").unwrap().into_raw();
    }
    
    let bundle = create_simple_prekey_bundle(&identity.unwrap());
    match serde_json::to_string(&bundle) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(_) => CString::new("ERROR: serialize failed").unwrap().into_raw(),
    }
}

// X3DH Session Establishment FFI
#[no_mangle]
pub extern "C" fn ffi_x3dh_alice_init_json(
    alice_identity_json: *const c_char,
    alice_registration_id: u32,
    bob_bundle_json: *const c_char,
) -> *mut c_char {
    if alice_identity_json.is_null() || bob_bundle_json.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let alice_identity_str = unsafe { CStr::from_ptr(alice_identity_json) }.to_str();
    if alice_identity_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in alice identity").unwrap().into_raw();
    }
    
    let bob_bundle_str = unsafe { CStr::from_ptr(bob_bundle_json) }.to_str();
    if bob_bundle_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in bob bundle").unwrap().into_raw();
    }
    
    let alice_identity: Result<IdentityKeyPair, _> = serde_json::from_str(alice_identity_str.unwrap());
    if alice_identity.is_err() {
        return CString::new("ERROR: failed to parse alice identity").unwrap().into_raw();
    }
    
    let bob_bundle: Result<PreKeyBundle, _> = serde_json::from_str(bob_bundle_str.unwrap());
    if bob_bundle.is_err() {
        return CString::new("ERROR: failed to parse bob bundle").unwrap().into_raw();
    }
    
    match crate::protocol::x3dh::x3dh_alice_init(
        &alice_identity.unwrap(),
        alice_registration_id,
        &bob_bundle.unwrap(),
    ) {
        Ok((initial_message, session_state)) => {
            let result = serde_json::json!({
                "success": true,
                "initial_message": initial_message,
                "session_state": session_state,
                "error": null
            });
            match serde_json::to_string(&result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
            }
        }
        Err(e) => {
            let error_result = serde_json::json!({
                "success": false,
                "initial_message": null,
                "session_state": null,
                "error": format!("X3DH Alice init failed: {}", e)
            });
            match serde_json::to_string(&error_result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize error").unwrap().into_raw(),
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_x3dh_bob_init_json(
    bob_identity_json: *const c_char,
    bob_registration_id: u32,
    bob_signed_prekey_json: *const c_char,
    bob_one_time_prekey_json: *const c_char, // nullable
    initial_message_json: *const c_char,
) -> *mut c_char {
    if bob_identity_json.is_null() || bob_signed_prekey_json.is_null() || initial_message_json.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let bob_identity_str = unsafe { CStr::from_ptr(bob_identity_json) }.to_str();
    if bob_identity_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in bob identity").unwrap().into_raw();
    }
    
    let bob_signed_prekey_str = unsafe { CStr::from_ptr(bob_signed_prekey_json) }.to_str();
    if bob_signed_prekey_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in bob signed prekey").unwrap().into_raw();
    }
    
    let initial_message_str = unsafe { CStr::from_ptr(initial_message_json) }.to_str();
    if initial_message_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in initial message").unwrap().into_raw();
    }
    
    let bob_identity: Result<IdentityKeyPair, _> = serde_json::from_str(bob_identity_str.unwrap());
    if bob_identity.is_err() {
        return CString::new("ERROR: failed to parse bob identity").unwrap().into_raw();
    }
    
    let bob_signed_prekey: Result<SignedPreKey, _> = serde_json::from_str(bob_signed_prekey_str.unwrap());
    if bob_signed_prekey.is_err() {
        return CString::new("ERROR: failed to parse bob signed prekey").unwrap().into_raw();
    }
    
    let initial_message: Result<X3DHInitialMessage, _> = serde_json::from_str(initial_message_str.unwrap());
    if initial_message.is_err() {
        return CString::new("ERROR: failed to parse initial message").unwrap().into_raw();
    }
    
    // Parse optional one-time prekey
    let bob_one_time_prekey = if bob_one_time_prekey_json.is_null() {
        None
    } else {
        let otpk_str = unsafe { CStr::from_ptr(bob_one_time_prekey_json) }.to_str();
        if otpk_str.is_err() {
            return CString::new("ERROR: invalid UTF8 in one-time prekey").unwrap().into_raw();
        }
        match serde_json::from_str::<OneTimePreKey>(otpk_str.unwrap()) {
            Ok(otpk) => Some(otpk),
            Err(_) => return CString::new("ERROR: failed to parse one-time prekey").unwrap().into_raw(),
        }
    };
    
    match crate::protocol::x3dh::x3dh_bob_init(
        &bob_identity.unwrap(),
        bob_registration_id,
        &bob_signed_prekey.unwrap(),
        bob_one_time_prekey.as_ref(),
        &initial_message.unwrap(),
    ) {
        Ok(session_state) => {
            let result = serde_json::json!({
                "success": true,
                "session_state": session_state,
                "error": null
            });
            match serde_json::to_string(&result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
            }
        }
        Err(e) => {
            let error_result = serde_json::json!({
                "success": false,
                "session_state": null,
                "error": format!("X3DH Bob init failed: {}", e)
            });
            match serde_json::to_string(&error_result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize error").unwrap().into_raw(),
            }
        }
    }
}

// Double Ratchet Message Encryption/Decryption FFI
#[no_mangle]
pub extern "C" fn ffi_encrypt_message_json(
    session_json: *const c_char,
    plaintext: *const c_char,
    associated_data: *const c_char, // nullable
) -> *mut c_char {
    if session_json.is_null() || plaintext.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let session_str = unsafe { CStr::from_ptr(session_json) }.to_str();
    if session_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in session").unwrap().into_raw();
    }
    
    let plaintext_str = unsafe { CStr::from_ptr(plaintext) }.to_str();
    if plaintext_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in plaintext").unwrap().into_raw();
    }
    
    let mut session: Result<SessionState, _> = serde_json::from_str(session_str.unwrap());
    if session.is_err() {
        return CString::new("ERROR: failed to parse session").unwrap().into_raw();
    }
    
    let associated_data_bytes = if associated_data.is_null() {
        None
    } else {
        let ad_str = unsafe { CStr::from_ptr(associated_data) }.to_str();
        if ad_str.is_err() {
            return CString::new("ERROR: invalid UTF8 in associated data").unwrap().into_raw();
        }
        Some(ad_str.unwrap().as_bytes())
    };
    
    let mut session_state = session.unwrap();
    match crate::protocol::double_ratchet::encrypt_message(
        &mut session_state,
        plaintext_str.unwrap().as_bytes(),
        associated_data_bytes,
    ) {
        Ok(encrypted_message) => {
            let result = serde_json::json!({
                "success": true,
                "encrypted_message": encrypted_message,
                "updated_session": session_state,
                "error": null
            });
            match serde_json::to_string(&result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
            }
        }
        Err(e) => {
            let error_result = serde_json::json!({
                "success": false,
                "encrypted_message": null,
                "updated_session": null,
                "error": format!("Encryption failed: {}", e)
            });
            match serde_json::to_string(&error_result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize error").unwrap().into_raw(),
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_decrypt_message_json(
    session_json: *const c_char,
    message_json: *const c_char,
    associated_data: *const c_char, // nullable
) -> *mut c_char {
    if session_json.is_null() || message_json.is_null() {
        return CString::new("ERROR: null input").unwrap().into_raw();
    }
    
    let session_str = unsafe { CStr::from_ptr(session_json) }.to_str();
    if session_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in session").unwrap().into_raw();
    }
    
    let message_str = unsafe { CStr::from_ptr(message_json) }.to_str();
    if message_str.is_err() {
        return CString::new("ERROR: invalid UTF8 in message").unwrap().into_raw();
    }
    
    let mut session: Result<SessionState, _> = serde_json::from_str(session_str.unwrap());
    if session.is_err() {
        return CString::new("ERROR: failed to parse session").unwrap().into_raw();
    }
    
    let message: Result<DoubleRatchetMessage, _> = serde_json::from_str(message_str.unwrap());
    if message.is_err() {
        return CString::new("ERROR: failed to parse message").unwrap().into_raw();
    }
    
    let associated_data_bytes = if associated_data.is_null() {
        None
    } else {
        let ad_str = unsafe { CStr::from_ptr(associated_data) }.to_str();
        if ad_str.is_err() {
            return CString::new("ERROR: invalid UTF8 in associated data").unwrap().into_raw();
        }
        Some(ad_str.unwrap().as_bytes())
    };
    
    let mut session_state = session.unwrap();
    match crate::protocol::double_ratchet::decrypt_message(
        &mut session_state,
        &message.unwrap(),
        associated_data_bytes,
    ) {
        Ok(plaintext_bytes) => {
            let plaintext = String::from_utf8_lossy(&plaintext_bytes);
            let result = serde_json::json!({
                "success": true,
                "plaintext": plaintext,
                "updated_session": session_state,
                "error": null
            });
            match serde_json::to_string(&result) {
                Ok(json) => CString::new(json).unwrap().into_raw(),
                Err(_) => CString::new("ERROR: failed to serialize result").unwrap().into_raw(),
            }
        }
        Err(e) => {
            let error_result = serde_json::json!({
                "success": false,
                "plaintext": null,
                "updated_session": null,
                "error": format!("Decryption failed: {}", e)
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
    
    #[test]
    fn test_ffi_identity_generation() {
        let json_ptr = ffi_generate_identity_keypair_json();
        assert!(!json_ptr.is_null());
        
        let json_str = unsafe { CStr::from_ptr(json_ptr) }.to_str().unwrap();
        assert!(!json_str.starts_with("ERROR"));
        
        let identity: IdentityKeyPair = serde_json::from_str(json_str).unwrap();
        assert_eq!(identity.dh_public.len(), 32);
        assert_eq!(identity.dh_private.len(), 32);
        assert_eq!(identity.ed_public.len(), 32);
        assert_eq!(identity.ed_private.len(), 32);
        
        ffi_free_string(json_ptr);
    }
    
    #[test]
    fn test_ffi_prekey_bundle_generation() {
        // First generate an identity
        let identity_json_ptr = ffi_generate_identity_keypair_json();
        assert!(!identity_json_ptr.is_null());
        
        // Then generate a prekey bundle
        let bundle_json_ptr = ffi_generate_prekey_bundle_json(identity_json_ptr);
        assert!(!bundle_json_ptr.is_null());
        
        let bundle_str = unsafe { CStr::from_ptr(bundle_json_ptr) }.to_str().unwrap();
        assert!(!bundle_str.starts_with("ERROR"));
        
        let bundle: PreKeyBundle = serde_json::from_str(bundle_str).unwrap();
        assert_eq!(bundle.identity_key.len(), 32);
        assert_eq!(bundle.signed_prekey_public.len(), 32);
        assert!(bundle.one_time_prekey.is_some());
        
        ffi_free_string(identity_json_ptr);
        ffi_free_string(bundle_json_ptr);
    }
}
