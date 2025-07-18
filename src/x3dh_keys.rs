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
