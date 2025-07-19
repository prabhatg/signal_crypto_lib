/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Skipped message keys management for out-of-order message handling.
 * Implements secure key storage with TTL expiration, memory limits,
 * and FFI bindings for robust Double Ratchet message decryption.
 */

// signal_crypto_lib/src/skipped_keys.rs

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

const MAX_SKIPPED_KEYS: usize = 50;
const KEY_TTL_SECS: u64 = 600; // 10 minutes

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SkippedKeyStore {
    keys: HashMap<u32, (Vec<u8>, u64)>, // (key, timestamp)
    queue: VecDeque<u32>,
}

impl SkippedKeyStore {
    pub fn clear_expired(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.keys.retain(|_, (_, ts)| now - *ts <= KEY_TTL_SECS);
        self.queue.retain(|i| self.keys.contains_key(i));
    }

    pub fn store_key(&mut self, index: u32, key: Vec<u8>) {
        self.clear_expired();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.keys.insert(index, (key, now));
        self.queue.push_back(index);

        if self.queue.len() > MAX_SKIPPED_KEYS {
            if let Some(oldest) = self.queue.pop_front() {
                self.keys.remove(&oldest);
            }
        }
    }

    pub fn use_key(&mut self, index: u32) -> Option<Vec<u8>> {
        self.clear_expired();
        if let Some((key, _)) = self.keys.remove(&index) {
            self.queue.retain(|&i| i != index);
            return Some(key);
        }
        None
    }
}

#[cfg(feature = "ffi")]
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn skipped_key_store_new() -> *mut SkippedKeyStore {
    Box::into_raw(Box::new(SkippedKeyStore::default()))
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn skipped_key_store_free(ptr: *mut SkippedKeyStore) {
    if !ptr.is_null() {
        unsafe { Box::from_raw(ptr); }
    }
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn skipped_key_store_clear_expired(ptr: *mut SkippedKeyStore) {
    if let Some(store) = unsafe { ptr.as_mut() } {
        store.clear_expired();
    }
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn skipped_key_store_store_key(
    ptr: *mut SkippedKeyStore,
    index: c_uint,
    key_ptr: *const u8,
    key_len: usize,
) {
    if let Some(store) = unsafe { ptr.as_mut() } {
        if !key_ptr.is_null() {
            let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len).to_vec() };
            store.store_key(index, key);
        }
    }
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub extern "C" fn skipped_key_store_use_key(
    ptr: *mut SkippedKeyStore,
    index: c_uint,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> bool {
    if let Some(store) = unsafe { ptr.as_mut() } {
        if let Some(key) = store.use_key(index) {
            let len = key.len();
            if !out_buf.is_null() && !out_len.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(key.as_ptr(), out_buf, len);
                    *out_len = len;
                }
                return true;
            }
        }
    }
    false
}
