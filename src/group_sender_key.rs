/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Group sender key management for efficient group messaging with forward secrecy.
 * Implements sender key chains, message encryption/decryption, group key rotation,
 * and mock prekey server functionality for scalable group communications.
 */

// signal_crypto_lib/src/group_sender_key.rs

use serde::{Serialize, Deserialize};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar, c_uint};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SenderKeyMessage {
    pub version: u8,
    pub group_id: String,
    pub sender_id: String,
    pub message_index: u32,
    pub ciphertext: Vec<u8>,
    pub associated_data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SenderKeyState {
    pub sender_id: String,
    pub group_id: String,
    pub chain_key: Vec<u8>,
    pub ratchet_key: Vec<u8>,
    pub message_index: u32,
}

impl SenderKeyState {
    pub fn new(sender_id: &str, group_id: &str) -> Self {
        let chain_key = hkdf_initial_key(sender_id, group_id);
        let ratchet = EphemeralSecret::new(OsRng);
        Self {
            sender_id: sender_id.to_string(),
            group_id: group_id.to_string(),
            chain_key,
            ratchet_key: PublicKey::from(&ratchet).as_bytes().to_vec(),
            message_index: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: Option<&[u8]>) -> SenderKeyMessage {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};

        let (key, nonce) = derive_message_key(&self.chain_key, self.message_index);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data.unwrap_or(&[]),
            },
        ).unwrap();

        self.message_index += 1;
        self.chain_key = update_chain_key(&self.chain_key);

        SenderKeyMessage {
            version: 1,
            group_id: self.group_id.clone(),
            sender_id: self.sender_id.clone(),
            message_index: self.message_index,
            ciphertext,
            associated_data: associated_data.map(|a| a.to_vec()),
        }
    }

    pub fn decrypt(&self, msg: &SenderKeyMessage) -> Option<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::{Aead, Payload};
        if msg.group_id != self.group_id || msg.sender_id != self.sender_id {
            return None;
        }
        let (key, nonce) = derive_message_key(&self.chain_key, msg.message_index - 1);
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &msg.ciphertext,
                aad: msg.associated_data.as_deref().unwrap_or(&[]),
            },
        ).ok()
    }

    pub fn reinitialize_group_key(&mut self, new_group_id: &str) {
        self.group_id = new_group_id.to_string();
        self.chain_key = hkdf_initial_key(&self.sender_id, new_group_id);
        let ratchet = EphemeralSecret::new(OsRng);
        self.ratchet_key = PublicKey::from(&ratchet).as_bytes().to_vec();
        self.message_index = 0;
    }

    pub fn reinitialize_with_seed(&mut self, new_group_id: &str, seed: &[u8]) {
        self.group_id = new_group_id.to_string();
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), seed);
        let mut out = [0u8; 32];
        hk.expand(&[], &mut out).unwrap();
        self.chain_key = out.to_vec();
        let ratchet = EphemeralSecret::new(OsRng);
        self.ratchet_key = PublicKey::from(&ratchet).as_bytes().to_vec();
        self.message_index = 0;
    }
}

#[no_mangle]
pub extern "C" fn sender_key_reinitialize_with_seed(
    state_ptr: *mut SenderKeyState,
    group_id: *const c_char,
    seed_ptr: *const c_uchar,
    seed_len: c_uint,
) {
    if state_ptr.is_null() || group_id.is_null() || seed_ptr.is_null() {
        return;
    }
    let state = unsafe { &mut *state_ptr };
    let group_id = unsafe { CStr::from_ptr(group_id) }.to_str().unwrap_or("");
    let seed = unsafe { std::slice::from_raw_parts(seed_ptr, seed_len as usize) };
    state.reinitialize_with_seed(group_id, seed);
}

fn hkdf_initial_key(sender: &str, group: &str) -> Vec<u8> {
    let salt = [0u8; 32];
    let ikm = [sender.as_bytes(), group.as_bytes()].concat();
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut out = [0u8; 32];
    hk.expand(&[], &mut out).unwrap();
    out.to_vec()
}

fn derive_message_key(chain_key: &[u8], index: u32) -> (Vec<u8>, [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(chain_key), &index.to_be_bytes());
    let mut out = [0u8; 44];
    hk.expand(&[], &mut out).unwrap();
    (out[..32].to_vec(), out[32..].try_into().unwrap())
}

fn update_chain_key(chain_key: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(chain_key), b"step");
    let mut out = [0u8; 32];
    hk.expand(&[], &mut out).unwrap();
    out.to_vec()
}

// Mock prekey server
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Default, Clone)]
pub struct MockPrekeyServer {
    pub storage: HashMap<String, Vec<Vec<u8>>>,
}

static PREKEY_SERVER: OnceLock<Mutex<MockPrekeyServer>> = OnceLock::new();

impl MockPrekeyServer {
    pub fn global() -> &'static Mutex<Self> {
        PREKEY_SERVER.get_or_init(|| Mutex::new(Self::default()))
    }

    pub fn add_prekey(&mut self, user_id: &str, prekey: Vec<u8>) {
        self.storage.entry(user_id.to_string()).or_default().push(prekey);
    }

    pub fn get_prekey(&mut self, user_id: &str) -> Option<Vec<u8>> {
        self.storage.get_mut(user_id)?.pop()
    }

    pub fn depleted(&self, user_id: &str) -> bool {
        self.storage.get(user_id).map_or(true, |v| v.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_sender_encryption_decryption() {
        let mut alice_state = SenderKeyState::new("alice", "group1");
        let bob_state = SenderKeyState {
            sender_id: "alice".into(),
            group_id: "group1".into(),
            chain_key: alice_state.chain_key.clone(),
            ratchet_key: alice_state.ratchet_key.clone(),
            message_index: 0,
        };

        let plaintext = b"hello group!";
        let msg = alice_state.encrypt(plaintext, Some(b"meta"));
        let decrypted = bob_state.decrypt(&msg).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_prekey_depletion() {
        let server = MockPrekeyServer::global();
        {
            let mut srv = server.lock().unwrap();
            srv.add_prekey("user1", vec![1,2,3]);
            assert!(!srv.depleted("user1"));
            let key = srv.get_prekey("user1");
            assert_eq!(key, Some(vec![1,2,3]));
            assert!(srv.depleted("user1"));
        }
    }

    #[test]
    fn test_group_key_reinitialization() {
        let mut state = SenderKeyState::new("alice", "group1");
        let old_chain_key = state.chain_key.clone();
        state.reinitialize_group_key("group2");
        assert_ne!(state.group_id, "group1");
        assert_ne!(state.chain_key, old_chain_key);
        assert_eq!(state.message_index, 0);
    }

    #[test]
    fn test_group_key_reinitialization_with_seed() {
        let mut state = SenderKeyState::new("alice", "group1");
        let seed = b"admin-seed-material";
        state.reinitialize_with_seed("group2", seed);
        assert_eq!(state.group_id, "group2");
        assert_eq!(state.message_index, 0);
    }
}
