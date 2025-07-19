/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Protocol constants and configuration values for the Signal Protocol implementation.
 * Defines key sizes, KDF info strings, and protocol parameters.
 */

// signal_crypto_lib/src/protocol/constants.rs

// Protocol version
pub const PROTOCOL_VERSION: u8 = 3;

// Key sizes
pub const DH_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const SYMMETRIC_KEY_SIZE: usize = 32;
pub const MAC_KEY_SIZE: usize = 32;
pub const ROOT_KEY_SIZE: usize = 32;
pub const CHAIN_KEY_SIZE: usize = 32;

// KDF info strings
pub const X3DH_INFO: &[u8] = b"Signal_X3DH_25519_AES-256-GCM_SHA256";
pub const ROOT_KDF_INFO: &[u8] = b"WhisperRatchet";
pub const CHAIN_KDF_INFO: &[u8] = b"WhisperMessageKeys";
pub const MESSAGE_KDF_INFO: &[u8] = b"WhisperMessageKeys";

// Double Ratchet KDF info strings
pub const ROOT_KEY_INFO: &[u8] = b"WhisperRatchet";
pub const CHAIN_KEY_INFO: &[u8] = b"WhisperChain";
pub const MESSAGE_KEY_INFO: &[u8] = b"WhisperMessageKeys";
pub const HEADER_KEY_INFO: &[u8] = b"WhisperHeaderKeys";

// Double Ratchet constants
pub const MAX_SKIP: u32 = 1000;
pub const MAX_SESSIONS: usize = 5;

// Message types
pub const PREKEY_TYPE: u8 = 3;
pub const MESSAGE_TYPE: u8 = 1;

// Registration ID bounds
pub const REGISTRATION_ID_MAX: u32 = 0x3FFF; // 14 bits