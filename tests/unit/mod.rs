/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Unit tests module - comprehensive testing of individual Signal Protocol components
 * including X3DH, Double Ratchet, Sesame, identity management, and cryptographic primitives
 */

//! Unit tests for Signal Protocol core components
//! 
//! This module contains comprehensive unit tests for all core protocol
//! components, organized by functionality.

pub mod x3dh;
pub mod double_ratchet;
pub mod sesame;
pub mod identity;
pub mod prekeys;
pub mod session_manager;
pub mod crypto;
pub mod types;