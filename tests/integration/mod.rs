/*
 * Signal Crypto Library 🔐
 * A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust
 *
 * Copyright (c) 2025 Prabhat Gupta
 *
 * Licensed under the MIT License
 * See LICENSE file in the project root for full license information.
 *
 * Integration tests module - end-to-end testing of complete Signal Protocol flows
 * including protocol flows, session lifecycle, group messaging, and security properties
 */

//! Integration tests for Signal Protocol implementation
//! 
//! This module contains end-to-end integration tests that verify
//! the complete protocol flows work correctly together.

pub mod protocol_flows;
pub mod session_lifecycle;
pub mod group_messaging;
pub mod security_properties;
pub mod performance_integration;
pub mod error_scenarios;
pub mod cross_platform;