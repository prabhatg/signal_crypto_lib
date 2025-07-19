<!--
Signal Crypto Library 🔐
A comprehensive, enterprise-grade implementation of the Signal Protocol in Rust

Copyright (c) 2025 Prabhat Gupta

Licensed under the MIT License
See LICENSE file in the project root for full license information.

Signal Protocol usage examples - basic Dart FFI examples and comprehensive Flutter
application demonstrating cryptographic operations and secure messaging patterns
-->

# Signal Protocol Examples

This directory contains basic examples for using the Signal Protocol library.

## 📁 Examples

### Basic Dart Example
- **File**: [`dart_example.dart`](dart_example.dart)
- **Description**: Basic FFI usage example showing identity generation and prekey bundles
- **Usage**: `dart run dart_example.dart`

### Complete Flutter Application
- **Location**: [`../flutter_signal_chat/`](../flutter_signal_chat/)
- **Description**: Full-featured Flutter group chat application with Signal Protocol
- **Features**: Complete X3DH, Double Ratchet, group messaging, and UI implementation

## 🚀 Getting Started

### For Basic Usage
```bash
# Run the basic Dart example
dart run example/dart_example.dart
```

### For Complete Implementation
```bash
# Explore the full Flutter application
cd flutter_signal_chat
flutter pub get
flutter run
```

## 📚 Documentation

- **[Dart Binding Guide](../docs/DART_BINDING_GUIDE.md)** - Complete integration guide
- **[Dart API Reference](../docs/DART_API_REFERENCE.md)** - Detailed Dart binding API documentation
- **[Flutter Example](../flutter_signal_chat/README.md)** - Complete application documentation

## 🔄 Migration Path

If you're using the basic example and want to upgrade to the full implementation:

1. **Review** the [Flutter example](../flutter_signal_chat/) for complete functionality
2. **Follow** the [Dart Binding Guide](../docs/DART_BINDING_GUIDE.md) for integration
3. **Reference** the [Dart API documentation](../docs/DART_API_REFERENCE.md) for all available functions

The basic example here is maintained for educational purposes, but the Flutter application provides a production-ready implementation with all Signal Protocol features.