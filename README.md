# Signal Crypto Library

A Rust implementation of the Signal Protocol for secure end-to-end encryption, designed to work with Dart/Flutter applications through FFI bindings.

## Features

This library implements the complete Signal Protocol specification including:

- **X3DH (Extended Triple Diffie-Hellman)**: Asynchronous key agreement protocol
- **Double Ratchet Algorithm**: Forward secrecy and post-compromise security
- **Prekey Bundles**: Allows asynchronous session establishment
- **Group Messaging**: Sender key distribution for efficient group encryption
- **FFI Bindings**: Direct integration with Dart/Flutter applications

## Architecture

The library is organized into several modules:

- `identity`: Identity key pair generation (X25519 for DH, Ed25519 for signatures)
- `x3dh`: X3DH key agreement implementation
- `prekey`: Prekey bundle creation and management
- `double_ratchet`: Message encryption/decryption with forward secrecy
- `group`: Group messaging with sender keys
- `x3dh_keys`: FFI bindings for Dart integration

## Building the Library

### Prerequisites

- Rust 1.70 or later
- Cargo

### Build for Release

```bash
cargo build --release
```

This will create a dynamic library in `target/release/`:
- macOS: `libsignal_crypto_lib.dylib`
- Linux: `libsignal_crypto_lib.so`
- Windows: `signal_crypto_lib.dll`

### Build with FFI Support

```bash
cargo build --release --features ffi
```

## Dart/Flutter Integration

### 1. Add FFI Dependency

In your `pubspec.yaml`:

```yaml
dependencies:
  ffi: ^2.0.0
```

### 2. Create Dart Bindings

Create a file `lib/signal_crypto.dart`:

```dart
import 'dart:ffi';
import 'dart:convert';
import 'package:ffi/ffi.dart';

// Load the dynamic library
final DynamicLibrary signalCrypto = Platform.isAndroid
    ? DynamicLibrary.open('libsignal_crypto_lib.so')
    : Platform.isIOS
    ? DynamicLibrary.process()
    : Platform.isMacOS
    ? DynamicLibrary.open('libsignal_crypto_lib.dylib')
    : DynamicLibrary.open('signal_crypto_lib.dll');

// FFI function signatures
typedef GenerateIdentityKeypairC = Pointer<Utf8> Function();
typedef GenerateIdentityKeypairDart = Pointer<Utf8> Function();

typedef GeneratePrekeyBundleC = Pointer<Utf8> Function(Pointer<Utf8>);
typedef GeneratePrekeyBundleDart = Pointer<Utf8> Function(Pointer<Utf8>);

typedef FreeStringC = Void Function(Pointer<Utf8>);
typedef FreeStringDart = void Function(Pointer<Utf8>);

// Bind the functions
final generateIdentityKeypair = signalCrypto
    .lookupFunction<GenerateIdentityKeypairC, GenerateIdentityKeypairDart>(
        'ffi_generate_identity_keypair_json');

final generatePrekeyBundle = signalCrypto
    .lookupFunction<GeneratePrekeyBundleC, GeneratePrekeyBundleDart>(
        'ffi_generate_prekey_bundle_json');

final freeString = signalCrypto
    .lookupFunction<FreeStringC, FreeStringDart>('ffi_free_string');

// Dart wrapper classes
class SignalCrypto {
  static Map<String, dynamic> generateIdentityKeypair() {
    final resultPtr = generateIdentityKeypair();
    final jsonStr = resultPtr.toDartString();
    freeString(resultPtr);
    
    if (jsonStr.startsWith('ERROR:')) {
      throw Exception(jsonStr);
    }
    
    return json.decode(jsonStr);
  }
  
  static Map<String, dynamic> generatePrekeyBundle(Map<String, dynamic> identity) {
    final identityJson = json.encode(identity);
    final identityPtr = identityJson.toNativeUtf8();
    
    final resultPtr = generatePrekeyBundle(identityPtr);
    final jsonStr = resultPtr.toDartString();
    
    malloc.free(identityPtr);
    freeString(resultPtr);
    
    if (jsonStr.startsWith('ERROR:')) {
      throw Exception(jsonStr);
    }
    
    return json.decode(jsonStr);
  }
}
```

### 3. Usage Example

```dart
import 'package:your_app/signal_crypto.dart';

void main() async {
  // Generate identity keypair
  final identity = SignalCrypto.generateIdentityKeypair();
  print('Generated identity: ${identity['ed_public'].length} bytes public key');
  
  // Generate prekey bundle
  final prekeyBundle = SignalCrypto.generatePrekeyBundle(identity);
  print('Generated prekey bundle with signed prekey');
  
  // The identity and prekey bundle can now be published to a server
  // for other users to establish sessions
}
```

## Rust API Usage

### Basic Example

```rust
use signal_crypto_lib::*;

fn main() {
    // Generate identity keys for Alice and Bob
    let alice_identity = generate_identity_keypair();
    let bob_identity = generate_identity_keypair();
    
    // Bob creates and publishes a prekey bundle
    let bob_bundle = create_prekey_bundle(&bob_identity);
    
    // Alice establishes a session with Bob
    let mut alice_session = establish_session(&alice_identity, &bob_bundle);
    
    // Bob establishes a session with Alice
    let alice_bundle = create_prekey_bundle(&alice_identity);
    let mut bob_session = establish_session(&bob_identity, &alice_bundle);
    
    // Synchronize chain keys (in practice, this happens through message exchange)
    bob_session.recv_chain_key = alice_session.send_chain_key.clone();
    alice_session.recv_chain_key = bob_session.send_chain_key.clone();
    
    // Alice sends a message to Bob
    let plaintext = "Hello Bob!";
    let encrypted = encrypt(&mut alice_session, plaintext);
    
    // Bob decrypts the message
    let decrypted = decrypt(&mut bob_session, &encrypted);
    assert_eq!(plaintext, decrypted);
}
```

### Group Messaging Example

```rust
use signal_crypto_lib::*;

fn main() {
    // Create a sender key for the group
    let sender_key = generate_sender_key();
    
    // Distribute the sender key to all group members
    let member1_key = sender_key.clone();
    let member2_key = sender_key.clone();
    
    // Any member can encrypt messages
    let plaintext = "Hello group!";
    let encrypted = encrypt_group_message(&sender_key, plaintext);
    
    // All members can decrypt
    let decrypted1 = decrypt_group_message(&member1_key, &encrypted);
    let decrypted2 = decrypt_group_message(&member2_key, &encrypted);
    
    assert_eq!(plaintext, decrypted1);
    assert_eq!(plaintext, decrypted2);
}
```

## Security Considerations

1. **Key Storage**: Private keys should be stored securely using platform-specific secure storage (Keychain on iOS, Keystore on Android)
2. **Key Rotation**: Implement regular rotation of prekeys and sender keys
3. **Perfect Forward Secrecy**: The Double Ratchet algorithm provides PFS by default
4. **Memory Safety**: The library uses `zeroize` to clear sensitive data from memory

## Testing

Run the test suite:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. New features include tests
3. Code follows Rust conventions
4. Documentation is updated

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

This implementation is based on the Signal Protocol specifications:
- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Sender Key Specification](https://signal.org/docs/specifications/sesame/)