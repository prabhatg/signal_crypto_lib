# Flutter Signal Chat - Complete Signal Protocol Implementation

A comprehensive Flutter application demonstrating end-to-end encrypted group chat using the Signal Protocol. This implementation provides a complete example of integrating Signal Protocol cryptography with Flutter for secure messaging applications.

## 🔐 Features

### Signal Protocol Implementation
- **X3DH Key Agreement**: Secure session establishment between users
- **Double Ratchet**: Forward secrecy for 1:1 conversations
- **Group Messaging**: Sender key-based encryption for group conversations
- **Session Management**: Persistent session storage and management
- **Identity Management**: Cryptographic identity generation and verification

### Flutter Application Features
- **Group Chat Interface**: Create and manage encrypted group conversations
- **Real-time Messaging**: Send and receive encrypted messages
- **Member Management**: Add/remove members from groups
- **Material Design 3**: Modern UI with light/dark theme support
- **State Management**: Provider-based architecture for reactive UI
- **Mock Implementation**: Complete working demo without external dependencies

## 🏗️ Architecture

### Rust FFI Layer
```
src/
├── lib.rs              # Main library exports
├── x3dh_keys.rs        # X3DH and Double Ratchet FFI functions
├── group_ffi.rs        # Group messaging FFI functions
└── session_ffi.rs      # Session management FFI functions
```

### Flutter Application Layer
```
flutter_signal_chat/
├── lib/
│   ├── main.dart                           # Application entry point
│   ├── models/signal_models.dart           # Data models
│   ├── services/
│   │   ├── signal_ffi.dart                # FFI wrapper (for real implementation)
│   │   ├── signal_protocol_service.dart   # Protocol service
│   │   ├── group_manager.dart             # Group management
│   │   └── message_service.dart           # Message handling
│   └── screens/
│       └── home_screen.dart               # Main UI screen
└── pubspec.yaml                           # Dependencies
```

## 🚀 Getting Started

### Prerequisites
- Flutter SDK (3.0+)
- Rust toolchain
- Dart SDK (3.0+)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd signal_crypto_lib
   ```

2. **Build the Rust library**
   ```bash
   cargo build --release
   ```

3. **Set up Flutter dependencies**
   ```bash
   cd flutter_signal_chat
   flutter pub get
   ```

4. **Run the application**
   ```bash
   flutter run
   ```

## 📱 Usage

### Basic Group Chat Operations

#### Creating a Group
```dart
final groupManager = GroupManager();
final group = await groupManager.createGroup(
  'My Group',
  'user_id',
  [
    GroupMember(
      memberId: 'member1',
      name: 'Alice',
      identityKey: aliceIdentityKey,
      identityKeyEd: aliceIdentityKeyEd,
      joinedAt: DateTime.now(),
    ),
  ],
);
```

#### Sending Messages
```dart
final messageService = MessageService();
await messageService.sendGroupMessage(
  groupId,
  'Hello, group!',
  MessageType.text,
);
```

#### Managing Members
```dart
// Add member
await groupManager.addMember(groupId, newMember);

// Remove member
await groupManager.removeMember(groupId, memberId);
```

### Signal Protocol Operations

#### Identity Generation
```dart
final signalService = SignalProtocolService();
await signalService.initialize();
final identity = await signalService.generateIdentityKeypair();
```

#### Session Establishment
```dart
final session = await signalService.establishSession(
  aliceIdentity,
  bobPrekeyBundle,
);
```

#### Message Encryption/Decryption
```dart
// Encrypt
final encrypted = await signalService.encryptMessage(
  sessionId,
  'Secret message',
);

// Decrypt
final decrypted = await signalService.decryptMessage(
  sessionId,
  encryptedMessage,
);
```

## 🔧 FFI Integration

### Rust Functions

The Rust library exposes the following FFI functions:

#### Key Generation
- `ffi_generate_identity_keypair()` - Generate identity keypair
- `ffi_generate_prekey_bundle(identity_json)` - Generate prekey bundle

#### Session Management
- `ffi_x3dh_alice_init(...)` - Initialize X3DH as Alice
- `ffi_x3dh_bob_init(...)` - Initialize X3DH as Bob
- `ffi_encrypt_message(...)` - Encrypt message with Double Ratchet
- `ffi_decrypt_message(...)` - Decrypt message with Double Ratchet

#### Group Operations
- `ffi_create_group_session(...)` - Create group session
- `ffi_add_group_member(...)` - Add member to group
- `ffi_remove_group_member(...)` - Remove member from group
- `ffi_encrypt_group_message(...)` - Encrypt group message
- `ffi_decrypt_group_message(...)` - Decrypt group message

### Dart FFI Wrapper

```dart
class SignalFFI {
  static final DynamicLibrary _lib = DynamicLibrary.open('libsignal_crypto.so');
  
  // Function bindings
  static final _generateIdentityKeypair = _lib
      .lookupFunction<GenerateIdentityKeypairC, GenerateIdentityKeypairDart>(
          'ffi_generate_identity_keypair');
  
  // Wrapper methods
  static Map<String, dynamic> generateIdentityKeypair() {
    final resultPtr = _generateIdentityKeypair();
    final jsonStr = resultPtr.toDartString();
    _freeString(resultPtr);
    return jsonDecode(jsonStr);
  }
}
```

## 🔒 Security Features

### Cryptographic Primitives
- **Curve25519**: Elliptic curve Diffie-Hellman
- **Ed25519**: Digital signatures
- **AES-256-GCM**: Symmetric encryption
- **HMAC-SHA256**: Message authentication
- **HKDF**: Key derivation

### Protocol Security
- **Perfect Forward Secrecy**: Past messages remain secure even if keys are compromised
- **Future Secrecy**: Compromised keys don't affect future messages
- **Deniability**: Messages can't be proven to come from a specific sender
- **Group Security**: Efficient group key management with sender keys

### Implementation Security
- **Memory Safety**: Rust's memory safety prevents buffer overflows
- **Constant-Time Operations**: Timing attack resistance
- **Secure Random Generation**: Cryptographically secure randomness
- **Key Zeroization**: Sensitive data is securely cleared from memory

## 📊 Data Models

### Core Models

```dart
class IdentityKeyPair {
  final List<int> dhPublic;
  final List<int> dhPrivate;
  final List<int> edPublic;
  final List<int> edPrivate;
}

class PreKeyBundle {
  final int registrationId;
  final int deviceId;
  final List<int> identityKey;
  final List<int> signedPrekeyPublic;
  final List<int> signedPrekeySignature;
  final List<int>? oneTimePrekey;
}

class SessionState {
  final String sessionId;
  final List<int> rootKey;
  final List<int>? chainKeySend;
  final List<int>? chainKeyRecv;
  final int nSend;
  final int nRecv;
}

class GroupSession {
  final String groupId;
  final String name;
  final List<GroupMember> members;
  final Map<String, SenderKey> senderKeys;
  final DateTime createdAt;
  final String creatorId;
}
```

## 🧪 Testing

### Unit Tests
```bash
# Rust tests
cargo test

# Flutter tests
cd flutter_signal_chat
flutter test
```

### Integration Tests
```bash
# Flutter integration tests
flutter test integration_test/
```

### Manual Testing
1. Launch the application
2. Create a new group
3. Send messages
4. Add/remove members
5. Verify encryption/decryption

## 🔄 State Management

The application uses Provider for state management:

```dart
MultiProvider(
  providers: [
    ChangeNotifierProvider(create: (_) => SignalProtocolService()),
    ChangeNotifierProvider(create: (_) => GroupManager()),
    ChangeNotifierProvider(create: (_) => MessageService()),
  ],
  child: MaterialApp(...),
)
```

## 🎨 UI Components

### Home Screen
- **Chats Tab**: List of group conversations
- **Groups Tab**: Group management interface
- **Profile Tab**: User settings and protocol status

### Chat Interface
- Message list with encryption indicators
- Compose message with send button
- Member list and group settings

### Material Design 3
- Dynamic color schemes
- Adaptive layouts
- Accessibility support

## 🚧 Development Status

### Completed ✅
- [x] Complete Rust FFI implementation
- [x] X3DH key agreement protocol
- [x] Double Ratchet messaging
- [x] Group messaging with sender keys
- [x] Session management
- [x] Flutter application structure
- [x] Mock UI implementation
- [x] State management setup

### In Progress 🔄
- [ ] Real FFI integration (currently mocked)
- [ ] Database persistence
- [ ] Network layer
- [ ] Push notifications

### Planned 📋
- [ ] Voice/video calling
- [ ] File sharing
- [ ] Message reactions
- [ ] Advanced group features
- [ ] Cross-platform support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

### Code Style
- Rust: Follow `rustfmt` formatting
- Dart: Follow `dart format` formatting
- Use meaningful variable names
- Add comprehensive documentation

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📚 Documentation

For detailed implementation guides and API documentation, see:

- **[Dart Binding Guide](../docs/DART_BINDING_GUIDE.md)** - Complete guide for using Signal Protocol in Dart
- **[Dart API Reference](../docs/DART_API_REFERENCE.md)** - Detailed Dart binding API documentation
- **[Documentation Index](../docs/README.md)** - Complete documentation overview
- **[Main Project README](../README.md)** - Overall project documentation

## � References

- [Signal Protocol Specification](https://signal.org/docs/)
- [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Flutter Documentation](https://flutter.dev/docs)
- [Rust FFI Guide](https://doc.rust-lang.org/nomicon/ffi.html)

## 📞 Support

For questions and support:
- **Documentation**: Check the [Dart Binding Guide](../docs/DART_BINDING_GUIDE.md) and [Dart API Reference](../docs/DART_API_REFERENCE.md)
- **Issues**: Create an issue on GitHub
- **Examples**: This Flutter app serves as a complete working example

---

**Note**: This is a demonstration implementation. For production use, ensure proper security auditing, key management, and compliance with relevant regulations.