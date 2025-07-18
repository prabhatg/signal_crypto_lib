# Signal Protocol Dart Binding API Reference

Complete API reference for the Signal Protocol Dart bindings, including all FFI functions, data models, and service interfaces.

## 📋 Table of Contents

1. [FFI Functions](#ffi-functions)
2. [Data Models](#data-models)
3. [Service APIs](#service-apis)
4. [Error Codes](#error-codes)
5. [Type Definitions](#type-definitions)

## 🔧 FFI Functions

### Identity and Key Management

#### `ffi_generate_identity_keypair()`

Generates a new identity keypair for Signal Protocol.

**Signature:**
```rust
extern "C" fn ffi_generate_identity_keypair() -> *mut c_char
```

**Returns:**
```json
{
  "success": true,
  "data": {
    "dh_public": [32 bytes],
    "dh_private": [32 bytes],
    "ed_public": [32 bytes],
    "ed_private": [32 bytes]
  }
}
```

**Dart Usage:**
```dart
final result = SignalFFI.generateIdentityKeypair();
final identity = IdentityKeyPair.fromJson(result['data']);
```

#### `ffi_generate_prekey_bundle(identity_json)`

Generates a prekey bundle for key exchange.

**Parameters:**
- `identity_json`: JSON string containing identity keypair

**Signature:**
```rust
extern "C" fn ffi_generate_prekey_bundle(identity_json: *const c_char) -> *mut c_char
```

**Returns:**
```json
{
  "success": true,
  "data": {
    "registration_id": 12345,
    "device_id": 1,
    "identity_key": [32 bytes],
    "identity_key_ed": [32 bytes],
    "signed_prekey_id": 1,
    "signed_prekey_public": [32 bytes],
    "signed_prekey_signature": [64 bytes],
    "one_time_prekey_id": 1,
    "one_time_prekey": [32 bytes]
  }
}
```

### X3DH Key Agreement

#### `ffi_x3dh_alice_init_json(alice_identity_json, bob_device_id, bob_prekey_bundle_json)`

Initiates X3DH key agreement as Alice.

**Parameters:**
- `alice_identity_json`: Alice's identity keypair
- `bob_device_id`: Bob's device ID
- `bob_prekey_bundle_json`: Bob's prekey bundle

**Signature:**
```rust
extern "C" fn ffi_x3dh_alice_init_json(
    alice_identity_json: *const c_char,
    bob_device_id: u32,
    bob_prekey_bundle_json: *const c_char
) -> *mut c_char
```

**Returns:**
```json
{
  "success": true,
  "data": {
    "session_id": "session_abc123",
    "registration_id": 12345,
    "device_id": 1,
    "dh_self_private": [32 bytes],
    "dh_self_public": [32 bytes],
    "dh_remote": [32 bytes],
    "root_key": [32 bytes],
    "chain_key_send": [32 bytes],
    "chain_key_recv": null,
    "n_send": 0,
    "n_recv": 0,
    "pn": 0,
    "max_skip": 1000
  }
}
```

#### `ffi_x3dh_bob_init_json(bob_identity_json, alice_device_id, alice_identity_json, alice_signed_prekey_json, alice_one_time_prekey_json, initial_message_json)`

Responds to X3DH key agreement as Bob.

**Parameters:**
- `bob_identity_json`: Bob's identity keypair
- `alice_device_id`: Alice's device ID
- `alice_identity_json`: Alice's identity key
- `alice_signed_prekey_json`: Alice's signed prekey
- `alice_one_time_prekey_json`: Alice's one-time prekey (optional)
- `initial_message_json`: Alice's initial message

**Returns:** Session state similar to Alice init.

### Double Ratchet Messaging

#### `ffi_encrypt_message_json(session_json, plaintext_json, associated_data_json)`

Encrypts a message using Double Ratchet.

**Parameters:**
- `session_json`: Current session state
- `plaintext_json`: Message to encrypt
- `associated_data_json`: Additional authenticated data

**Signature:**
```rust
extern "C" fn ffi_encrypt_message_json(
    session_json: *const c_char,
    plaintext_json: *const c_char,
    associated_data_json: *const c_char
) -> *mut c_char
```

**Returns:**
```json
{
  "success": true,
  "data": {
    "encrypted_message": {
      "header": [40 bytes],
      "ciphertext": [variable length]
    },
    "updated_session": {
      // Updated session state
    }
  }
}
```

#### `ffi_decrypt_message_json(session_json, encrypted_message_json, associated_data_json)`

Decrypts a message using Double Ratchet.

**Parameters:**
- `session_json`: Current session state
- `encrypted_message_json`: Encrypted message
- `associated_data_json`: Additional authenticated data

**Returns:**
```json
{
  "success": true,
  "data": {
    "plaintext": "Decrypted message",
    "updated_session": {
      // Updated session state
    }
  }
}
```

### Group Messaging

#### `ffi_create_group_session(group_id_json, creator_identity_json, initial_members_json)`

Creates a new group session.

**Parameters:**
- `group_id_json`: Unique group identifier
- `creator_identity_json`: Creator's identity
- `initial_members_json`: Array of initial members

**Signature:**
```rust
extern "C" fn ffi_create_group_session(
    group_id_json: *const c_char,
    creator_identity_json: *const c_char,
    initial_members_json: *const c_char
) -> *mut c_char
```

**Returns:**
```json
{
  "success": true,
  "data": {
    "group_id": "group_abc123",
    "name": "My Group",
    "members": [
      {
        "member_id": "user1",
        "identity_key": [32 bytes],
        "identity_key_ed": [32 bytes],
        "joined_at": "2024-01-01T00:00:00Z"
      }
    ],
    "sender_keys": {},
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "creator_id": "creator_user"
  }
}
```

#### `ffi_add_group_member(group_session_json, member_identity_json, inviter_identity_json)`

Adds a member to an existing group.

**Parameters:**
- `group_session_json`: Current group session
- `member_identity_json`: New member's identity
- `inviter_identity_json`: Inviter's identity

#### `ffi_remove_group_member(group_session_json, member_id_json)`

Removes a member from a group.

**Parameters:**
- `group_session_json`: Current group session
- `member_id_json`: ID of member to remove

#### `ffi_encrypt_group_message(group_session_json, sender_identity_json, plaintext_json)`

Encrypts a message for group delivery.

**Parameters:**
- `group_session_json`: Group session state
- `sender_identity_json`: Sender's identity
- `plaintext_json`: Message to encrypt

**Returns:**
```json
{
  "success": true,
  "data": {
    "encrypted_message": {
      "message_id": "msg_abc123",
      "group_id": "group_abc123",
      "sender_id": "user1",
      "encrypted_message": {
        "content": [encrypted bytes],
        "sender_key_id": 1
      },
      "timestamp": "2024-01-01T00:00:00Z",
      "message_type": "text"
    },
    "updated_session": {
      // Updated group session
    }
  }
}
```

#### `ffi_decrypt_group_message(group_session_json, encrypted_message_json)`

Decrypts a group message.

**Parameters:**
- `group_session_json`: Group session state
- `encrypted_message_json`: Encrypted group message

### Session Management

#### `ffi_session_manager_new(user_id_json, storage_path_json)`

Creates a new session manager.

**Parameters:**
- `user_id_json`: User identifier
- `storage_path_json`: Path for session storage

#### `ffi_store_session(manager_handle, session_id_json, session_data_json)`

Stores a session in persistent storage.

**Parameters:**
- `manager_handle`: Session manager handle
- `session_id_json`: Session identifier
- `session_data_json`: Session data to store

#### `ffi_load_session(manager_handle, session_id_json)`

Loads a session from persistent storage.

**Parameters:**
- `manager_handle`: Session manager handle
- `session_id_json`: Session identifier

#### `ffi_free_string(ptr)`

Frees memory allocated by FFI functions.

**Parameters:**
- `ptr`: Pointer to string to free

## 📊 Data Models

### IdentityKeyPair

```dart
class IdentityKeyPair {
  final List<int> dhPublic;      // 32 bytes - Curve25519 public key
  final List<int> dhPrivate;     // 32 bytes - Curve25519 private key
  final List<int> edPublic;      // 32 bytes - Ed25519 public key
  final List<int> edPrivate;     // 32 bytes - Ed25519 private key

  IdentityKeyPair({
    required this.dhPublic,
    required this.dhPrivate,
    required this.edPublic,
    required this.edPrivate,
  });

  factory IdentityKeyPair.fromJson(Map<String, dynamic> json);
  Map<String, dynamic> toJson();
}
```

### PreKeyBundle

```dart
class PreKeyBundle {
  final int registrationId;           // Unique registration ID
  final int deviceId;                 // Device identifier
  final List<int> identityKey;        // Identity public key
  final List<int> identityKeyEd;      // Ed25519 identity key
  final int signedPrekeyId;           // Signed prekey ID
  final List<int> signedPrekeyPublic; // Signed prekey public
  final List<int> signedPrekeySignature; // Prekey signature
  final int? oneTimePrekeyId;         // One-time prekey ID (optional)
  final List<int>? oneTimePrekey;     // One-time prekey (optional)

  PreKeyBundle({
    required this.registrationId,
    required this.deviceId,
    required this.identityKey,
    required this.identityKeyEd,
    required this.signedPrekeyId,
    required this.signedPrekeyPublic,
    required this.signedPrekeySignature,
    this.oneTimePrekeyId,
    this.oneTimePrekey,
  });
}
```

### SessionState

```dart
class SessionState {
  final String sessionId;            // Unique session identifier
  final int registrationId;          // Registration ID
  final int deviceId;                 // Device ID
  final List<int> dhSelfPrivate;      // Our DH private key
  final List<int> dhSelfPublic;       // Our DH public key
  final List<int>? dhRemote;          // Remote DH public key
  final List<int> rootKey;            // Root key for key derivation
  final List<int>? chainKeySend;      // Sending chain key
  final List<int>? chainKeyRecv;      // Receiving chain key
  final int nSend;                    // Send counter
  final int nRecv;                    // Receive counter
  final int pn;                       // Previous chain length
  final int maxSkip;                  // Maximum skip count

  SessionState({
    required this.sessionId,
    required this.registrationId,
    required this.deviceId,
    required this.dhSelfPrivate,
    required this.dhSelfPublic,
    this.dhRemote,
    required this.rootKey,
    this.chainKeySend,
    this.chainKeyRecv,
    required this.nSend,
    required this.nRecv,
    required this.pn,
    required this.maxSkip,
  });
}
```

### GroupMember

```dart
class GroupMember {
  final String memberId;              // Unique member identifier
  final String name;                  // Display name
  final List<int> identityKey;        // Member's identity key
  final List<int> identityKeyEd;      // Member's Ed25519 key
  final DateTime joinedAt;            // Join timestamp

  GroupMember({
    required this.memberId,
    required this.name,
    required this.identityKey,
    required this.identityKeyEd,
    required this.joinedAt,
  });
}
```

### GroupSession

```dart
class GroupSession {
  final String groupId;               // Unique group identifier
  final String name;                  // Group name
  final List<GroupMember> members;    // Group members
  final Map<String, SenderKey> senderKeys; // Sender keys by member
  final DateTime createdAt;           // Creation timestamp
  final DateTime updatedAt;           // Last update timestamp
  final String creatorId;             // Creator's user ID

  GroupSession({
    required this.groupId,
    required this.name,
    required this.members,
    required this.senderKeys,
    required this.createdAt,
    required this.updatedAt,
    required this.creatorId,
  });
}
```

### Message

```dart
enum MessageType { text, image, file, system }
enum MessageStatus { sending, sent, delivered, read, failed }

class Message {
  final String messageId;             // Unique message identifier
  final String? groupId;              // Group ID (for group messages)
  final String? senderId;             // Sender's user ID
  final String? recipientId;          // Recipient's user ID (for direct messages)
  final String content;               // Message content
  final MessageType type;             // Message type
  final MessageStatus status;         // Message status
  final DateTime timestamp;           // Message timestamp
  final Map<String, dynamic>? metadata; // Additional metadata

  Message({
    required this.messageId,
    this.groupId,
    this.senderId,
    this.recipientId,
    required this.content,
    required this.type,
    required this.status,
    required this.timestamp,
    this.metadata,
  });
}
```

## 🔌 Service APIs

### SignalProtocolService

Main service for Signal Protocol operations.

```dart
class SignalProtocolService extends ChangeNotifier {
  // Initialization
  Future<void> initialize();
  
  // Identity management
  Future<IdentityKeyPair> generateIdentityKeypair();
  Future<PreKeyBundle> generatePrekeyBundle(IdentityKeyPair identity);
  
  // Session management
  Future<SessionState> establishSession(
    IdentityKeyPair aliceIdentity,
    PreKeyBundle bobBundle,
  );
  
  // Message encryption/decryption
  Future<Map<String, dynamic>> encryptMessage(String sessionId, String plaintext);
  Future<String> decryptMessage(String sessionId, Map<String, dynamic> encryptedMessage);
  
  // Session storage
  Future<void> storeSession(String sessionId, SessionState session);
  SessionState? getSession(String sessionId);
  Future<void> deleteSession(String sessionId);
  
  // Properties
  bool get isInitialized;
  IdentityKeyPair? get currentIdentity;
  List<String> get sessionIds;
}
```

### GroupManager

Service for managing group conversations.

```dart
class GroupManager extends ChangeNotifier {
  // Group creation
  Future<GroupSession> createGroup(
    String name,
    String creatorId,
    List<GroupMember> initialMembers,
  );
  
  // Member management
  Future<void> addMember(String groupId, GroupMember member);
  Future<void> removeMember(String groupId, String memberId);
  
  // Group operations
  Future<void> updateGroupName(String groupId, String newName);
  Future<void> leaveGroup(String groupId, String memberId);
  Future<void> deleteGroup(String groupId);
  
  // Getters
  GroupSession? getGroup(String groupId);
  List<GroupSession> get groups;
  List<String> get groupIds;
}
```

### MessageService

Service for handling encrypted messages.

```dart
class MessageService extends ChangeNotifier {
  // User management
  void setCurrentUser(String userId);
  String? get currentUserId;
  
  // Message sending
  Future<Message> sendGroupMessage(String groupId, String content, MessageType type);
  Future<Message> sendDirectMessage(String recipientId, String content, MessageType type);
  
  // Message receiving
  Future<void> receiveGroupMessage(GroupMessage groupMessage);
  Future<void> receiveDirectMessage(Map<String, dynamic> encryptedMessage);
  
  // Message management
  Future<void> markAsRead(String messageId);
  Future<void> deleteMessage(String messageId);
  Future<void> clearConversation(String conversationId);
  
  // Message retrieval
  List<Message> getMessages(String conversationId);
  List<Message> getGroupMessages(String groupId);
  List<Message> getDirectMessages(String conversationId);
  
  // Properties
  List<String> get conversationIds;
}
```

## ❌ Error Codes

### FFI Error Codes

| Code | Description |
|------|-------------|
| `SUCCESS` | Operation completed successfully |
| `ERROR_INVALID_INPUT` | Invalid input parameters |
| `ERROR_CRYPTO_FAILURE` | Cryptographic operation failed |
| `ERROR_SESSION_NOT_FOUND` | Session not found |
| `ERROR_GROUP_NOT_FOUND` | Group not found |
| `ERROR_MEMBER_NOT_FOUND` | Member not found |
| `ERROR_INSUFFICIENT_PERMISSIONS` | Insufficient permissions |
| `ERROR_STORAGE_FAILURE` | Storage operation failed |
| `ERROR_MEMORY_ALLOCATION` | Memory allocation failed |
| `ERROR_SERIALIZATION` | JSON serialization/deserialization failed |

### Exception Types

```dart
class SignalProtocolException implements Exception {
  final String message;
  final String? code;
  
  SignalProtocolException(this.message, [this.code]);
  
  @override
  String toString() => 'SignalProtocolException: $message${code != null ? ' ($code)' : ''}';
}

class FFIException extends SignalProtocolException {
  FFIException(String message, [String? code]) : super(message, code);
}

class CryptoException extends SignalProtocolException {
  CryptoException(String message, [String? code]) : super(message, code);
}

class SessionException extends SignalProtocolException {
  SessionException(String message, [String? code]) : super(message, code);
}
```

## 📝 Type Definitions

### FFI Type Mappings

| Rust Type | Dart Type | Description |
|-----------|-----------|-------------|
| `*const c_char` | `Pointer<Utf8>` | UTF-8 string pointer |
| `*mut c_char` | `Pointer<Utf8>` | Mutable UTF-8 string pointer |
| `u32` | `int` | 32-bit unsigned integer |
| `u64` | `int` | 64-bit unsigned integer |
| `bool` | `bool` | Boolean value |

### JSON Schema Definitions

#### Identity Keypair Schema
```json
{
  "type": "object",
  "properties": {
    "dh_public": {"type": "array", "items": {"type": "integer"}, "minItems": 32, "maxItems": 32},
    "dh_private": {"type": "array", "items": {"type": "integer"}, "minItems": 32, "maxItems": 32},
    "ed_public": {"type": "array", "items": {"type": "integer"}, "minItems": 32, "maxItems": 32},
    "ed_private": {"type": "array", "items": {"type": "integer"}, "minItems": 32, "maxItems": 32}
  },
  "required": ["dh_public", "dh_private", "ed_public", "ed_private"]
}
```

#### Session State Schema
```json
{
  "type": "object",
  "properties": {
    "session_id": {"type": "string"},
    "registration_id": {"type": "integer"},
    "device_id": {"type": "integer"},
    "dh_self_private": {"type": "array", "items": {"type": "integer"}},
    "dh_self_public": {"type": "array", "items": {"type": "integer"}},
    "root_key": {"type": "array", "items": {"type": "integer"}},
    "n_send": {"type": "integer"},
    "n_recv": {"type": "integer"},
    "max_skip": {"type": "integer"}
  },
  "required": ["session_id", "registration_id", "device_id", "root_key", "n_send", "n_recv", "max_skip"]
}
```

---

This API reference provides complete documentation for integrating the Signal Protocol Dart bindings into Flutter applications. For implementation examples, see the [Dart Binding Guide](DART_BINDING_GUIDE.md).