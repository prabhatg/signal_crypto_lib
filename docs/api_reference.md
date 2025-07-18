# Signal Crypto Library - Complete API Reference 🔧

## Table of Contents

1. [Core Types](#core-types)
2. [Identity Management](#identity-management)
3. [Prekey Management](#prekey-management)
4. [Protocol Functions](#protocol-functions)
5. [Session Management](#session-management)
6. [Group Messaging](#group-messaging)
7. [Advanced Features](#advanced-features)
8. [Enterprise Features](#enterprise-features)
9. [AI/ML Integration](#aiml-integration)
10. [Post-Quantum Cryptography](#post-quantum-cryptography)
11. [Next-Generation Technologies](#next-generation-technologies)
12. [Performance Optimization](#performance-optimization)
13. [Error Types](#error-types)
14. [FFI Bindings](#ffi-bindings)

## Core Types

### `IdentityKeyPair`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct IdentityKeyPair {
    pub dh_public: Vec<u8>,    // X25519 public key (32 bytes)
    pub dh_private: Vec<u8>,   // X25519 private key (32 bytes)
    pub ed_public: Vec<u8>,    // Ed25519 public key (32 bytes)
    pub ed_private: Vec<u8>,   // Ed25519 private key (32 bytes)
}
```

**Description:** Contains both X25519 (for key agreement) and Ed25519 (for signatures) key pairs.

**Security:** Automatically zeroized on drop to prevent key material from remaining in memory.

### `PreKeyBundle`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key: Vec<u8>,          // X25519 public key
    pub identity_key_ed: Vec<u8>,       // Ed25519 public key
    pub signed_prekey_id: u32,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey: Option<Vec<u8>>,
}
```

**Description:** Bundle of public keys used for asynchronous session establishment.

### `SessionState`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub registration_id: u32,
    pub device_id: u32,
    
    // DH Ratchet State
    pub dh_self_private: Vec<u8>,
    pub dh_self_public: Vec<u8>,
    pub dh_remote: Option<Vec<u8>>,
    
    // Root and Chain Keys
    pub root_key: Vec<u8>,
    pub chain_key_send: Option<Vec<u8>>,
    pub chain_key_recv: Option<Vec<u8>>,
    
    // Header Keys
    pub header_key_send: Option<Vec<u8>>,
    pub header_key_recv: Option<Vec<u8>>,
    pub next_header_key_send: Option<Vec<u8>>,
    pub next_header_key_recv: Option<Vec<u8>>,
    
    // Message Counters
    pub n_send: u32,
    pub n_recv: u32,
    pub pn: u32,
    
    // Skipped Message Keys
    pub mk_skipped: HashMap<(Vec<u8>, u32), Vec<u8>>,
    pub max_skip: u32,
}
```

**Description:** Complete state for a Double Ratchet session.

## Identity Management

### `generate_identity_keypair()`

```rust
pub fn generate_identity_keypair() -> IdentityKeyPair
```

**Description:** Generates a new identity key pair with both X25519 and Ed25519 keys.

**Returns:** `IdentityKeyPair` containing all necessary keys.

**Example:**
```rust
let identity = generate_identity_keypair();
assert_eq!(identity.dh_public.len(), 32);
assert_eq!(identity.ed_public.len(), 32);
```

**Security Considerations:**
- Uses cryptographically secure random number generation
- Keys are automatically zeroized when dropped
- Should be stored securely (preferably in HSM for production)

## Prekey Management

### `generate_signed_prekey()`

```rust
pub fn generate_signed_prekey(
    identity: &IdentityKeyPair,
    key_id: u32
) -> SignedPreKey
```

**Description:** Generates a signed prekey for asynchronous session establishment.

**Parameters:**
- `identity`: Identity key pair used for signing
- `key_id`: Unique identifier for this prekey

**Returns:** `SignedPreKey` with signature from identity key.

**Example:**
```rust
let identity = generate_identity_keypair();
let signed_prekey = generate_signed_prekey(&identity, 1);
```

### `generate_one_time_prekey()`

```rust
pub fn generate_one_time_prekey(key_id: u32) -> OneTimePreKey
```

**Description:** Generates a one-time prekey for enhanced forward secrecy.

**Parameters:**
- `key_id`: Unique identifier for this prekey

**Returns:** `OneTimePreKey` for single use.

**Example:**
```rust
let one_time_prekey = generate_one_time_prekey(100);
```

## Protocol Functions

### X3DH Protocol

#### `x3dh_alice_init()`

```rust
pub fn x3dh_alice_init(
    alice_identity: &IdentityKeyPair,
    alice_registration_id: u32,
    bob_bundle: &PreKeyBundle,
) -> Result<(X3DHInitialMessage, SessionState), X3DHError>
```

**Description:** Alice's side of X3DH key agreement protocol.

**Parameters:**
- `alice_identity`: Alice's identity key pair
- `alice_registration_id`: Alice's registration ID
- `bob_bundle`: Bob's prekey bundle

**Returns:** Tuple of initial message and session state.

**Example:**
```rust
let (initial_message, alice_session) = x3dh_alice_init(
    &alice_identity,
    5678,
    &bob_bundle,
)?;
```

#### `x3dh_bob_init()`

```rust
pub fn x3dh_bob_init(
    bob_identity: &IdentityKeyPair,
    bob_registration_id: u32,
    bob_signed_prekey: &SignedPreKey,
    bob_one_time_prekey: Option<&OneTimePreKey>,
    initial_message: &X3DHInitialMessage,
) -> Result<SessionState, X3DHError>
```

**Description:** Bob's side of X3DH key agreement protocol.

**Parameters:**
- `bob_identity`: Bob's identity key pair
- `bob_registration_id`: Bob's registration ID
- `bob_signed_prekey`: Bob's signed prekey
- `bob_one_time_prekey`: Optional one-time prekey
- `initial_message`: Alice's initial message

**Returns:** Bob's session state.

### Double Ratchet Protocol

#### `encrypt_message()`

```rust
pub fn encrypt_message(
    session: &mut SessionState,
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<DoubleRatchetMessage, DoubleRatchetError>
```

**Description:** Encrypts a message using the Double Ratchet algorithm.

**Parameters:**
- `session`: Mutable reference to session state
- `plaintext`: Message to encrypt
- `associated_data`: Optional additional authenticated data

**Returns:** Encrypted message with header.

#### `decrypt_message()`

```rust
pub fn decrypt_message(
    session: &mut SessionState,
    message: &DoubleRatchetMessage,
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, DoubleRatchetError>
```

**Description:** Decrypts a message using the Double Ratchet algorithm.

**Parameters:**
- `session`: Mutable reference to session state
- `message`: Encrypted message to decrypt
- `associated_data`: Optional additional authenticated data

**Returns:** Decrypted plaintext.

## Session Management

### `SessionManager`

```rust
pub struct SessionManager {
    // Private fields
}

impl SessionManager {
    pub fn new(
        db_path: Option<PathBuf>,
        storage_key: [u8; 32],
    ) -> Result<Self, SessionManagerError>;
    
    pub fn store_session(
        &self,
        session: &SessionState,
        remote_identity: &str,
    ) -> Result<(), SessionManagerError>;
    
    pub fn load_session(
        &self,
        remote_identity: &str,
    ) -> Result<Option<SessionState>, SessionManagerError>;
    
    pub fn delete_session(
        &self,
        remote_identity: &str,
    ) -> Result<(), SessionManagerError>;
    
    pub fn cleanup_expired_sessions(&self) -> Result<(), SessionManagerError>;
}
```

**Description:** Manages persistent storage and lifecycle of sessions.

**Example:**
```rust
let storage_key = [0u8; 32]; // Use secure key in production
let session_manager = SessionManager::new(
    Some(PathBuf::from("sessions.db")),
    storage_key,
)?;

session_manager.store_session(&session, "alice@example.com")?;
let loaded_session = session_manager.load_session("alice@example.com")?;
```

## Group Messaging

### `GroupSessionState`

```rust
pub struct GroupSessionState {
    pub group_id: String,
    pub own_sender_id: String,
    pub sender_chains: HashMap<String, SenderChainState>,
    pub skipped_message_keys: HashMap<(String, u32), Vec<u8>>,
    pub max_skip: u32,
}

impl GroupSessionState {
    pub fn new(group_id: &str, own_sender_id: &str) -> Self;
    
    pub fn initialize_own_chain(&mut self) -> Result<SenderKeyDistributionMessage, SesameError>;
    
    pub fn add_sender(
        &mut self,
        sender_id: &str,
        distribution_msg: &SenderKeyDistributionMessage,
    ) -> Result<(), SesameError>;
    
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<SesameMessage, SesameError>;
    
    pub fn decrypt_message(
        &mut self,
        sender_id: &str,
        message: &SesameMessage,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, SesameError>;
}
```

**Description:** Manages group messaging sessions with sender key distribution.

**Example:**
```rust
let mut group_session = GroupSessionState::new("group_id", "alice");
let distribution_message = group_session.initialize_own_chain()?;

// Add other members
group_session.add_sender("bob", &bob_distribution_message)?;

// Send group message
let encrypted = group_session.encrypt_message(b"Hello group!", None)?;
```

## Advanced Features

### `MessageBatcher`

```rust
pub struct MessageBatcher {
    // Private fields
}

impl MessageBatcher {
    pub fn new(config: BatchConfig) -> Self;
    
    pub fn add_message(&mut self, message: Message) -> Result<(), AdvancedError>;
    
    pub fn try_create_batch(&mut self) -> Result<Option<MessageBatch>, AdvancedError>;
}
```

### `ProtocolVersion`

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolVersion {
    V1_0,
    V2_0,
    V2_1,
    V3_0,
}

impl ProtocolVersion {
    pub fn is_compatible_with(&self, other: &ProtocolVersion) -> bool;
    pub fn latest() -> Self;
}
```

### `AdvancedGroupSession`

```rust
pub struct AdvancedGroupSession {
    // Private fields
}

impl AdvancedGroupSession {
    pub fn new(group_id: &str, config: GroupConfig) -> Self;
    
    pub fn add_member(&mut self, member: GroupMember) -> Result<(), AdvancedError>;
    
    pub fn send_message_with_tracking(
        &mut self,
        message: &str,
        priority: MessagePriority,
    ) -> Result<MessageId, AdvancedError>;
    
    pub fn get_delivery_status(&self, message_id: &MessageId) -> Result<DeliveryStatus, AdvancedError>;
}
```

## Enterprise Features

### `EnterpriseAuthManager`

```rust
pub struct EnterpriseAuthManager {
    // Private fields
}

impl EnterpriseAuthManager {
    pub fn new(config: EnterpriseAuthConfig) -> Result<Self, EnterpriseError>;
    
    pub fn authenticate(
        &self,
        user_id: &str,
        auth_method: AuthMethod,
        credentials: &str,
    ) -> Result<AuthSession, EnterpriseError>;
    
    pub fn assign_role(&self, user_id: &str, role: &Role) -> Result<(), EnterpriseError>;
    
    pub fn check_permission(
        &self,
        user_id: &str,
        permission: &Permission,
    ) -> Result<bool, EnterpriseError>;
}
```

### `AuditLogger`

```rust
pub struct AuditLogger {
    // Private fields
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> Result<Self, AuditError>;
    
    pub fn log_event(&self, event: AuditEvent) -> Result<(), AuditError>;
    
    pub fn query_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>, AuditError>;
}
```

## AI/ML Integration

### `AIMLEngine`

```rust
pub struct AIMLEngine {
    // Private fields
}

impl AIMLEngine {
    pub fn new(config: AIMLConfig) -> Result<Self, AIMLError>;
    
    pub fn analyze_behavior(&self, activity: &UserActivity) -> Result<BehaviorProfile, AIMLError>;
    
    pub fn analyze_message(&self, message: &str) -> Result<ThreatAssessment, AIMLError>;
    
    pub fn get_threat_detector(&self) -> &ThreatDetector;
    
    pub fn get_federated_learner(&self) -> &FederatedLearner;
}
```

### `ThreatDetector`

```rust
pub struct ThreatDetector {
    // Private fields
}

impl ThreatDetector {
    pub fn analyze_message(&self, message_data: &MessageData) -> Result<ThreatAssessment, AIMLError>;
    
    pub fn update_model(&mut self, training_data: &TrainingData) -> Result<(), AIMLError>;
}
```

## Post-Quantum Cryptography

### `PQAlgorithm`

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum PQAlgorithm {
    // NIST Key Encapsulation Mechanisms
    Kyber512,
    Kyber768,
    Kyber1024,
    
    // NIST Digital Signatures
    Dilithium2,
    Dilithium3,
    Dilithium5,
    
    // Alternative Signatures
    Falcon512,
    Falcon1024,
    SPHINCS128s,
    SPHINCS192s,
    SPHINCS256s,
    
    // Additional KEMs
    BIKE,
    ClassicMcEliece,
    HQC,
}
```

### `HybridKeyPair`

```rust
pub struct HybridKeyPair {
    // Private fields
}

impl HybridKeyPair {
    pub fn generate(
        pq_algorithm: PQAlgorithm,
        hybrid_mode: HybridMode,
    ) -> Result<Self, PQError>;
    
    pub fn get_classical_public(&self) -> &[u8];
    pub fn get_pq_public(&self) -> &[u8];
}
```

### `CryptoMigrationManager`

```rust
pub struct CryptoMigrationManager {
    // Private fields
}

impl CryptoMigrationManager {
    pub fn new(config: MigrationConfig) -> Result<Self, PQError>;
    
    pub fn should_migrate(&self, session: &SessionState) -> Result<bool, PQError>;
    
    pub fn migrate_session(&self, session: &SessionState) -> Result<SessionState, PQError>;
}
```

## Next-Generation Technologies

### `HomomorphicEngine`

```rust
pub struct HomomorphicEngine {
    // Private fields
}

impl HomomorphicEngine {
    pub fn new(config: HomomorphicConfig) -> Result<Self, NextGenError>;
    
    pub fn encrypt(&self, data: &[u8]) -> Result<EncryptedData, NextGenError>;
    
    pub fn compute(
        &self,
        encrypted_data: &EncryptedData,
        circuit: &ComputationCircuit,
    ) -> Result<EncryptedResult, NextGenError>;
    
    pub fn decrypt(&self, encrypted_result: &EncryptedResult) -> Result<Vec<u8>, NextGenError>;
}
```

### `ZKProofSystem`

```rust
pub struct ZKProofSystem {
    // Private fields
}

impl ZKProofSystem {
    pub fn new(config: ZKConfig) -> Result<Self, NextGenError>;
    
    pub fn generate_proof(
        &self,
        witness: &SecretWitness,
        public_inputs: &PublicInputs,
        circuit: &VerificationCircuit,
    ) -> Result<ZKProof, NextGenError>;
    
    pub fn verify_proof(
        &self,
        proof: &ZKProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, NextGenError>;
}
```

### `BlockchainIntegration`

```rust
pub struct BlockchainIntegration {
    // Private fields
}

impl BlockchainIntegration {
    pub fn new(config: BlockchainConfig) -> Result<Self, NextGenError>;
    
    pub fn store_identity(&self, identity_data: &IdentityData) -> Result<Hash, NextGenError>;
    
    pub fn verify_identity(&self, identity_hash: &Hash) -> Result<VerifiedIdentity, NextGenError>;
}
```

## Performance Optimization

### `LruCache`

```rust
pub struct LruCache<K, V> {
    // Private fields
}

impl<K, V> LruCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    pub fn new(capacity: usize) -> Self;
    
    pub fn get(&mut self, key: &K) -> Option<&V>;
    
    pub fn put(&mut self, key: K, value: V) -> Option<V>;
    
    pub fn remove(&mut self, key: &K) -> Option<V>;
    
    pub fn clear(&mut self);
}
```

### `PerformanceMonitor`

```rust
pub struct PerformanceMonitor {
    // Private fields
}

impl PerformanceMonitor {
    pub fn new() -> Self;
    
    pub fn start_timer(&self, operation: &str) -> Timer;
    
    pub fn get_metrics(&self) -> Result<PerformanceMetrics, PerformanceError>;
    
    pub fn reset_metrics(&mut self);
}
```

### `ObjectPool`

```rust
pub struct ObjectPool<T> {
    // Private fields
}

impl<T> ObjectPool<T>
where
    T: Send + 'static,
{
    pub fn new<F>(config: PoolConfig<T, F>) -> Result<Self, PerformanceError>
    where
        F: Fn() -> T + Send + Sync + 'static;
    
    pub fn get(&self) -> Result<PooledObject<T>, PerformanceError>;
    
    pub fn put(&self, object: T) -> Result<(), PerformanceError>;
}
```

## Error Types

### `SignalError`

```rust
#[derive(Debug, Clone)]
pub enum SignalError {
    CryptographicError(String),
    InvalidInput(String),
    AuthenticationFailed(String),
    SessionError(String),
    NetworkError(String),
    DatabaseError(String),
    SerializationError(String),
    ProtocolError(String),
    KeyError(String),
    DecryptionError(String),
    EncryptionError(String),
    InvalidMessage(String),
    RateLimitExceeded(String),
    PermissionDenied(String),
    NotFound(String),
    InternalError(String),
}
```

### `X3DHError`

```rust
#[derive(Debug)]
pub enum X3DHError {
    InvalidKeySize,
    InvalidSignature,
    MissingOneTimePreKey,
    InvalidPreKeyBundle,
    CryptoError(String),
}
```

### `DoubleRatchetError`

```rust
#[derive(Debug, Clone)]
pub enum DoubleRatchetError {
    InvalidKeySize,
    EncryptionFailed,
    DecryptionFailed,
    InvalidHeader,
    InvalidMessageNumber,
    TooManySkippedMessages,
    CryptoError(String),
}
```

### `SessionManagerError`

```rust
#[derive(Debug, Clone)]
pub enum SessionManagerError {
    SessionNotFound,
    StorageError(String),
    SerializationError(String),
    EncryptionError(String),
    DatabaseError(String),
}
```

## FFI Bindings

### C-Compatible Functions

```rust
// Identity key generation
#[no_mangle]
pub extern "C" fn generate_identity_keys(
    dh_public: *mut *mut u8,
    dh_private: *mut *mut u8,
    ed_public: *mut *mut u8,
    ed_private: *mut *mut u8,
) -> c_int;

// Memory management
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char);

#[no_mangle]
pub extern "C" fn free_bytes(ptr: *mut u8, len: usize);

// Session management
#[no_mangle]
pub extern "C" fn session_manager_new(
    db_path: *const c_char,
    storage_key: *const u8,
) -> *mut SessionManager;

#[no_mangle]
pub extern "C" fn session_manager_free(manager: *mut SessionManager);

// Error codes
pub const SUCCESS: c_int = 0;
pub const ERROR_INVALID_INPUT: c_int = -1;
pub const ERROR_ENCRYPTION_FAILED: c_int = -2;
pub const ERROR_DECRYPTION_FAILED: c_int = -3;
pub const ERROR_SESSION_NOT_FOUND: c_int = -4;
pub const ERROR_STORAGE_FAILED: c_int = -5;
pub const ERROR_SERIALIZATION_FAILED: c_int = -6;
```

### Dart/Flutter Integration

```dart
// Example Dart bindings
class SignalCrypto {
  static final DynamicLibrary _lib = _loadLibrary();
  
  static Map<String, dynamic> generateIdentityKeypair() {
    final resultPtr = _generateIdentityKeypair();
    final jsonStr = resultPtr.toDartString();
    _freeString(resultPtr);
    
    if (jsonStr.startsWith('ERROR:')) {
      throw Exception(jsonStr);
    }
    
    return json.decode(jsonStr);
  }
  
  // Additional methods...
}
```

## Constants

### Protocol Constants

```rust
// Key sizes
pub const DH_KEY_SIZE: usize = 32;
pub const ED_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const SHARED_SECRET_SIZE: usize = 32;

// HKDF info strings
pub const MESSAGE_KEY_INFO: &[u8] = b"MessageKey";
pub const CHAIN_KEY_INFO: &[u8] = b"ChainKey";
pub const ROOT_KEY_INFO: &[u8] = b"RootKey";
pub const HEADER_KEY_INFO: &[u8] = b"HeaderKey";

// Protocol limits
pub const MAX_SKIP_MESSAGES: u32 = 1000;
pub const MAX_SESSION_AGE_DAYS: u32 = 30;
pub const MAX_GROUP_SIZE: usize = 10000;
```

---

This API reference provides comprehensive coverage of all public interfaces in the Signal Crypto Library. For implementation details and examples, refer to the [Developer Guide](developer_guide.md) and [Developer Guide Part 2](developer_guide_part2.md).