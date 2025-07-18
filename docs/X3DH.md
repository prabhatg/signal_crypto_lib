# 📚 Signal Protocol – X3DH + PreKey Implementation

This module implements key elements of the [Signal Protocol](https://signal.org/docs/specifications/x3dh/) based on the **X3DH key agreement**, PreKey messages, and header encryption with MAC verification.

---

## ✨ Features

| Feature | Status |
|--------|--------|
| ✅ X3DH key agreement (identity, signed prekey, one-time prekey) | ✔️ Complete |
| ✅ PreKey bundle and PreKeyMessage format | ✔️ Complete |
| ✅ AES-GCM + HKDF for message encryption | ✔️ Complete |
| ✅ Header encryption with SHA256 MAC | ✔️ Complete |
| ✅ PreKey expiration and device IDs | ✔️ Complete |
| ✅ Dart FFI bindings | ✔️ Complete |
| ✅ Secure memory zeroing for keys | ✔️ Complete |
| ✅ Replay protection via MAC check | ✔️ Complete |
| ✅ Comprehensive unit and integration tests | ✔️ Complete |

---

## 🔐 Key Concepts

### PreKeyBundle
Published by a device to allow asynchronous session initiation. Includes:

- `identity_pub`: Ed25519 identity key
- `signed_prekey_pub`: X25519 pubkey signed by identity key
- `signed_prekey_sig`: Signature over `signed_prekey_pub`
- `one_time_prekey_pub`: Optional X25519 one-time key
- `expires_at`: Optional UNIX expiry time
- `device_id`: Optional device identifier

### PreKeyMessage
Sent by the initiator to establish a session:

- `identity_pub`: Sender's Ed25519 public key
- `ephemeral_pub`: Sender’s ephemeral X25519 public key
- `signed_prekey_pub`, `one_time_prekey_pub`: Copied from recipient bundle
- `sig`: Signature over `ephemeral_pub` using sender identity key
- `ciphertext`: Encrypted header and payload using AES-256-GCM

### EncryptedHeader
Serialized + MAC'd using SHA256, includes:

- `nonce`: 96-bit nonce used for AES-GCM
- `version`: Protocol version
- `ratchet_pub`: Sender ratchet pubkey

---

## 🛠️ Dart FFI Usage

### Functions

```c
char* ffi_generate_prekey_bundle_json();
char* ffi_decrypt_prekey_message_json(const char* msg_json, const uint8_t* id_secret, const uint8_t* spk_secret);
void ffi_free_string(char* ptr);
```

### Dart Example

```dart
final dylib = DynamicLibrary.open("libsignal_crypto.so");
final generate = dylib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('ffi_generate_prekey_bundle_json');
final freeStr = dylib.lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>('ffi_free_string');

final result = generate();
final dartStr = result.toDartString();
freeStr(result);
```

---

## 🧪 Running Tests

Run all tests with:

```bash
cargo test
```

Included test coverage:
- Message integrity and roundtrip encryption
- Signature verification failures
- Expired PreKeyBundles
- JSON + FFI roundtrip tests

---

## 🔒 Security Practices

- `zeroize` ensures secrets are wiped from memory
- All FFI memory returned must be freed via `ffi_free_string`
- Invalid UTF-8, malformed input, and bad key sizes return `"ERROR: ..."` to avoid crashes