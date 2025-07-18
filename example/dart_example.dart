import 'dart:ffi';
import 'dart:convert';
import 'dart:io';
import 'package:ffi/ffi.dart';

// Signal Crypto Library FFI Bindings Example
// This demonstrates how to use the Signal Protocol library from Dart/Flutter

// Load the dynamic library based on platform
DynamicLibrary loadSignalCryptoLibrary() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libsignal_crypto_lib.so');
  } else if (Platform.isIOS) {
    return DynamicLibrary.process();
  } else if (Platform.isMacOS) {
    return DynamicLibrary.open('libsignal_crypto_lib.dylib');
  } else if (Platform.isWindows) {
    return DynamicLibrary.open('signal_crypto_lib.dll');
  } else if (Platform.isLinux) {
    return DynamicLibrary.open('libsignal_crypto_lib.so');
  } else {
    throw UnsupportedError('Platform not supported');
  }
}

// FFI function signatures
typedef GenerateIdentityKeypairC = Pointer<Utf8> Function();
typedef GenerateIdentityKeypairDart = Pointer<Utf8> Function();

typedef GeneratePrekeyBundleC = Pointer<Utf8> Function(Pointer<Utf8>);
typedef GeneratePrekeyBundleDart = Pointer<Utf8> Function(Pointer<Utf8>);

typedef FreeStringC = Void Function(Pointer<Utf8>);
typedef FreeStringDart = void Function(Pointer<Utf8>);

class SignalCrypto {
  late final DynamicLibrary _lib;
  late final GenerateIdentityKeypairDart _generateIdentityKeypair;
  late final GeneratePrekeyBundleDart _generatePrekeyBundle;
  late final FreeStringDart _freeString;

  SignalCrypto() {
    _lib = loadSignalCryptoLibrary();
    
    _generateIdentityKeypair = _lib
        .lookupFunction<GenerateIdentityKeypairC, GenerateIdentityKeypairDart>(
            'ffi_generate_identity_keypair_json');
    
    _generatePrekeyBundle = _lib
        .lookupFunction<GeneratePrekeyBundleC, GeneratePrekeyBundleDart>(
            'ffi_generate_prekey_bundle_json');
    
    _freeString = _lib
        .lookupFunction<FreeStringC, FreeStringDart>('ffi_free_string');
  }

  Map<String, dynamic> generateIdentityKeypair() {
    final resultPtr = _generateIdentityKeypair();
    final jsonStr = resultPtr.toDartString();
    _freeString(resultPtr);
    
    if (jsonStr.startsWith('ERROR:')) {
      throw Exception(jsonStr);
    }
    
    return json.decode(jsonStr);
  }
  
  Map<String, dynamic> generatePrekeyBundle(Map<String, dynamic> identity) {
    final identityJson = json.encode(identity);
    final identityPtr = identityJson.toNativeUtf8();
    
    final resultPtr = _generatePrekeyBundle(identityPtr);
    final jsonStr = resultPtr.toDartString();
    
    malloc.free(identityPtr);
    _freeString(resultPtr);
    
    if (jsonStr.startsWith('ERROR:')) {
      throw Exception(jsonStr);
    }
    
    return json.decode(jsonStr);
  }
}

// Example usage
void main() {
  print('Signal Crypto Library - Dart Example\n');
  
  try {
    final crypto = SignalCrypto();
    
    // Step 1: Generate identity keypair
    print('1. Generating identity keypair...');
    final identity = crypto.generateIdentityKeypair();
    print('   ✓ Generated identity with:');
    print('     - DH Public Key: ${identity['dh_public'].length} bytes');
    print('     - Ed25519 Public Key: ${identity['ed_public'].length} bytes');
    
    // Step 2: Generate prekey bundle
    print('\n2. Generating prekey bundle...');
    final prekeyBundle = crypto.generatePrekeyBundle(identity);
    print('   ✓ Generated prekey bundle with:');
    print('     - Identity Key: ${prekeyBundle['identity_key'].length} bytes');
    print('     - Signed Prekey ID: ${prekeyBundle['signed_prekey']['key_id']}');
    print('     - Signature: ${prekeyBundle['signed_prekey']['signature'].length} bytes');
    
    if (prekeyBundle['one_time_prekey'] != null) {
      print('     - One-time Prekey ID: ${prekeyBundle['one_time_prekey']['key_id']}');
    }
    
    print('\n3. Example JSON output:');
    print('   Identity: ${json.encode(identity).substring(0, 100)}...');
    print('   Bundle: ${json.encode(prekeyBundle).substring(0, 100)}...');
    
    print('\n✅ Signal Protocol initialization successful!');
    print('   You can now use these keys to establish secure sessions.');
    
  } catch (e) {
    print('❌ Error: $e');
  }
}

// Example of a complete Signal Protocol session
class SignalSession {
  final Map<String, dynamic> identity;
  final Map<String, dynamic> prekeyBundle;
  
  SignalSession({required this.identity, required this.prekeyBundle});
  
  // In a real implementation, you would:
  // 1. Publish your prekey bundle to a server
  // 2. Fetch other users' prekey bundles
  // 3. Establish sessions using X3DH
  // 4. Exchange messages using Double Ratchet
  
  void publishToServer() {
    // POST prekeyBundle to your server
    print('Publishing prekey bundle to server...');
  }
  
  Future<Map<String, dynamic>> fetchUserBundle(String userId) async {
    // GET /users/{userId}/prekey-bundle from your server
    print('Fetching prekey bundle for user: $userId');
    return {};
  }
}