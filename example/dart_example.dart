import 'dart:ffi';
import 'dart:convert';
import 'dart:io';

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

// FFI function signatures using basic C types
typedef GenerateIdentityKeypairC = Pointer<Char> Function();
typedef GenerateIdentityKeypairDart = Pointer<Char> Function();

typedef GeneratePrekeyBundleC = Pointer<Char> Function(Pointer<Char>);
typedef GeneratePrekeyBundleDart = Pointer<Char> Function(Pointer<Char>);

typedef FreeStringC = Void Function(Pointer<Char>);
typedef FreeStringDart = void Function(Pointer<Char>);

// Basic memory allocation functions
typedef MallocC = Pointer<Void> Function(IntPtr size);
typedef MallocDart = Pointer<Void> Function(int size);

typedef FreeC = Void Function(Pointer<Void> ptr);
typedef FreeDart = void Function(Pointer<Void> ptr);

// Simple memory allocator using system malloc/free
class SimpleAllocator {
  static MallocDart? _malloc;
  static FreeDart? _free;
  static bool _initialized = false;

  static void _init() {
    if (_initialized) return;
    
    try {
      if (Platform.isWindows) {
        final lib = DynamicLibrary.open('msvcrt.dll');
        _malloc = lib.lookupFunction<MallocC, MallocDart>('malloc');
        _free = lib.lookupFunction<FreeC, FreeDart>('free');
      } else {
        final lib = DynamicLibrary.process();
        _malloc = lib.lookupFunction<MallocC, MallocDart>('malloc');
        _free = lib.lookupFunction<FreeC, FreeDart>('free');
      }
      _initialized = true;
    } catch (e) {
      // Fallback: we'll handle this in the methods
      _initialized = false;
    }
  }

  static Pointer<Char> allocateChar(int count) {
    _init();
    if (!_initialized || _malloc == null) {
      throw UnsupportedError('Memory allocation not available');
    }
    return _malloc!(count).cast<Char>();
  }

  static void free(Pointer ptr) {
    _init();
    if (_initialized && _free != null && ptr != nullptr) {
      _free!(ptr.cast<Void>());
    }
  }
}

// Extension to convert Pointer<Char> to String
extension PointerCharExtension on Pointer<Char> {
  String toDartString() {
    if (this == nullptr) return '';
    
    final List<int> units = [];
    int i = 0;
    while (this[i] != 0) {
      units.add(this[i]);
      i++;
    }
    return String.fromCharCodes(units);
  }
}

// Extension to convert String to Pointer<Char>
extension StringToCharExtension on String {
  Pointer<Char> toNativeChar() {
    final units = utf8.encode(this);
    final result = SimpleAllocator.allocateChar(units.length + 1);
    for (int i = 0; i < units.length; i++) {
      result[i] = units[i];
    }
    result[units.length] = 0; // null terminator
    return result;
  }
}

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
    final identityPtr = identityJson.toNativeChar();
    
    final resultPtr = _generatePrekeyBundle(identityPtr);
    final jsonStr = resultPtr.toDartString();
    
    SimpleAllocator.free(identityPtr);
    _freeString(resultPtr);
    
    if (jsonStr.startsWith('ERROR:')) {
      throw Exception(jsonStr);
    }
    
    return json.decode(jsonStr);
  }
}

// Mock implementation for demonstration when library is not available
class MockSignalCrypto {
  Map<String, dynamic> generateIdentityKeypair() {
    // Mock data for demonstration
    return {
      'dh_public': List.generate(32, (i) => i),
      'dh_private': List.generate(32, (i) => i + 32),
      'ed_public': List.generate(32, (i) => i + 64),
      'ed_private': List.generate(32, (i) => i + 96),
    };
  }
  
  Map<String, dynamic> generatePrekeyBundle(Map<String, dynamic> identity) {
    // Mock data for demonstration
    return {
      'identity_key': identity['dh_public'],
      'signed_prekey': {
        'key_id': 1,
        'public': List.generate(32, (i) => i + 128),
        'signature': List.generate(64, (i) => i + 160),
      },
      'one_time_prekey': {
        'key_id': 2,
        'public': List.generate(32, (i) => i + 224),
      }
    };
  }
}

// Example usage
void main() {
  print('Signal Crypto Library - Dart Example\n');
  
  try {
    // Try to use the real library first
    dynamic crypto;
    bool usingMock = false;
    
    try {
      crypto = SignalCrypto();
    } catch (e) {
      print('⚠️  Could not load Signal Crypto Library: $e');
      print('   Using mock implementation for demonstration...\n');
      crypto = MockSignalCrypto();
      usingMock = true;
    }
    
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
    final identityStr = json.encode(identity);
    final bundleStr = json.encode(prekeyBundle);
    print('   Identity: ${identityStr.length > 100 ? identityStr.substring(0, 100) + '...' : identityStr}');
    print('   Bundle: ${bundleStr.length > 100 ? bundleStr.substring(0, 100) + '...' : bundleStr}');
    
    if (usingMock) {
      print('\n📝 Note: This is a mock demonstration.');
      print('   To use the real Signal Protocol library:');
      print('   1. Build the Rust library: cargo build --release');
      print('   2. Ensure the library is in your system path');
      print('   3. Run this example again');
    } else {
      print('\n✅ Signal Protocol initialization successful!');
      print('   You can now use these keys to establish secure sessions.');
    }
    
  } catch (e) {
    print('❌ Error: $e');
    print('\nTroubleshooting:');
    print('1. Ensure the Signal Crypto Library is built (cargo build --release)');
    print('2. Check that the library is accessible in your system path');
    print('3. Verify the FFI function names match the library exports');
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