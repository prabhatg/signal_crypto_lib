#!/bin/bash

# Build and Test Script for Signal Crypto Library
# This script demonstrates how to build the library and run tests

echo "Signal Crypto Library - Build and Test Script"
echo "============================================="
echo ""

# Step 1: Build the library
echo "1. Building the library in release mode..."
cargo build --release --features ffi

if [ $? -eq 0 ]; then
    echo "   ✓ Build successful!"
else
    echo "   ✗ Build failed!"
    exit 1
fi

# Step 2: Run tests
echo ""
echo "2. Running tests..."
cargo test

if [ $? -eq 0 ]; then
    echo "   ✓ All tests passed!"
else
    echo "   ✗ Some tests failed!"
    exit 1
fi

# Step 3: Show library location
echo ""
echo "3. Library location:"
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "   macOS: target/release/libsignal_crypto_lib.dylib"
    ls -la target/release/libsignal_crypto_lib.dylib
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "   Linux: target/release/libsignal_crypto_lib.so"
    ls -la target/release/libsignal_crypto_lib.so
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo "   Windows: target/release/signal_crypto_lib.dll"
    ls -la target/release/signal_crypto_lib.dll
fi

echo ""
echo "4. Next steps:"
echo "   - Copy the library to your Flutter project's appropriate platform folder"
echo "   - For Android: android/app/src/main/jniLibs/{ABI}/"
echo "   - For iOS: ios/Frameworks/"
echo "   - For macOS: macos/Frameworks/"
echo "   - Use the Dart example code to integrate with your Flutter app"
echo ""
echo "✅ Build and test completed successfully!"