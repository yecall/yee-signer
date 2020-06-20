#!/bin/bash

#oc
cargo lipo --release
cbindgen src/ffi.rs -l c > target/universal/release/libyee_signer.h

cp target/universal/release/libyee_signer.h oc/YeeSigner/YeeSigner/YeeSigner/
cp target/universal/release/libyee_signer.a oc/YeeSigner/YeeSigner/YeeSigner/

#java
PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/:$PATH CC_aarch64_linux_android=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android26-clang cargo build --lib --release --target aarch64-linux-android
PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/:$PATH CC_armv7_linux_androideabi=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi26-clang CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi26-clang cargo build --lib --release --target armv7-linux-androideabi
PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/:$PATH CC_i686_linux_android=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android26-clang CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android26-clang cargo build --lib --release --target i686-linux-android
cargo build --release

cp target/aarch64-linux-android/release/libyee_signer.so java/jniLibs/arm64/
cp target/armv7-linux-androideabi/release/libyee_signer.so java/jniLibs/armeabi/
cp target/i686-linux-android/release/libyee_signer.so java/jniLibs/x86/
cp target/release/libyee_signer.dylib java/jniLibs/
