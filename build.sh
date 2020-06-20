#!/bin/bash

cargo lipo --release
cbindgen src/ffi.rs -l c > target/universal/release/libyee_signer.h

cp target/universal/release/libyee_signer.h oc/YeeSigner/YeeSigner/YeeSigner/
cp target/universal/release/libyee_signer.a oc/YeeSigner/YeeSigner/YeeSigner/

cargo build --release
cp target/release/libyee_signer.dylib java/jniLibs/
