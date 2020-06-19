// Copyright 2019, 2020 Wingchain
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jbyteArray;
use jni::sys::jlong;

use crate::{KeyPair, Verifier, SignerResult};

fn error_code(error: &str) -> i8 {
	match error {
		"invalid mini secret key" => 2,
		"invalid secret key" => 3,
		"invalid public key" => 4,
		"invalid signature" => 5,
		"jni error" => 6,
		_ => 1,
	}
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFromMiniSecretKey
(env: JNIEnv, _jclass: JClass, mini_secret_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let mini_secret_key = env.convert_byte_array(mini_secret_key).map_err(|_| "jni error")?;

		let key_pair = KeyPair::from_mini_secret_key(&mini_secret_key)?;

		let a = Box::into_raw(Box::new(key_pair));

		Ok(a as jlong)
	};

	match run() {
		Ok(r) => r,
		Err(e) => {
			let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]);
			0
		}
	}
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFromSecretKey
(env: JNIEnv, _jclass: JClass, secret_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let secret_key = env.convert_byte_array(secret_key).map_err(|_| "jni error")?;

		let key_pair = KeyPair::from_secret_key(&secret_key)?;

		let a = Box::into_raw(Box::new(key_pair));

		Ok(a as jlong)
	};

	match run() {
		Ok(r) => r,
		Err(e) => {
			let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]);
			0
		}
	}
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_publicKey
(env: JNIEnv, _jclass: JClass, key_pair: jlong, public_key: jbyteArray, error: jbyteArray) {
	let key_pair = unsafe { Box::from_raw(key_pair as *mut KeyPair) };

	let run = || -> SignerResult<()> {
		let public_key_result = key_pair.public_key().iter().map(|x| *x as i8).collect::<Vec<_>>();


		env.set_byte_array_region(public_key, 0, &public_key_result).map_err(|_| "jni error")?;
		Ok(())
	};

	match run() {
		Ok(_) => (),
		Err(e) => { let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]); }
	}

	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_secretKey
(env: JNIEnv, _jclass: JClass, key_pair: jlong, secret_key: jbyteArray, error: jbyteArray) {
	let key_pair = unsafe { Box::from_raw(key_pair as *mut KeyPair) };

	let run = || -> SignerResult<()> {
		let secret_key_result = key_pair.secret_key().iter().map(|x| *x as i8).collect::<Vec<_>>();


		env.set_byte_array_region(secret_key, 0, &secret_key_result).map_err(|_| "jni error")?;
		Ok(())
	};
	match run() {
		Ok(_) => (),
		Err(e) => { let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]); }
	}

	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_sign
(env: JNIEnv, _jclass: JClass, key_pair: jlong, message: jbyteArray, signature: jbyteArray, error: jbyteArray) {
	let key_pair = unsafe { Box::from_raw(key_pair as *mut KeyPair) };

	let run = || -> SignerResult<()> {
		let message = env.convert_byte_array(message).map_err(|_| "jni error")?;

		let signature_result = key_pair.sign(&message).iter().map(|x| *x as i8).collect::<Vec<_>>();

		env.set_byte_array_region(signature, 0, &signature_result).map_err(|_| "jni error")?;
		Ok(())
	};
	match run() {
		Ok(_) => (),
		Err(e) => { let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]); }
	}

	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFree
(_env: JNIEnv, _jclass: JClass, key_pair: jlong, _error: jbyteArray) {
	let _key_pair = unsafe { Box::from_raw(key_pair as *mut KeyPair) };
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifierFromPublicKey
(env: JNIEnv, _jclass: JClass, public_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let public_key = env.convert_byte_array(public_key).map_err(|_| "jni error")?;

		let verifier = Verifier::from_public_key(&public_key)?;

		let a = Box::into_raw(Box::new(verifier));

		Ok(a as jlong)
	};

	match run() {
		Ok(r) => r,
		Err(e) => {
			let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]);
			0
		}
	}
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verify
(env: JNIEnv, _jclass: JClass, verifier: jlong, signature: jbyteArray, message: jbyteArray, error: jbyteArray) {
	let verifier = unsafe { Box::from_raw(verifier as *mut Verifier) };

	let run = || -> SignerResult<()> {
		let signature = env.convert_byte_array(signature).map_err(|_| "jni error")?;

		let message = env.convert_byte_array(message).map_err(|_| "jni error")?;

		verifier.verify(&signature, &message)?;

		Ok(())
	};
	match run() {
		Ok(_) => (),
		Err(e) => { let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]); }
	}

	std::mem::forget(verifier);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifierFree
(_env: JNIEnv, _jclass: JClass, verifier: jlong, _error: jbyteArray) {
	let _verifier = unsafe { Box::from_raw(verifier as *mut Verifier) };
}
