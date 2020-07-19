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

use std::os::raw::c_uint;

use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jlong;
use jni::sys::jbyteArray;

use crate::{KeyPair, SECRET_KEY_LEN, SignerResult, Verifier};
use crate::error::error_result_jni;
use crate::export;
use crate::tx::types::HASH_LEN;

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFromMiniSecretKey
(env: JNIEnv, _jclass: JClass, mini_secret_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let mini_secret_key = env.convert_byte_array(mini_secret_key).map_err(|_| "jni error")?;

		let result = export::key_pair_from_mini_secret_key(&mini_secret_key)?;

		Ok(result as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFromSecretKey
(env: JNIEnv, _jclass: JClass, secret_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let secret_key = env.convert_byte_array(secret_key).map_err(|_| "jni error")?;

		let result = export::key_pair_from_secret_key(&secret_key)?;

		Ok(result as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_publicKey
(env: JNIEnv, _jclass: JClass, key_pair: jlong, public_key: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let result = export::public_key(key_pair as *mut KeyPair).iter().map(|x| *x as i8).collect::<Vec<_>>();

		env.set_byte_array_region(public_key, 0, &result).map_err(|_| "jni error")?;
		Ok(())
	};

	error_result_jni(run, (), &env, error);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_secretKey
(env: JNIEnv, _jclass: JClass, key_pair: jlong, secret_key: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let result = export::secret_key(key_pair as *mut KeyPair).iter().map(|x| *x as i8).collect::<Vec<_>>();

		env.set_byte_array_region(secret_key, 0, &result).map_err(|_| "jni error")?;
		Ok(())
	};
	error_result_jni(run, (), &env, error);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_sign
(env: JNIEnv, _jclass: JClass, key_pair: jlong, message: jbyteArray, signature: jbyteArray, ctx: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let message = env.convert_byte_array(message).map_err(|_| "jni error")?;
		let ctx = env.convert_byte_array(ctx).map_err(|_| "jni error")?;

		let result = export::sign(key_pair as *mut KeyPair, &message, &ctx).iter().map(|x| *x as i8).collect::<Vec<_>>();

		env.set_byte_array_region(signature, 0, &result).map_err(|_| "jni error")?;
		Ok(())
	};
	error_result_jni(run, (), &env, error);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFree
(_env: JNIEnv, _jclass: JClass, key_pair: jlong, _error: jbyteArray) {
	export::key_pair_free(key_pair as *mut KeyPair);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifierFromPublicKey
(env: JNIEnv, _jclass: JClass, public_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let public_key = env.convert_byte_array(public_key).map_err(|_| "jni error")?;

		let result = export::verifier_from_public_key(&public_key)?;

		Ok(result as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verify
(env: JNIEnv, _jclass: JClass, verifier: jlong, signature: jbyteArray, message: jbyteArray, ctx: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let signature = env.convert_byte_array(signature).map_err(|_| "jni error")?;

		let message = env.convert_byte_array(message).map_err(|_| "jni error")?;
		let ctx = env.convert_byte_array(ctx).map_err(|_| "jni error")?;

		export::verify(verifier as *mut Verifier, &signature, &message, &ctx)?;

		Ok(())
	};
	error_result_jni(run, (), &env, error);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifierFree
(_env: JNIEnv, _jclass: JClass, verifier: jlong, _error: jbyteArray) {
	export::verifier_free(verifier as *mut Verifier);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_buildCall
(env: JNIEnv, _jclass: JClass, json: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let json = env.convert_byte_array(json).map_err(|_| "jni error")?;
		let call = export::common_build_call(&json)?;
		Ok(call as jlong)
	};
	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_callFree
(env: JNIEnv, _jclass: JClass, call: jlong, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		export::call_free(call as *mut c_uint)
	};

	error_result_jni(run, (), &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_buildTx
(env: JNIEnv, _jclass: JClass, secret_key: jbyteArray, nonce: jlong, period: jlong, current: jlong, current_hash: jbyteArray, call: jlong, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let secret_key = env.convert_byte_array(secret_key).map_err(|_| "jni error")?;
		let secret_key = {
			let mut tmp = [0u8; SECRET_KEY_LEN];
			tmp.copy_from_slice(&secret_key);
			tmp
		};
		let nonce = nonce as u64;
		let period = period as u64;
		let current = current as u64;

		let current_hash = env.convert_byte_array(current_hash).map_err(|_| "jni error")?;
		let current_hash = {
			let mut tmp = [0u8; HASH_LEN];
			tmp.copy_from_slice(&current_hash);
			tmp
		};

		let result = export::common_build_tx(secret_key, nonce, period, current, current_hash,
											 call as *mut c_uint)?;

		Ok(result as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txFree
(env: JNIEnv, _jclass: JClass, tx: jlong, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		export::tx_free(tx as *mut c_uint)
	};

	error_result_jni(run, (), &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txEncode
(env: JNIEnv, _jclass: JClass, tx: jlong, error: jbyteArray) -> jlong{
	let run = || -> SignerResult<jlong> {
		let result = export::tx_encode(tx as *mut c_uint)?;
		Ok(result as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_vecLen
(env: JNIEnv, _jclass: JClass, vec: jlong, error: jbyteArray) -> jlong{
	let run = || -> SignerResult<jlong> {
		let result = export::vec_len(vec as *mut c_uint)?;
		Ok(result as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_vecCopy
(env: JNIEnv, _jclass: JClass, vec: jlong, out: jbyteArray, error: jbyteArray){
	let run = || -> SignerResult<()> {

		let f = |vec: &Vec<u8>| {
			let vec = vec.iter().map(|x|*x as i8).collect::<Vec<_>>();
			env.set_byte_array_region(out, 0, &vec).map_err(|_| "jni error")?;
			Ok(())
		};

		export::vec_copy(vec as *mut c_uint, f)?;
		Ok(())
	};

	error_result_jni(run, (), &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_vecFree
(env: JNIEnv, _jclass: JClass, vec: jlong, error: jbyteArray){
	let run = || -> SignerResult<()> {
		export::vec_free(vec as *mut c_uint)
	};

	error_result_jni(run, (), &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txDecode
(env: JNIEnv, _jclass: JClass, raw: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let raw = env.convert_byte_array(raw).map_err(|_| "jni error")?;
		let tx = export::tx_decode(&raw)?;
		Ok(tx as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifyTx
(env: JNIEnv, _jclass: JClass, tx: jlong, current_hash: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let current_hash = env.convert_byte_array(current_hash).map_err(|_| "jni error")?;
		let current_hash = {
			let mut tmp = [0u8; HASH_LEN];
			tmp.copy_from_slice(&current_hash);
			tmp
		};

		export::common_verify_tx(tx as *mut c_uint, &current_hash)
	};

	error_result_jni(run, (), &env, error)
}
