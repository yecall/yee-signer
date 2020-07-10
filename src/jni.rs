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
use jni::sys::{jlong, jint};

use crate::{KeyPair, Verifier, SignerResult, SECRET_KEY_LEN};
use crate::error::error_result_jni;
use crate::tx::{build_tx, call, build_call, verify_tx, decode_tx_method};
use crate::tx::types::{ADDRESS_LEN, Address, HASH_LEN, Call, Transaction};
use parity_codec::{Compact, Encode, Decode};

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_keyPairFromMiniSecretKey
(env: JNIEnv, _jclass: JClass, mini_secret_key: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let mini_secret_key = env.convert_byte_array(mini_secret_key).map_err(|_| "jni error")?;

		let key_pair = KeyPair::from_mini_secret_key(&mini_secret_key)?;

		let a = Box::into_raw(Box::new(key_pair));

		Ok(a as jlong)
	};

	error_result_jni(run, 0, &env, error)
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

	error_result_jni(run, 0, &env, error)
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

	error_result_jni(run, (), &env, error);

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
	error_result_jni(run, (), &env, error);

	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_sign
(env: JNIEnv, _jclass: JClass, key_pair: jlong, message: jbyteArray, signature: jbyteArray, ctx: jbyteArray, error: jbyteArray) {
	let key_pair = unsafe { Box::from_raw(key_pair as *mut KeyPair) };

	let run = || -> SignerResult<()> {
		let message = env.convert_byte_array(message).map_err(|_| "jni error")?;
		let ctx = env.convert_byte_array(ctx).map_err(|_| "jni error")?;

		let signature_result = key_pair.sign(&message, &ctx).iter().map(|x| *x as i8).collect::<Vec<_>>();

		env.set_byte_array_region(signature, 0, &signature_result).map_err(|_| "jni error")?;
		Ok(())
	};
	error_result_jni(run, (), &env, error);

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

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verify
(env: JNIEnv, _jclass: JClass, verifier: jlong, signature: jbyteArray, message: jbyteArray, ctx: jbyteArray, error: jbyteArray) {
	let verifier = unsafe { Box::from_raw(verifier as *mut Verifier) };

	let run = || -> SignerResult<()> {
		let signature = env.convert_byte_array(signature).map_err(|_| "jni error")?;

		let message = env.convert_byte_array(message).map_err(|_| "jni error")?;
		let ctx = env.convert_byte_array(ctx).map_err(|_| "jni error")?;

		verifier.verify(&signature, &message, &ctx)?;

		Ok(())
	};
	error_result_jni(run, (), &env, error);

	std::mem::forget(verifier);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifierFree
(_env: JNIEnv, _jclass: JClass, verifier: jlong, _error: jbyteArray) {
	let _verifier = unsafe { Box::from_raw(verifier as *mut Verifier) };
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_buildCallBalanceTransfer
(env: JNIEnv, _jclass: JClass, dest: jbyteArray, value: jlong, module_holder: jbyteArray, method_holder: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let call = {
			let (module, method) = (call::BALANCE, call::TRANSFER);
			let dest = env.convert_byte_array(dest).map_err(|_| "jni error")?;
			let dest = {
				let mut tmp = [0u8; ADDRESS_LEN];
				tmp.copy_from_slice(&dest);
				Address(tmp)
			};
			let value = Compact(value as u128);

			let params = call::BalanceTransferParams {
				dest,
				value,
			};

			env.set_byte_array_region(module_holder, 0, &[module as i8]).map_err(|_| "jni error")?;
			env.set_byte_array_region(method_holder, 0, &[method as i8]).map_err(|_| "jni error")?;

			let call = build_call(module, method, params);
			let a = Box::into_raw(Box::new(call));
			a
		};

		Ok(call as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_callFree
(env: JNIEnv, _jclass: JClass, call: jlong, module: jint, method: jint, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let _call = match (module as u8, method as u8) {
			(call::BALANCE, call::TRANSFER) => {
				unsafe { Box::from_raw(call as *mut Call<call::BalanceTransferParams>) }
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_jni(run, (), &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_buildTx
(env: JNIEnv, _jclass: JClass, secret_key: jbyteArray, nonce: jlong, period: jlong, current: jlong, current_hash: jbyteArray, call: jlong, module: jint, method: jint, error: jbyteArray) -> jlong {
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

		let tx = match (module as u8, method as u8) {
			(call::BALANCE, call::TRANSFER) => {
				let call = unsafe { Box::from_raw(call as *mut Call<call::BalanceTransferParams>) };
				let call_clone = *call.clone();
				std::mem::forget(call);
				let tx = build_tx(secret_key, nonce, period, current, current_hash, call_clone)?;
				let a = Box::into_raw(Box::new(tx));
				a
			}
			_ => return Err("invalid method".to_string()),
		};

		Ok(tx as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txFree
(env: JNIEnv, _jclass: JClass, tx: jlong, module: jint, method: jint, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let _tx = match (module as u8, method as u8) {
			(call::BALANCE, call::TRANSFER) => {
				unsafe { Box::from_raw(tx as *mut Transaction<call::BalanceTransferParams>) }
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_jni(run, (), &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txLength
(env: JNIEnv, _jclass: JClass, tx: jlong, module: jint, method: jint, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<i64> {
		let len = match (module as u8, method as u8) {
			(call::BALANCE, call::TRANSFER) => {
				let tx = unsafe { Box::from_raw(tx as *mut Transaction<call::BalanceTransferParams>) };
				let len = tx.encode().len();
				std::mem::forget(tx);
				len
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(len as i64)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txEncode
(env: JNIEnv, _jclass: JClass, tx: jlong, module: jint, method: jint, buffer: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		match (module as u8, method as u8) {
			(call::BALANCE, call::TRANSFER) => {
				let tx = unsafe { Box::from_raw(tx as *mut Transaction<call::BalanceTransferParams>) };
				let encode = (*tx).encode().iter().map(|x| *x as i8).collect::<Vec<_>>();
				std::mem::forget(tx);
				env.set_byte_array_region(buffer, 0, &encode).map_err(|_| "jni error")?;
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_jni(run, (), &env, error);
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_txDecode
(env: JNIEnv, _jclass: JClass, raw: jbyteArray, module_holder: jbyteArray, method_holder: jbyteArray, error: jbyteArray) -> jlong {
	let run = || -> SignerResult<jlong> {
		let raw = env.convert_byte_array(raw).map_err(|_| "jni error")?;
		let (module, method) = decode_tx_method(&raw)?;

		let tx = match (module, method) {
			(call::BALANCE, call::TRANSFER) => {
				env.set_byte_array_region(module_holder, 0, &[module as i8]).map_err(|_| "jni error")?;
				env.set_byte_array_region(method_holder, 0, &[method as i8]).map_err(|_| "jni error")?;
				let tx: Transaction<call::BalanceTransferParams> = Decode::decode(&mut &raw[..]).ok_or("invalid tx")?;
				let a = Box::into_raw(Box::new(tx));
				a
			}
			_ => return Err("invalid tx".to_string()),
		};

		Ok(tx as jlong)
	};

	error_result_jni(run, 0, &env, error)
}

#[no_mangle]
pub extern "system" fn Java_io_yeeco_yeesigner_JNI_verifyTx
(env: JNIEnv, _jclass: JClass, tx: jlong, module: jint, method: jint, current_hash: jbyteArray, error: jbyteArray) {
	let run = || -> SignerResult<()> {
		let current_hash = env.convert_byte_array(current_hash).map_err(|_| "jni error")?;
		let current_hash = {
			let mut tmp = [0u8; HASH_LEN];
			tmp.copy_from_slice(&current_hash);
			tmp
		};

		match (module as u8, method as u8) {
			(call::BALANCE, call::TRANSFER) => {
				let tx = unsafe { Box::from_raw(tx as *mut Transaction<call::BalanceTransferParams>) };
				let verified = verify_tx(&tx, &current_hash);
				std::mem::forget(tx);
				verified?
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_jni(run, (), &env, error);
}
