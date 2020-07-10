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

use std::os::raw::{c_uchar, c_uint, c_ulong};
use std::slice;
use std::ptr::null_mut;

use crate::{KeyPair, Verifier, SignerResult, SECRET_KEY_LEN};
use crate::error::error_result_ffi;
use crate::tx::{method, build_tx, decode_tx_method, verify_tx};
use parity_codec::{Compact, Encode, Decode};
use crate::tx::types::{BalanceTransferParams, ADDRESS_LEN, Address, Call, HASH_LEN, Transaction};
use crate::tx::build_call;

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_from_mini_secret_key(mini_secret_key: *const c_uchar,
														   mini_secret_key_len: c_uint,
														   err: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let mini_secret_key = unsafe { slice::from_raw_parts(mini_secret_key, mini_secret_key_len as usize) };

		let key_pair = KeyPair::from_mini_secret_key(mini_secret_key)?;

		Ok(Box::into_raw(Box::new(key_pair)) as *mut c_uint)
	};

	error_result_ffi(run, null_mut() as *mut _, err)
}

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_from_secret_key(secret_key: *const c_uchar,
													  secret_key_len: c_uint,
													  err: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let secret_key = unsafe { slice::from_raw_parts(secret_key, secret_key_len as usize) };

		let key_pair = KeyPair::from_secret_key(secret_key)?;

		Ok(Box::into_raw(Box::new(key_pair)) as *mut c_uint)
	};

	error_result_ffi(run, null_mut() as *mut _, err)
}

#[no_mangle]
pub extern "C" fn yee_signer_public_key(key_pair: *mut c_uint,
										out: *mut c_uchar,
										out_len: c_uint,
										_err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let key_pair = unsafe { Box::from_raw(key_pair) };

	let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };
	let public_key_result = key_pair.public_key();
	out.copy_from_slice(&public_key_result);
	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "C" fn yee_signer_secret_key(key_pair: *mut c_uint,
										out: *mut c_uchar,
										out_len: c_uint,
										_err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let key_pair = unsafe { Box::from_raw(key_pair) };
	let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };
	let secret_key_result = key_pair.secret_key();
	out.copy_from_slice(&secret_key_result);
	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "C" fn yee_signer_sign(key_pair: *mut c_uint,
								  message: *const c_uchar,
								  message_len: c_uint,
								  out: *mut c_uchar,
								  out_len: c_uint,
								  _err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let key_pair = unsafe { Box::from_raw(key_pair) };

	let message = unsafe { slice::from_raw_parts(message, message_len as usize) };

	let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };
	let result = key_pair.sign(message);
	out.copy_from_slice(&result);
	std::mem::forget(key_pair);
}

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_free(key_pair: *mut c_uint,
										   _err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let _key_pair = unsafe { Box::from_raw(key_pair) };
}

#[no_mangle]
pub extern "C" fn yee_signer_verifier_from_public_key(public_key: *const c_uchar,
													  public_key_len: c_uint,
													  err: *mut c_uint) -> *mut c_uint {
	let public_key = unsafe { slice::from_raw_parts(public_key, public_key_len as usize) };

	let run = || -> SignerResult<*mut c_uint> {
		let verifier = Verifier::from_public_key(public_key)?;
		Ok(Box::into_raw(Box::new(verifier)) as *mut c_uint)
	};

	error_result_ffi(run, null_mut() as *mut _, err)
}

#[no_mangle]
pub extern "C" fn yee_signer_verify(verifier: *mut c_uint,
									signature: *const c_uchar,
									signature_len: c_uint,
									message: *const c_uchar,
									message_len: c_uint,
									err: *mut c_uint) {
	let verifier = verifier as *mut Verifier;
	let verifier = unsafe { Box::from_raw(verifier) };

	let signature = unsafe { slice::from_raw_parts(signature, signature_len as usize) };
	let message = unsafe { slice::from_raw_parts(message, message_len as usize) };

	let run = || -> SignerResult<()> {
		verifier.verify(signature, message)?;
		Ok(())
	};

	error_result_ffi(run, (), err);

	std::mem::forget(verifier);
}

#[no_mangle]
pub extern "C" fn yee_signer_verifier_free(verifier: *mut c_uint,
										   _err: *mut c_uint) {
	let verifier = verifier as *mut Verifier;
	let _verifier = unsafe { Box::from_raw(verifier) };
}

#[no_mangle]
pub extern "C" fn yee_signer_build_call_balance_transfer
(dest: *const c_uchar, dest_len: c_uint, value: c_ulong, module_holder: *mut c_uint, method_holder: *mut c_uint, error: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let call = {
			let (module, method) = (method::BALANCE, method::TRANSFER);
			let dest = {
				let mut tmp = [0u8; ADDRESS_LEN];
				tmp.copy_from_slice(unsafe { slice::from_raw_parts(dest, dest_len as usize) });
				tmp
			};
			let dest = Address(dest);
			let value = Compact(value as u128);

			let params = BalanceTransferParams {
				dest,
				value,
			};

			unsafe { *module_holder = module as c_uint };
			unsafe { *method_holder = method as c_uint };

			let call = build_call(module, method, params);
			let a = Box::into_raw(Box::new(call));
			a
		};

		Ok(call as *mut c_uint)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_call_free
(call: *mut c_uint, module: c_uint, method: c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		let _call = match (module as u8, method as u8) {
			(method::BALANCE, method::TRANSFER) => {
				let call = call as *mut Call<BalanceTransferParams>;
				let _call = unsafe { Box::from_raw(call) };
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_ffi(run, (), error)
}

#[no_mangle]
pub extern "C" fn yee_signer_build_tx
(secret_key: *const c_uchar, secret_key_len: c_uint, nonce: c_ulong, period: c_ulong, current: c_ulong,
 current_hash: *const c_uchar, current_hash_len: c_uint, call: *mut c_uint, module: c_uint, method: c_uint, error: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let secret_key = {
			let mut tmp = [0u8; SECRET_KEY_LEN];
			tmp.copy_from_slice(unsafe { slice::from_raw_parts(secret_key, secret_key_len as usize) });
			tmp
		};

		let nonce = nonce as u64;
		let period = period as u64;
		let current = current as u64;

		let current_hash = {
			let mut tmp = [0u8; HASH_LEN];
			tmp.copy_from_slice(unsafe { slice::from_raw_parts(current_hash, current_hash_len as usize) });
			tmp
		};

		let tx = match (module as u8, method as u8) {
			(method::BALANCE, method::TRANSFER) => {
				let call = unsafe { Box::from_raw(call as *mut Call<BalanceTransferParams>) };
				let call_clone = *call.clone();
				std::mem::forget(call);
				let tx = build_tx(secret_key, nonce, period, current, current_hash, call_clone)?;
				let a = Box::into_raw(Box::new(tx));
				a
			}
			_ => return Err("invalid method".to_string()),
		};

		Ok(tx as *mut c_uint)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_free
(tx: *mut c_uint, module: c_uint, method: c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		let _tx = match (module as u8, method as u8) {
			(method::BALANCE, method::TRANSFER) => {
				unsafe { Box::from_raw(tx as *mut Transaction<BalanceTransferParams>) }
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_ffi(run, (), error)
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_length
(tx: *mut c_uint, module: c_uint, method: c_uint, error: *mut c_uint) -> c_uint {
	let run = || -> SignerResult<c_uint> {
		let len = match (module as u8, method as u8) {
			(method::BALANCE, method::TRANSFER) => {
				let tx = unsafe { Box::from_raw(tx as *mut Transaction<BalanceTransferParams>) };
				let len = tx.encode().len();
				std::mem::forget(tx);
				len
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(len as c_uint)
	};

	error_result_ffi(run, 0, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_encode
(tx: *mut c_uint, module: c_uint, method: c_uint, buffer: *mut c_uchar, buffer_len: c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		match (module as u8, method as u8) {
			(method::BALANCE, method::TRANSFER) => {
				let tx = unsafe { Box::from_raw(tx as *mut Transaction<BalanceTransferParams>) };
				let encode = (*tx).encode();
				let buffer = unsafe { slice::from_raw_parts_mut(buffer, buffer_len as usize) };
				buffer.copy_from_slice(&encode);
				std::mem::forget(tx);
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_ffi(run, (), error);
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_decode
(raw: *const c_uchar, raw_len: c_uint, module_holder: *mut c_uint, method_holder: *mut c_uint, error: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let raw = unsafe { slice::from_raw_parts(raw, raw_len as usize) };
		let (module, method) = decode_tx_method(raw)?;

		let tx = match (module, method) {
			(method::BALANCE, method::TRANSFER) => {
				unsafe { *module_holder = module as c_uint };
				unsafe { *method_holder = method as c_uint };

				let tx: Transaction<BalanceTransferParams> = Decode::decode(&mut &raw[..]).ok_or("invalid tx")?;
				let a = Box::into_raw(Box::new(tx));
				a
			}
			_ => return Err("invalid tx".to_string()),
		};

		Ok(tx as *mut _)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_verify_tx
(tx: *mut c_uint, module: c_uint, method: c_uint, current_hash: *const c_uchar, current_hash_len: c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		let current_hash = {
			let mut tmp = [0u8; HASH_LEN];
			tmp.copy_from_slice(unsafe { slice::from_raw_parts(current_hash, current_hash_len as usize) });
			tmp
		};

		match (module as u8, method as u8) {
			(method::BALANCE, method::TRANSFER) => {
				let tx = unsafe { Box::from_raw(tx as *mut Transaction<BalanceTransferParams>) };
				let verified = verify_tx(&tx, &current_hash);
				std::mem::forget(tx);
				verified?
			}
			_ => return Err("invalid method".to_string()),
		};
		Ok(())
	};

	error_result_ffi(run, (), error);
}
