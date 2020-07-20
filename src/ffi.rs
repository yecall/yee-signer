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
use std::ptr::null_mut;
use std::slice;

use crate::{KeyPair, SECRET_KEY_LEN, SignerResult, Verifier};
use crate::error::error_result_ffi;
use crate::export;
use crate::tx::types::HASH_LEN;

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_from_mini_secret_key(mini_secret_key: *const c_uchar,
														   mini_secret_key_len: c_uint,
														   err: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let mini_secret_key = unsafe { slice::from_raw_parts(mini_secret_key, mini_secret_key_len as usize) };

		let result = export::key_pair_from_mini_secret_key(mini_secret_key)?;

		Ok(result as *mut _)
	};

	error_result_ffi(run, null_mut() as *mut _, err)
}

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_from_secret_key(secret_key: *const c_uchar,
													  secret_key_len: c_uint,
													  err: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let secret_key = unsafe { slice::from_raw_parts(secret_key, secret_key_len as usize) };

		let result = export::key_pair_from_secret_key(secret_key)?;

		Ok(result as *mut _)
	};

	error_result_ffi(run, null_mut() as *mut _, err)
}

#[no_mangle]
pub extern "C" fn yee_signer_public_key(key_pair: *mut c_uint,
										out: *mut c_uchar,
										out_len: c_uint,
										_err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let result = export::public_key(key_pair);

	let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };

	out.copy_from_slice(&result);
}

#[no_mangle]
pub extern "C" fn yee_signer_secret_key(key_pair: *mut c_uint,
										out: *mut c_uchar,
										out_len: c_uint,
										_err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let result = export::secret_key(key_pair);
	let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };

	out.copy_from_slice(&result);
}

#[no_mangle]
pub extern "C" fn yee_signer_sign(key_pair: *mut c_uint,
								  message: *const c_uchar,
								  message_len: c_uint,
								  out: *mut c_uchar,
								  out_len: c_uint,
								  ctx: *const c_uchar,
								  ctx_len: c_uint,
								  _err: *mut c_uint) {
	let key_pair = key_pair as *mut KeyPair;
	let message = unsafe { slice::from_raw_parts(message, message_len as usize) };
	let ctx = unsafe { slice::from_raw_parts(ctx, ctx_len as usize) };

	let result = export::sign(key_pair, message, ctx);

	let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };
	out.copy_from_slice(&result);
}

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_free(key_pair: *mut c_uint,
										   _err: *mut c_uint) {
	export::key_pair_free(key_pair as *mut KeyPair);
}

#[no_mangle]
pub extern "C" fn yee_signer_verifier_from_public_key(public_key: *const c_uchar,
													  public_key_len: c_uint,
													  err: *mut c_uint) -> *mut c_uint {
	let public_key = unsafe { slice::from_raw_parts(public_key, public_key_len as usize) };

	let run = || -> SignerResult<*mut c_uint> {
		let result = export::verifier_from_public_key(public_key)?;
		Ok(result as *mut c_uint)
	};

	error_result_ffi(run, null_mut() as *mut _, err)
}

#[no_mangle]
pub extern "C" fn yee_signer_verify(verifier: *mut c_uint,
									signature: *const c_uchar,
									signature_len: c_uint,
									message: *const c_uchar,
									message_len: c_uint,
									ctx: *const c_uchar,
									ctx_len: c_uint,
									err: *mut c_uint) {
	let verifier = verifier as *mut Verifier;

	let signature = unsafe { slice::from_raw_parts(signature, signature_len as usize) };
	let message = unsafe { slice::from_raw_parts(message, message_len as usize) };
	let ctx = unsafe { slice::from_raw_parts(ctx, ctx_len as usize) };

	let run = || -> SignerResult<()> {
		export::verify(verifier, signature, message, ctx)?;
		Ok(())
	};

	error_result_ffi(run, (), err);
}

#[no_mangle]
pub extern "C" fn yee_signer_verifier_free(verifier: *mut c_uint,
										   _err: *mut c_uint) {
	export::verifier_free(verifier as *mut Verifier);
}

#[no_mangle]
pub extern "C" fn yee_signer_build_call
(json: *const c_uchar, json_len: c_uint, error: *mut c_uint) -> *mut c_uint {

	let json = unsafe { slice::from_raw_parts(json, json_len as usize) };

	let run = || -> SignerResult<*mut c_uint> {
		export::common_build_call(json)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_call_free
(call: *mut c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		export::call_free(call)
	};

	error_result_ffi(run, (), error)
}

#[no_mangle]
pub extern "C" fn yee_signer_build_tx
(secret_key: *const c_uchar, secret_key_len: c_uint, nonce: c_ulong, period: c_ulong, current: c_ulong,
 current_hash: *const c_uchar, current_hash_len: c_uint, call: *mut c_uint, error: *mut c_uint) -> *mut c_uint {
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

		export::common_build_tx(secret_key, nonce, period, current, current_hash, call)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_free
(tx: *mut c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		export::tx_free(tx)
	};

	error_result_ffi(run, (), error)
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_encode
(tx: *mut c_uint, error: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let result = export::tx_encode(tx)?;
		Ok(result)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_vec_len
(vec: *mut c_uint, error: *mut c_uint) -> c_uint {
	let run = || -> SignerResult<c_uint> {
		let result = export::vec_len(vec)?;
		Ok(result)
	};

	error_result_ffi(run, 0, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_vec_copy
(vec: *mut c_uint, out: *mut c_uchar, out_len: c_uint,  error: *mut c_uint) {
	let run = || -> SignerResult<()> {

		let out = unsafe { slice::from_raw_parts_mut(out, out_len as usize) };

		let f = |vec: &Vec<u8>| {
			out.copy_from_slice(vec);
			Ok(())
		};

		export::vec_copy(vec, f)?;
		Ok(())
	};

	error_result_ffi(run, (), error)
}

#[no_mangle]
pub extern "C" fn yee_signer_vec_free
(vec: *mut c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {

		export::vec_free(vec)?;
		Ok(())
	};

	error_result_ffi(run, (), error);
}

#[no_mangle]
pub extern "C" fn yee_signer_tx_decode
(raw: *const c_uchar, raw_len: c_uint, error: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let raw = unsafe { slice::from_raw_parts(raw, raw_len as usize) };

		let tx = export::tx_decode(raw)?;

		Ok(tx)
	};

	error_result_ffi(run, null_mut() as *mut _, error)
}

#[no_mangle]
pub extern "C" fn yee_signer_verify_tx
(tx: *mut c_uint, current_hash: *const c_uchar, current_hash_len: c_uint, error: *mut c_uint) {
	let run = || -> SignerResult<()> {
		let current_hash = {
			let mut tmp = [0u8; HASH_LEN];
			tmp.copy_from_slice(unsafe { slice::from_raw_parts(current_hash, current_hash_len as usize) });
			tmp
		};

		export::common_verify_tx(tx, &current_hash)
	};

	error_result_ffi(run, (), error);
}
