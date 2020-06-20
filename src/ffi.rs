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

use std::os::raw::{c_uchar, c_uint};
use std::slice;
use std::ptr::null_mut;

use crate::{KeyPair, Verifier, SignerResult};
use crate::error::error_code;

#[no_mangle]
pub extern "C" fn yee_signer_key_pair_from_mini_secret_key(mini_secret_key: *const c_uchar,
														   mini_secret_key_len: c_uint,
														   err: *mut c_uint) -> *mut c_uint {
	let run = || -> SignerResult<*mut c_uint> {
		let mini_secret_key = unsafe { slice::from_raw_parts(mini_secret_key, mini_secret_key_len as usize) };

		let key_pair = KeyPair::from_mini_secret_key(mini_secret_key)?;

		Ok(Box::into_raw(Box::new(key_pair)) as *mut c_uint)
	};

	match run() {
		Ok(r) => r,
		Err(e) => {
			unsafe { *err = error_code(&e) as c_uint };
			null_mut() as *mut _
		}
	}
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

	match run() {
		Ok(r) => r,
		Err(e) => {
			unsafe { *err = error_code(&e) as c_uint };
			null_mut() as *mut _
		}
	}
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

	let run = || -> SignerResult< *mut c_uint> {
		let verifier = Verifier::from_public_key(public_key)?;
		Ok(Box::into_raw(Box::new(verifier)) as *mut c_uint)
	};

	match run() {
		Ok(r) => r,
		Err(e) => {
			unsafe { *err = error_code(&e) as c_uint };
			null_mut() as *mut _
		}
	}
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

	match run() {
		Ok(r) => r,
		Err(e) => {
			unsafe { *err = error_code(&e) as c_uint };
		}
	}

	std::mem::forget(verifier);
}

#[no_mangle]
pub extern "C" fn yee_signer_verifier_free(verifier: *mut c_uint,
										   _err: *mut c_uint) {
	let verifier = verifier as *mut Verifier;
	let _verifier = unsafe { Box::from_raw(verifier) };
}