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

use parity_codec::{Decode, Encode};

use crate::address::{address_decode, address_encode};
use crate::external::c_uint;
use crate::external::{Box, String, ToString, Vec};
use crate::tx::build_call;
use crate::tx::types::{Call, Hash, Secret, Transaction};
use crate::tx::{build_tx, verify_tx};
use crate::{KeyPair, SignerResult, Verifier, PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LENGTH};

pub fn key_pair_generate() -> SignerResult<*mut KeyPair> {
	let key_pair = KeyPair::generate()?;

	Ok(Box::into_raw(Box::new(key_pair)))
}

pub fn key_pair_from_mini_secret_key(mini_secret_key: &[u8]) -> SignerResult<*mut KeyPair> {
	let key_pair = KeyPair::from_mini_secret_key(mini_secret_key)?;

	Ok(Box::into_raw(Box::new(key_pair)))
}

pub fn key_pair_from_secret_key(secret_key: &[u8]) -> SignerResult<*mut KeyPair> {
	let key_pair = KeyPair::from_secret_key(secret_key)?;

	Ok(Box::into_raw(Box::new(key_pair)))
}

pub fn public_key(key_pair: *mut KeyPair) -> [u8; PUBLIC_KEY_LEN] {
	let key_pair = unsafe { Box::from_raw(key_pair) };
	let public_key_result = key_pair.public_key();
	core::mem::forget(key_pair);
	public_key_result
}

pub fn secret_key(key_pair: *mut KeyPair) -> [u8; SECRET_KEY_LEN] {
	let key_pair = unsafe { Box::from_raw(key_pair) };
	let secret_key_result = key_pair.secret_key();
	core::mem::forget(key_pair);
	secret_key_result
}

pub fn sign(key_pair: *mut KeyPair, message: &[u8], ctx: &[u8]) -> [u8; SIGNATURE_LENGTH] {
	let key_pair = unsafe { Box::from_raw(key_pair) };
	let result = key_pair.sign(message, ctx);
	core::mem::forget(key_pair);
	result
}

pub fn key_pair_free(key_pair: *mut KeyPair) {
	let _key_pair = unsafe { Box::from_raw(key_pair) };
}

pub fn verifier_from_public_key(public_key: &[u8]) -> SignerResult<*mut Verifier> {
	let verifier = Verifier::from_public_key(public_key)?;
	Ok(Box::into_raw(Box::new(verifier)))
}

pub fn verify(
	verifier: *mut Verifier,
	signature: &[u8],
	message: &[u8],
	ctx: &[u8],
) -> SignerResult<()> {
	let verifier = unsafe { Box::from_raw(verifier) };
	let result = verifier.verify(signature, message, ctx);
	core::mem::forget(verifier);
	result
}

pub fn verifier_free(verifier: *mut Verifier) {
	let _verifier = unsafe { Box::from_raw(verifier) };
}

pub fn common_build_call(json: &[u8]) -> SignerResult<*mut c_uint> {
	let call = build_call(json)?;
	let result = Box::into_raw(Box::new(call)) as *mut c_uint;
	Ok(result)
}

pub fn call_free(call: *mut c_uint) -> SignerResult<()> {
	let call = call as *mut Call;
	let _call = unsafe { Box::from_raw(call) };
	Ok(())
}

pub fn common_build_tx(
	secret_key: Secret,
	nonce: u64,
	period: u64,
	current: u64,
	current_hash: Hash,
	call: *mut c_uint,
) -> SignerResult<*mut c_uint> {
	let call = unsafe { Box::from_raw(call as *mut Call) };
	let call_clone = *call.clone();
	core::mem::forget(call);
	let tx = build_tx(secret_key, nonce, period, current, current_hash, call_clone)?;
	let result = Box::into_raw(Box::new(tx)) as *mut _;
	Ok(result)
}

pub fn tx_free(tx: *mut c_uint) -> SignerResult<()> {
	let tx = tx as *mut Transaction;
	let _tx = unsafe { Box::from_raw(tx) };
	Ok(())
}

pub fn tx_encode(tx: *mut c_uint) -> SignerResult<*mut c_uint> {
	let tx = unsafe { Box::from_raw(tx as *mut Transaction) };
	let encode = tx.encode();
	let result = Box::into_raw(Box::new(encode)) as *mut _;
	core::mem::forget(tx);
	Ok(result)
}

pub fn vec_len(vec: *mut c_uint) -> SignerResult<c_uint> {
	let vec = unsafe { Box::from_raw(vec as *mut Vec<u8>) };
	let len = vec.len();
	core::mem::forget(vec);
	Ok(len as c_uint)
}

pub fn vec_copy<F>(vec: *mut c_uint, mut f: F) -> SignerResult<()>
where
	F: FnMut(&Vec<u8>) -> SignerResult<()>,
{
	let vec = unsafe { Box::from_raw(vec as *mut Vec<u8>) };
	f(&vec)?;
	core::mem::forget(vec);
	Ok(())
}

pub fn vec_free(vec: *mut c_uint) -> SignerResult<()> {
	let vec = vec as *mut Vec<u8>;
	let _vec = unsafe { Box::from_raw(vec) };
	Ok(())
}

pub fn tx_decode(raw: &[u8]) -> SignerResult<*mut c_uint> {
	let tx: Transaction = Decode::decode(&mut &raw[..]).ok_or("invalid tx")?;
	let result = Box::into_raw(Box::new(tx));
	Ok(result as *mut _)
}

pub fn common_verify_tx(tx: *mut c_uint, current_hash: &Hash) -> SignerResult<()> {
	let tx = unsafe { Box::from_raw(tx as *mut Transaction) };
	let verified = verify_tx(&tx, &current_hash);
	core::mem::forget(tx);
	verified
}

pub fn common_address_encode(public_key: &[u8], hrp: &[u8]) -> SignerResult<*mut c_uint> {
	let hrp = String::from_utf8_lossy(hrp);

	let address =
		address_encode(public_key, hrp.as_ref()).map_err(|_| "address encode error".to_string())?;

	let address = address.into_bytes();
	let result = Box::into_raw(Box::new(address)) as *mut _;
	Ok(result)
}

pub fn common_address_decode(address: &[u8]) -> SignerResult<(*mut c_uint, *mut c_uint)> {
	let address = String::from_utf8_lossy(address);

	let (public_key, hrp) =
		address_decode(address.as_ref()).map_err(|_| "address decode error".to_string())?;
	let public_key = public_key.to_vec();
	let hrp = hrp.into_bytes();

	let public_key = Box::into_raw(Box::new(public_key)) as *mut _;
	let hrp = Box::into_raw(Box::new(hrp)) as *mut _;
	Ok((public_key, hrp))
}
