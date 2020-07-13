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

use parity_codec::{Decode, Encode};
use serde::Deserialize;

use crate::{KeyPair, PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LENGTH, SignerResult, Verifier};
use crate::tx::{build_tx, call, decode_tx_method, verify_tx};
use crate::tx::build_call;
use crate::tx::call::{BalanceTransferParams, SudoSetKeyParams, SudoSudoParams};
use crate::tx::types::{Call, Hash, Secret, Transaction};
use serde_json::Value;

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
	std::mem::forget(key_pair);
	public_key_result
}

pub fn secret_key(key_pair: *mut KeyPair) -> [u8; SECRET_KEY_LEN] {

	let key_pair = unsafe { Box::from_raw(key_pair) };
	let secret_key_result = key_pair.secret_key();
	std::mem::forget(key_pair);
	secret_key_result
}

pub fn sign(key_pair: *mut KeyPair, message: &[u8], ctx: &[u8]) -> [u8; SIGNATURE_LENGTH] {
	let key_pair = unsafe { Box::from_raw(key_pair) };
	let result = key_pair.sign(message, ctx);
	std::mem::forget(key_pair);
	result
}

pub fn key_pair_free(key_pair: *mut KeyPair) {
	let _key_pair = unsafe { Box::from_raw(key_pair) };
}

pub fn verifier_from_public_key(public_key: &[u8]) -> SignerResult<*mut Verifier> {

	let verifier = Verifier::from_public_key(public_key)?;
	Ok(Box::into_raw(Box::new(verifier)))
}

pub fn verify(verifier: *mut Verifier, signature: &[u8], message: &[u8], ctx: &[u8]) -> SignerResult<()> {

	let verifier = unsafe { Box::from_raw(verifier) };
	let result = verifier.verify(signature, message, ctx);
	std::mem::forget(verifier);
	result
}

pub fn verifier_free(verifier: *mut Verifier) {
	let _verifier = unsafe { Box::from_raw(verifier) };
}

pub fn common_build_call(module: u8, method: u8, params: &[u8]) -> SignerResult<*mut c_uint> {

	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			common_build_call_fn::<BalanceTransferParams>(module, method, params)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			common_build_call_fn::<SudoSetKeyParams>(module, method, params)
		},
		_ => Err("invalid method".to_string()),
	}
}

fn common_build_call_fn<'de, Params: Deserialize<'de>>(module: u8, method: u8, params: &'de [u8]) -> SignerResult<*mut c_uint> {
	let params : Params = serde_json::from_slice::<'de>(&params).map_err(|_| "invalid params")?;
	let call = build_call(module, method, params);
	let result = Box::into_raw(Box::new(call)) as *mut c_uint;
	Ok(result)
}

pub fn call_free(call: *mut c_uint, module: u8, method: u8) -> SignerResult<()> {
	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			call_free_fn::<BalanceTransferParams>(call)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			call_free_fn::<SudoSetKeyParams>(call)
		},
		_ => Err("invalid method".to_string()),
	}
}

fn call_free_fn<Params>(call: *mut c_uint) -> SignerResult<()> {
	let call = call as *mut Call<Params>;
	let _call = unsafe { Box::from_raw(call) };
	Ok(())
}

pub fn common_build_tx(secret_key: Secret, nonce: u64, period: u64, current: u64,
					   current_hash: Hash, call: *mut c_uint, module: u8, method: u8) -> SignerResult<*mut c_uint> {

	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			common_build_tx_fn::<BalanceTransferParams>(secret_key, nonce, period, current, current_hash, call)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			common_build_tx_fn::<SudoSetKeyParams>(secret_key, nonce, period, current, current_hash, call)
		},
		_ => Err("invalid method".to_string()),
	}
}

fn common_build_tx_fn<Params: Clone + Encode>(secret_key: Secret, nonce: u64, period: u64, current: u64,
						  current_hash: Hash, call: *mut c_uint) -> SignerResult<*mut c_uint> {
	let call = unsafe { Box::from_raw(call as *mut Call<Params>) };
	let call_clone = *call.clone();
	std::mem::forget(call);
	let tx = build_tx(secret_key, nonce, period, current, current_hash, call_clone)?;
	let result = Box::into_raw(Box::new(tx)) as *mut _;
	Ok(result)
}

pub fn tx_free(tx: *mut c_uint, module: u8, method: u8) -> SignerResult<()> {
	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			tx_free_fn::<BalanceTransferParams>(tx)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			tx_free_fn::<SudoSetKeyParams>(tx)
		},
		_ => Err("invalid method".to_string()),
	}
}

fn tx_free_fn<Params>(tx: *mut c_uint) -> SignerResult<()> {
	let tx = tx as *mut Transaction<Params>;
	let _tx = unsafe { Box::from_raw(tx) };
	Ok(())
}

pub fn tx_encode(tx: *mut c_uint, module: u8, method: u8) -> SignerResult<Vec<u8>> {
	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			tx_encode_fn::<BalanceTransferParams>(tx)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			tx_encode_fn::<SudoSetKeyParams>(tx)
		},
		_ => Err("invalid method".to_string()),
	}
}

fn tx_encode_fn<Params: Encode>(tx: *mut c_uint)  -> SignerResult<Vec<u8>> {
	let tx = unsafe { Box::from_raw(tx as *mut Transaction<Params>) };
	let encode = tx.encode();
	std::mem::forget(tx);
	Ok(encode)
}

pub fn tx_decode(raw: &[u8]) -> SignerResult<(*mut c_uint, u8, u8)> {
	let (module, method) = decode_tx_method(raw)?;
	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			tx_decode_fn::<BalanceTransferParams>(raw)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			tx_decode_fn::<SudoSetKeyParams>(raw)
		},
		_ => Err("invalid method".to_string()),
	}.map(|r| (r, module, method))
}

fn tx_decode_fn<Params: Decode>(raw: &[u8]) -> SignerResult<*mut c_uint> {
	let tx: Transaction<Params> = Decode::decode(&mut &raw[..]).ok_or("invalid tx")?;
	let result = Box::into_raw(Box::new(tx));
	Ok(result as *mut _)
}

pub fn common_verify_tx(tx: *mut c_uint, module: u8, method: u8, current_hash: &Hash) -> SignerResult<()> {

	match (module, method) {
		(call::BALANCE, call::TRANSFER) => {
			common_verify_tx_fn::<BalanceTransferParams>(tx, current_hash)
		},
		(call::SUDO, call::SUDO_SET_KEY) => {
			common_verify_tx_fn::<SudoSetKeyParams>(tx, current_hash)
		},
		_ => Err("invalid method".to_string()),
	}
}

fn common_verify_tx_fn<Params: Encode>(tx: *mut c_uint, current_hash: &Hash) -> SignerResult<()> {

	let tx = unsafe { Box::from_raw(tx as *mut Transaction<Params>) };
	let verified = verify_tx(&tx, &current_hash);
	std::mem::forget(tx);
	verified

}

#[allow(dead_code)]
#[derive(Deserialize)]
struct CallWithValue {
	pub module: i8,
	pub method: i8,
	pub params: Value,
}

#[allow(dead_code)]
fn extract_sudo_sudo_params(params: &[u8]) -> SignerResult<(u8, u8)> {

	let params : SudoSudoParams<CallWithValue> = serde_json::from_slice(params).map_err(|_|"invalid params")?;

	Ok((params.proposal.module as u8, params.proposal.method as u8))
}
