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

use parity_codec::{Compact, Decode, Input};
use parity_codec::Encode;
use rust_crypto::blake2b;

use crate::{KeyPair, SignerResult, PUBLIC_KEY_LEN, Verifier};
use crate::tx::types::{address_from_public, Call, Era, Hash, HASH_LEN, Nonce, Secret, Transaction, Address, Signature};

pub mod types;
pub mod call;

const CTX: &[u8] = b"substrate";

pub fn build_call<Params>(module: u8, method: u8, params: Params) -> Call<Params>
{
	Call {
		module: module as i8,
		method: method as i8,
		params,
	}
}

pub fn build_tx<Params>(secret_key: Secret, nonce: Nonce, period: u64, current: u64, current_hash: Hash, call: Call<Params>) -> SignerResult<Transaction<Params>>
	where Params: Encode,
{
	let key_pair = KeyPair::from_secret_key(&secret_key)?;

	let public_key = key_pair.public_key();
	let address = address_from_public(&public_key);
	let era = Era::mortal(period, current);
	let nonce = Compact(nonce);

	let raw_payload = (&nonce, &call, &era, &current_hash);
	let signature = raw_payload.using_encoded(|payload| {
		if payload.len() > 256 {
			key_pair.sign(&blake2b_256(payload), CTX)
		} else {
			key_pair.sign(payload, CTX)
		}
	});

	let tx = Transaction {
		signature: Some((address, signature, nonce, era)),
		call,
	};

	Ok(tx)
}

pub fn decode_tx_method(raw: &[u8]) -> SignerResult<(u8, u8)> {
	let input = &mut &raw[..];

	let _length_do_not_remove_me_see_above: Vec<()> = Decode::decode(input).ok_or("invalid tx")?;

	let version = input.read_byte().ok_or("invalid tx")?;

	let is_signed = version & 0b1000_0000 != 0;

	struct A {
		pub signature: Option<(Address, Signature, Compact<Nonce>, Era)>,
		pub call: (i8, i8),
	}

	let a = A {
		signature: if is_signed { Some(Decode::decode(input).ok_or("invalid tx")?) } else { None },
		call: Decode::decode(input).ok_or("invalid tx")?,
	};

	Ok((a.call.0 as u8, a.call.1 as u8))
}

pub fn verify_tx<Params>(tx: &Transaction<Params>, current_hash: &Hash) -> SignerResult<()>
	where Params: Encode,
{
	let (address, signature, nonce, era) = match &tx.signature {
		Some(signature) => signature,
		None => return Ok(()),
	};
	let call = &tx.call;

	let raw_payload = (&nonce, call, &era, &current_hash);

	let public_key = {
		let mut tmp = [0u8; PUBLIC_KEY_LEN];
		tmp.copy_from_slice(&address.0[1..]);
		tmp
	};
	let verifier = Verifier::from_public_key(&public_key)?;

	let verified = raw_payload.using_encoded(|payload| {
		if payload.len() > 256 {
			verifier.verify(&signature[..], &blake2b_256(payload), CTX)
		} else {
			verifier.verify(&signature[..], &payload, CTX)
		}
	});
	verified
}

fn blake2b_256(data: &[u8]) -> Hash {
	let mut out = [0u8; HASH_LEN];
	blake2b::Blake2b::blake2b(&mut out, data, &[]);
	out
}

#[cfg(test)]
mod tests {
	use parity_codec::Decode;

	use crate::SECRET_KEY_LEN;

	use super::*;
	use crate::tx::call::{BALANCE, TRANSFER, BalanceTransferParams};

	#[test]
	fn test_build_tx() {
		let balance_transfer_params = BalanceTransferParams {
			dest: address_from_public(&hex::decode("927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70").unwrap()),
			value: Compact(1000),
		};

		let call = build_call(call::BALANCE, call::TRANSFER, balance_transfer_params);

		let secret_key = {
			let secret_key = hex::decode("0b58d672927e01314d624fcb834a0f04b554f37640e0a4c342029a996ec1450bac8afb286e210d3afbfb8fd429129bd33329baaea6b919c92651c072c59d2408").unwrap();
			let mut out = [0u8; SECRET_KEY_LEN];
			out.copy_from_slice(&secret_key);
			out
		};

		let current_hash = {
			let current_hash = hex::decode("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13").unwrap();
			let mut out = [0u8; HASH_LEN];
			out.copy_from_slice(&current_hash);
			out
		};

		let tx = build_tx(secret_key, 0, 64, 26491, current_hash, call).unwrap();
		let tx = tx.encode();

		assert_eq!(tx.len(), 140);

		// decode method
		let (module, method) = decode_tx_method(&tx).unwrap();

		assert_eq!((module, method), (BALANCE, TRANSFER));

		// decode
		let tx: Transaction<BalanceTransferParams> = Decode::decode(&mut &tx[..]).unwrap();

		// verify
		let verified = verify_tx(&tx, &current_hash);

		assert!(verified.is_ok());
	}
}
