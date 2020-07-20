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

use crate::{KeyPair, PUBLIC_KEY_LEN, SignerResult, Verifier};
use crate::tx::types::{Address, address_from_public, Call, Era, Hash, HASH_LEN, Nonce, Secret, Signature, Transaction};

pub mod types;
pub mod call;
mod serde;

const CTX: &[u8] = b"substrate";

pub fn build_call(json: &[u8]) -> SignerResult<Call>
{
	let call: Call = serde_json::from_slice(json).map_err(|_| "invalid json")?;
	Ok(call)
}

pub fn build_tx(secret_key: Secret, nonce: Nonce, period: u64, current: u64, current_hash: Hash, call: Call) -> SignerResult<Transaction>
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

pub fn verify_tx(tx: &Transaction, current_hash: &Hash) -> SignerResult<()>
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
	use super::*;

	#[test]
	fn test_tx_balance_transfer() {
		let (key_pair0, key_pair4) = get_key_pairs();
		let dest = address_from_public(&key_pair4.public_key());
		let dest = format!("0x{}", hex::encode(&dest.0[..]));
		let value = 1000;

		let module = call::balances::MODULE;
		let method = call::balances::TRANSFER;
		let call = format!(r#"{{ "module":{}, "method":{}, "params":{{"dest":"{}","value":{}}}}}"#, module, method, dest, value);
		println!("call: {}", call);

		let call = build_call(call.as_bytes()).unwrap();

		let nonce = 0;
		let (current, current_hash) = get_current();

		let expected = (140, module, method);
		test_tx(key_pair0, nonce, current, current_hash, call, expected);
	}

	#[test]
	fn test_tx_sudo_set_key() {
		let (key_pair0, key_pair4) = get_key_pairs();
		let address = address_from_public(&key_pair4.public_key());

		let address = format!("0x{}", hex::encode(&address.0[..]));

		let module = call::sudo::MODULE;
		let method = call::sudo::SET_KEY;
		let call = format!(r#"{{ "module":{}, "method":{}, "params":{{"addresses":["{}"]}}}}"#, module, method, address);
		println!("call: {}", call);

		let call = build_call(call.as_bytes()).unwrap();

		let nonce = 0;
		let (current, current_hash) = get_current();

		let expected = (139, module, method);
		test_tx(key_pair0, nonce, current, current_hash, call, expected);
	}

	#[test]
	fn test_tx_sudo_sudo_force_update_crfg_authorites() {
		let (key_pair0, _key_pair4) = get_key_pairs();

		let authority_id = "0x7800f639b82c7d139c81e33cd226ebaf9c5b0df79358114c1c71498d20a3399e";
		let weight = 1;
		let median = 11;

		let module = call::sudo::MODULE;
		let method = call::sudo::SUDO;
		let crfg_module = call::crfg::MODULE;
		let crfg_method = call::crfg::FORCE_UPDATE_AUTHORITIES;
		let call = format!(r#"{{ "module":{}, "method":{}, "params":{{"proposal":{{"module":{},"method":{},"params":{{"authorities":[["{}",{}]],"median":{}}}}}}}}}"#,
						   module, method, crfg_module, crfg_method, authority_id, weight, median);
		println!("call: {}", call);

		let call = build_call(call.as_bytes()).unwrap();

		let nonce = 0;
		let (current, current_hash) = get_current();

		let expected = (156, module, method);
		test_tx(key_pair0, nonce, current, current_hash, call, expected);
	}

	fn test_tx(sender: KeyPair, nonce: u64, current: u64, current_hash: Hash, call: Call, expected: (usize, u8, u8)) {
		let (expected_len, expected_module, expected_method) = expected;

		let secret_key = sender.secret_key();
		let tx = build_tx(secret_key, nonce, 64, current, current_hash, call).unwrap();

		let tx = tx.encode();

		println!("tx: 0x{}", hex::encode(&tx));

		assert_eq!(tx.len(), expected_len);

		// decode method
		let (module, method) = decode_tx_method(&tx).unwrap();

		assert_eq!((module, method), (expected_module, expected_method));

		// decode
		let tx: Transaction = Decode::decode(&mut &tx[..]).unwrap();

		// verify
		let verified = verify_tx(&tx, &current_hash);

		assert!(verified.is_ok());
	}

	fn get_current() -> (u64, Hash) {
		let current = 122;

		let current_hash = {
			let current_hash = hex::decode("00005ffdae0956deb76e40b94af6e990717a7f8956a1920007739ff4b901f386").unwrap();
			let mut out = [0u8; HASH_LEN];
			out.copy_from_slice(&current_hash);
			out
		};

		(current, current_hash)
	}

	fn get_key_pairs() -> (KeyPair, KeyPair) {
		let secret_key0 = hex::decode("a8666e483fd6c26dbb6deeec5afae765561ecc94df432f02920fc5d9cd4ae206ead577e5bc11215d4735cee89218e22f2d950a2a4667745ea1b5ea8b26bba5d6").unwrap();
		let key_pair0 = KeyPair::from_secret_key(&secret_key0).unwrap();

		let secret_key4 = hex::decode("f8eb0d437140e458ec6103965a4442f6b00e37943142017e9856f3310023ab530a0cc96e386686f95d2da0c7fa423ab7b84d5076b3ba6e7756e21aaafe9d3696").unwrap();
		let key_pair4 = KeyPair::from_secret_key(&secret_key4).unwrap();

		(key_pair0, key_pair4)
	}
}
